


#include "common.h"
#include "wfp.h"
#include "callouts.h"

#include "pend.h"
#include "pend.tmh"


extern MAIN_CONTEXT* g_Context;





NTSTATUS
PendRequest
(
    MAIN_CONTEXT* Context,
    HANDLE ProcessId,
    UINT64 FilterId,
    UINT16 LayerId,
    void* ClassifyContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(FilterId);
    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(ClassifyOut);

    NTSTATUS status;

    DoTraceMessage(Default, "PendRequest()");

    auto record = (PENDED_CLASSIFICATION*)
        ExAllocatePoolUninitialized(NonPagedPool, sizeof(PENDED_CLASSIFICATION), ST_POOL_TAG);

    if (record == NULL)
    {
        DoTraceMessage(Default, "ExAllocatePoolUninitialized() failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT64 classifyHandle;
    status = FwpsAcquireClassifyHandle0(ClassifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("FwpsAcquireClassifyHandle0() failed\n");
        goto Abort;
    }

    status = FwpsPendClassify0(classifyHandle, FilterId, 0, ClassifyOut);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "FwpsPendClassify0() failed");
        FwpsReleaseClassifyHandle0(classifyHandle);
        goto Abort;
    }

    record->ProcessId = ProcessId;
    record->Timestamp = KeQueryInterruptTime();
    record->ClassifyHandle = classifyHandle;
    record->ClassifyOut = *ClassifyOut;
    record->LayerId = LayerId;
    record->FilterId = FilterId;


    WdfSpinLockAcquire(g_Context->classificationsLock);
    
    InsertTailList(&g_Context->classificationsQueue, &record->listEntry);
    
    WdfSpinLockRelease(g_Context->classificationsLock);

    KeSetEvent(
        &g_Context->classificationQueueEvent,
        0,
        FALSE
    );

    return STATUS_SUCCESS;

Abort:
    ExFreePoolWithTag(record, ST_POOL_TAG);
    return status;
}


///////////////////////////////////////////////////////////////////////////////

//
// Iterate over all pended bind requests.
//
void
ClassifyWorker(
    _In_ void* StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    DoTraceMessage(Default, "CalssifyWorker() Enter");

    for (;;)
    {
        auto status = KeWaitForSingleObject(
            &g_Context->classificationQueueEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
        DoTraceMessage(Default, "CalssifyWorker() wait Status=%!STATUS!", status);
        KeClearEvent(&g_Context->classificationQueueEvent);


        while (!IsListEmpty(&g_Context->classificationsQueue))
        {
            DoTraceMessage(Default, "CalssifyWorker() !Peek rec");

            WdfSpinLockAcquire(g_Context->classificationsLock);

            auto rec = RemoveHeadList(&g_Context->classificationsQueue);

            WdfSpinLockRelease(g_Context->classificationsLock);



            auto req = CONTAINING_RECORD(rec, PENDED_CLASSIFICATION, listEntry);

            // Forward Packet //
            ReauthPendedRequest(req);
        };

        if (g_Context->quit) {
            break;
        }
    }
    DoTraceMessage(Default, "CalssifyWorker() !Exit");

    PsTerminateSystemThread(STATUS_SUCCESS);
}

void
ReauthPendedRequest
(
    PENDED_CLASSIFICATION* Record
)
{
    DoTraceMessage(Default, "ReauthPendedRequest: re-auth for pended request of process %llu", UINT64(Record->ProcessId));

    if (UINT64(Record->ProcessId) == g_Context->processId)
    {
        FWPS_CONNECT_REQUEST0* connectRequest = NULL;
        auto status = FwpsAcquireWritableLayerDataPointer(Record->ClassifyHandle, Record->FilterId, 0, (PVOID*)&connectRequest, &Record->ClassifyOut);
        if (NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "ReauthPendedRequest > Redirect request >");

            IN_ADDR RedirectAddress = { 0 };
            RedirectAddress.s_addr = g_Context->hostRedirect;
            INETADDR_SET_ADDRESS((SOCKADDR*)&connectRequest->localAddressAndPort, (const UCHAR*)&RedirectAddress);

            FwpsApplyModifiedLayerData(Record->ClassifyHandle, connectRequest, 0);

            //ClassificationApplySoftPermit(classifyOut);
            ClassificationApplyHardPermit(&Record->ClassifyOut);
        }
        else
        {
            DoTraceMessage(Default, "ReauthPendedRequest !FwpsAcquireWritableLayerDataPointer() Status=%!STATUS!", status);
        }
    }


    FwpsCompleteClassify0(Record->ClassifyHandle, 0, &Record->ClassifyOut);
    FwpsReleaseClassifyHandle0(Record->ClassifyHandle);

    ExFreePoolWithTag(Record, ST_POOL_TAG);
}

