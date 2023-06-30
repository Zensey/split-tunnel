


#include "common.h"
#include "wfp.h"
#include "callouts.h"
#include "ioctl.h"

#include "pend.h"
#include "pend.tmh"


extern MAIN_CONTEXT* g_Context;


NTSTATUS
PendRequest
(
    MAIN_CONTEXT* Context,
    UINT64 ProcessId,
    UINT64 FilterId,
    UINT16 LayerId,
    void* ClassifyContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ClassifyContext);
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
        DoTraceMessage(Default, "FwpsAcquireClassifyHandle0() failed");
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


    WdfSpinLockAcquire(g_Context->ClassificationsLock);
    
    InsertTailList(&g_Context->ClassificationsQueue, &record->listEntry);
    
    WdfSpinLockRelease(g_Context->ClassificationsLock);

    KeSetEvent(
        &g_Context->ClassificationQueueEvent,
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

    struct {
        unsigned int queue    : 1;
        unsigned int request  : 1;
        unsigned int decision : 1;
    } state = {0,0,0};

    PVOID events[] = {
        &g_Context->ClassificationQueueEvent,
        &g_Context->InvertedCallEvent,
        &g_Context->DecisionEvent
    };

    for (;;)
    {
        DoTraceMessage(Default, "ClassifyWorker() wait >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

        auto status = KeWaitForMultipleObjects(3, events, WaitAny, Executive,
            KernelMode, FALSE, NULL, NULL);

        DoTraceMessage(Default, "ClassifyWorker() wait Status=%!STATUS!", status);

        if (KeReadStateEvent(&g_Context->ClassificationQueueEvent)) {
            state.queue = 1;
            KeClearEvent(&g_Context->ClassificationQueueEvent);
        }
        if (KeReadStateEvent(&g_Context->InvertedCallEvent)) {
            state.request = 1;
            KeClearEvent(&g_Context->InvertedCallEvent);
        }
        if (KeReadStateEvent(&g_Context->DecisionEvent)) {
            state.decision = 1;
            KeClearEvent(&g_Context->DecisionEvent);
        }

        DoTraceMessage(Default, "ClassifyWorker() events_: %d %d %d",
            state.queue,
            state.request,
            state.decision
        );

        if (state.queue && state.request)
        {
            state.queue = 0;
            state.request = 0;

            DoTraceMessage(Default, "CalssifyWorker() !Peek rec");

            if (!IsListEmpty(&g_Context->ClassificationsQueue))
            {
                WdfSpinLockAcquire(g_Context->ClassificationsLock);

                auto rec = RemoveHeadList(&g_Context->ClassificationsQueue);

                WdfSpinLockRelease(g_Context->ClassificationsLock);

                auto req = CONTAINING_RECORD(rec, PENDED_CLASSIFICATION, listEntry);


                //req->listEntry
                InsertTailList(&g_Context->ResQueue, &req->listEntry);

                // ioctl
                CompleteIoctlRequest(req);
            };

            if (!IsListEmpty(&g_Context->ClassificationsQueue)) {
                state.queue = 1;
            }
        }

        if (state.decision) {
            state.decision = 0;
            
            // ioctl
            CompleteIoctlResponse();
        }

        if (g_Context->Quit) {
            // todo: terminate all requests
            break;
        }
    }
    DoTraceMessage(Default, "CalssifyWorker() !Exit");

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
CompleteIoctlResponse()
{
    WDFREQUEST request;
    void* bufferPointer;

    DoTraceMessage(Default, "CompleteIoctlReply()");

    auto status = WdfIoQueueRetrieveNextRequest(
        g_Context->NotificationQueue2,
        &request);
    if (!NT_SUCCESS(status)) {
        DoTraceMessage(Default, "CompleteIoctlReply() !Peek decision req Status=%!STATUS!", status);
        return status;
    }

    status = WdfRequestRetrieveInputBuffer(request,
        100,
        (PVOID*)&bufferPointer,
        nullptr);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "CompleteIoctlReply() !WdfRequestRetrieveInputBuffer Status=%!STATUS!", status);
        return status;
    }
    else
    {
        auto reply = ((DrvRequest*)bufferPointer);

        DoTraceMessage(Default, "CompleteIoctlReply() pid,result: %llu %d", reply->pid, reply->result);

        PLIST_ENTRY entry = &g_Context->ResQueue;
        while (&g_Context->ResQueue != entry->Flink)
        {
            entry = entry->Flink;

            auto rec2 = CONTAINING_RECORD(entry, PENDED_CLASSIFICATION, listEntry);
            if (rec2->ProcessId == reply->pid) {

                DoTraceMessage(Default, "CompleteIoctlReply() Remove");
                
                RemoveEntryList(&rec2->listEntry);

                // Forward Packet //
                ReauthPendedRequest(rec2, reply->result);
                break;
            }
        }
    }
    WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

NTSTATUS
CompleteIoctlRequest
(
    PENDED_CLASSIFICATION *req
)
{
    WDFREQUEST notifyRequest;
    void* bufferPointer;

    DoTraceMessage(Default, "CompleteIoctlRequest()");

    auto status = WdfIoQueueRetrieveNextRequest(g_Context->NotificationQueue,
        &notifyRequest);
    if (!NT_SUCCESS(status)) {
        DoTraceMessage(Default, "CompleteIoctlRequest() !Peek notification req Status=%!STATUS!", status);
        return status;
    }

    status = WdfRequestRetrieveOutputBuffer(notifyRequest,
        100,
        (PVOID*)&bufferPointer,
        nullptr);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "CompleteIoctlRequest() !WdfRequestRetrieveOutputBuffer Status=%!STATUS!", status);
        WdfRequestCompleteWithInformation(notifyRequest, STATUS_SUCCESS, 0);
    }
    else
    {
        *((UINT64*)bufferPointer) = req->ProcessId;
        WdfRequestCompleteWithInformation(notifyRequest, STATUS_SUCCESS, 100);
    }

    return status;
}

void
ReauthPendedRequest
(
    PENDED_CLASSIFICATION* Record,
    BOOL decision
)
{
    DoTraceMessage(Default, "ReauthPendedRequest: re-auth for pended request of process %llu, layer: %d", Record->ProcessId, Record->LayerId);

    if (decision)
    {
        FWPS_CONNECT_REQUEST0* connectRequest = NULL;
        auto status = FwpsAcquireWritableLayerDataPointer(Record->ClassifyHandle, Record->FilterId, 0, (PVOID*)&connectRequest, &Record->ClassifyOut);
        if (NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "ReauthPendedRequest > Redirect request >");

            IN_ADDR RedirectAddress = { 0 };
            RedirectAddress.s_addr = g_Context->HostRedirect;
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

