/*

*/

#include "common.h"
#include "callouts.h"
#include "pend.h"


#include "wfp.h"
#include "wfp.tmh"


MAIN_CONTEXT *g_Context;


NTSTATUS
InitializeWfp(PDRIVER_OBJECT DriverObject)
{
    InitializeWfpContext(&g_Context);

    ExUuidCreate(&g_Context->SessionKey);
    ExUuidCreate(&g_Context->ProviderKey);
    ExUuidCreate(&g_Context->ProviderContextKey);
    ExUuidCreate(&g_Context->SubLayerKey);
    ExUuidCreate(&g_Context->ConnectRedirectCalloutKey);
    ExUuidCreate(&g_Context->ConnectRedirectFilterKey);
    ExUuidCreate(&g_Context->ConnectRedirectPermitCalloutKey);
    ExUuidCreate(&g_Context->ConnectRedirectPermitFilterKey);
    ExUuidCreate(&g_Context->BindRedirectCalloutKey);
    ExUuidCreate(&g_Context->BindRedirectFilterKey);


    NTSTATUS status;
    {
        FWPM_SESSION Session;
        RtlZeroMemory(&Session, sizeof(Session));
        Session.sessionKey = g_Context->SessionKey;
        Session.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Session");
        Session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        status = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, &Session, &g_Context->EngineHandle);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmEngineOpen() Status=%!STATUS!", status);
        }

        status = FwpmTransactionBegin(g_Context->EngineHandle, 0);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmTransactionBegin() Status=%!STATUS!", status);
        }

        FWPM_PROVIDER Provider;
        RtlZeroMemory(&Provider, sizeof(Provider));
        Provider.providerKey = g_Context->ProviderKey;
        Provider.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Provider");
        status = FwpmProviderAdd(g_Context->EngineHandle, &Provider, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmProviderAdd() Status=%!STATUS!", status);
        }

        FWPM_SUBLAYER SubLayer;
        RtlZeroMemory(&SubLayer, sizeof(SubLayer));
        SubLayer.subLayerKey = g_Context->SubLayerKey;
        SubLayer.displayData.name = const_cast<wchar_t*>(L"WfpDnsRedirect SubLayer");
        SubLayer.providerKey = &g_Context->ProviderKey;
        SubLayer.weight = MAXUINT16;
        status = FwpmSubLayerAdd(g_Context->EngineHandle, &SubLayer, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmSubLayerAdd() Status=%!STATUS!", status);
        }

        ///////////////////////////////////////////////////////////
        // TCP
        {
            FWPM_CALLOUT Callout;
            FWPS_CALLOUT Callouts;

            RtlZeroMemory(&Callout, sizeof(Callout));
            Callout.calloutKey = g_Context->ConnectRedirectCalloutKey;
            Callout.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Callout");
            Callout.providerKey = &g_Context->ProviderKey;
            Callout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

            status = FwpmCalloutAdd(g_Context->EngineHandle, &Callout, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpmCalloutAdd(ConnectRedirect) Status=%!STATUS!", status);
            }

            RtlZeroMemory(&Callouts, sizeof(Callouts));
            Callouts.calloutKey = g_Context->ConnectRedirectCalloutKey;
            Callouts.classifyFn = CalloutConnectRedirectClassify;
            Callouts.notifyFn = DriverNotify;

            status = FwpsCalloutRegister(DriverObject, &Callouts, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpsCalloutRegister1(ConnectRedirect) Status=%!STATUS!", status);
            }
        }

        {
            FWPM_CALLOUT Callout;
            FWPS_CALLOUT Callouts;

            RtlZeroMemory(&Callout, sizeof(Callout));
            Callout.calloutKey = g_Context->ConnectRedirectPermitCalloutKey;
            Callout.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Permit Callout");
            Callout.providerKey = &g_Context->ProviderKey;
            Callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

            status = FwpmCalloutAdd(g_Context->EngineHandle, &Callout, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpmCalloutAdd(ConnectRedirect) Status=%!STATUS!", status);
            }

            RtlZeroMemory(&Callouts, sizeof(Callouts));
            Callouts.calloutKey = g_Context->ConnectRedirectPermitCalloutKey;
            Callouts.classifyFn = CalloutConnectRedirectPermitClassify;
            Callouts.notifyFn = DriverNotify;

            status = FwpsCalloutRegister(DriverObject, &Callouts, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpsCalloutRegister2(ConnectRedirect) Status=%!STATUS!", status);
            }
        }

        // non-TCP
        {
            FWPM_CALLOUT Callout;
            FWPS_CALLOUT Callouts;

            RtlZeroMemory(&Callout, sizeof(Callout));
            Callout.calloutKey = g_Context->BindRedirectCalloutKey;
            Callout.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Callout");
            Callout.providerKey = &g_Context->ProviderKey;
            Callout.applicableLayer = FWPM_LAYER_ALE_BIND_REDIRECT_V4;

            status = FwpmCalloutAdd(g_Context->EngineHandle, &Callout, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpmCalloutAdd(ConnectRedirect) Status=%!STATUS!", status);
            }

            RtlZeroMemory(&Callouts, sizeof(Callouts));
            Callouts.calloutKey = g_Context->BindRedirectCalloutKey;
            Callouts.classifyFn = CalloutBindRedirectClassify;
            Callouts.notifyFn = DriverNotify;

            status = FwpsCalloutRegister(DriverObject, &Callouts, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpsCalloutRegister3(ConnectRedirect) Status=%!STATUS!", status);
            }
        }
        //////////////////////////////////////////

        //TCP
        {
            UINT64 FilterWeight = MAXUINT64;
            FWPM_FILTER Filter;
            RtlZeroMemory(&Filter, sizeof(Filter));
            Filter.filterKey = g_Context->ConnectRedirectFilterKey;
            Filter.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Filter");
            Filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
            Filter.providerKey = &g_Context->ProviderKey;
            Filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
            Filter.subLayerKey = g_Context->SubLayerKey;
            Filter.weight.type = FWP_UINT64;
            Filter.weight.uint64 = const_cast<UINT64*>(&FilterWeight);
            Filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN; // FWP_ACTION_CALLOUT_TERMINATING;
            Filter.action.calloutKey = g_Context->ConnectRedirectCalloutKey;
            //Filter.providerContextKey = g_Context->g_ProviderContextKey;


            FWPM_FILTER_CONDITION0 cond;
            cond.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue.type = FWP_UINT8;
            cond.conditionValue.uint8 = IPPROTO_TCP;

            Filter.filterCondition = &cond;
            Filter.numFilterConditions = 1;

            status = FwpmFilterAdd(g_Context->EngineHandle, &Filter, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpmFilterAdd(ConnectRedirect) Status=%!STATUS!", status);
            }
        }

        {
            UINT64 FilterWeight = MAXUINT64 - 10;
            FWPM_FILTER Filter;
            RtlZeroMemory(&Filter, sizeof(Filter));
            Filter.filterKey = g_Context->ConnectRedirectPermitFilterKey;
            Filter.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Auth Filter");
            Filter.providerKey = &g_Context->ProviderKey;
            Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            Filter.subLayerKey = g_Context->SubLayerKey;
            Filter.weight.type = FWP_UINT64;
            Filter.weight.uint64 = const_cast<UINT64*>(&FilterWeight);
            Filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN; // FWP_ACTION_CALLOUT_TERMINATING;
            Filter.action.calloutKey = g_Context->ConnectRedirectPermitCalloutKey;
            //Filter.providerContextKey = g_Context->g_ProviderContextKey;

            status = FwpmFilterAdd(g_Context->EngineHandle, &Filter, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpmFilterAdd(ConnectRedirect) Status=%!STATUS!", status);
            }
        }

        // non-TCP
        {
            UINT64 FilterWeight = MAXUINT64;
            FWPM_FILTER Filter;
            RtlZeroMemory(&Filter, sizeof(Filter));
            Filter.filterKey = g_Context->BindRedirectFilterKey;
            Filter.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Bind Redirect Filter");
            Filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
            Filter.providerKey = &g_Context->ProviderKey;
            Filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V4;
            Filter.subLayerKey = g_Context->SubLayerKey;
            Filter.weight.type = FWP_UINT64;
            Filter.weight.uint64 = const_cast<UINT64*>(&FilterWeight);
            Filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN; // FWP_ACTION_CALLOUT_TERMINATING;
            Filter.action.calloutKey = g_Context->BindRedirectCalloutKey;
            //Filter.providerContextKey = g_Context->g_ProviderContextKey;


            FWPM_FILTER_CONDITION0 cond;
            cond.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            cond.matchType = FWP_MATCH_NOT_EQUAL;
            cond.conditionValue.type = FWP_UINT8;
            cond.conditionValue.uint8 = IPPROTO_TCP;

            Filter.filterCondition = &cond;
            Filter.numFilterConditions = 1;

            status = FwpmFilterAdd(g_Context->EngineHandle, &Filter, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "FwpmFilterAdd(BindRedirect) Status=%!STATUS!", status);
            }
        }


        status = FwpmTransactionCommit(g_Context->EngineHandle);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmTransactionCommit() Status=%!STATUS!", status);
        }
    }

    return status;
}

NTSTATUS
ClearWfp()
{
    NTSTATUS status;
    {
        status = FwpmTransactionBegin(g_Context->EngineHandle, 0);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmTransactionBegin() Status=%!STATUS!", status);
        }

        status = FwpmFilterDeleteByKey(g_Context->EngineHandle, &g_Context->BindRedirectFilterKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmFilterDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmFilterDeleteByKey(g_Context->EngineHandle, &g_Context->ConnectRedirectPermitFilterKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmFilterDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmFilterDeleteByKey(g_Context->EngineHandle, &g_Context->ConnectRedirectFilterKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmFilterDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmCalloutDeleteByKey(g_Context->EngineHandle, &g_Context->ConnectRedirectPermitCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmCalloutDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmCalloutDeleteByKey(g_Context->EngineHandle, &g_Context->ConnectRedirectCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmCalloutDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmSubLayerDeleteByKey(g_Context->EngineHandle, &g_Context->SubLayerKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmSubLayerDeleteByKey() Status=%!STATUS!", status);
        }

        /*
        Status = FwpmProviderContextDeleteByKey(g_Context->g_EngineHandle, &g_Context->g_ProviderContextKey);
        if (!NT_SUCCESS(Status))
        {
            DoTraceMessage(Default, "FwpmProviderContextDeleteByKey() Status=%!STATUS!", Status);
        }
        */

        status = FwpmProviderDeleteByKey(g_Context->EngineHandle, &g_Context->ProviderKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmProviderDeleteByKey() Status=%!STATUS!", status);
        }

        status = FwpmTransactionCommit(g_Context->EngineHandle);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmTransactionCommit() Status=%!STATUS!", status);
        }

        status = FwpmEngineClose(g_Context->EngineHandle);
        g_Context->EngineHandle = NULL;
    }

    {
        status = FwpsCalloutUnregisterByKey(&g_Context->BindRedirectCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsCalloutUnregisterByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpsCalloutUnregisterByKey(&g_Context->ConnectRedirectCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsCalloutUnregisterByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpsCalloutUnregisterByKey(&g_Context->ConnectRedirectPermitCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsCalloutUnregisterByKey(ConnectRedirect) Status=%!STATUS!", status);
        }
    }

    ClearWfpContext(g_Context);

    return status;
}

NTSTATUS
InitializeWfpContext(MAIN_CONTEXT** Context)
{
    auto context = (MAIN_CONTEXT*)ExAllocatePoolUninitialized(NonPagedPool, sizeof(MAIN_CONTEXT), ST_POOL_TAG);
    if (context == NULL)
    {
        DoTraceMessage(Default, "ExAllocatePoolUninitialized() failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(*context));

    auto status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->ClassificationsLock);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "WdfSpinLockCreate() failed\n");
        goto Abort;
    }

    InitializeListHead(&context->ClassificationsQueue);
    InitializeListHead(&context->ResQueue);

    KeInitializeEvent(
        &context->ClassificationQueueEvent,
        NotificationEvent,
        FALSE
    );
    KeInitializeEvent(
        &context->InvertedCallEvent,
        NotificationEvent,
        FALSE
    );
    KeInitializeEvent(
        &context->DecisionEvent,
        NotificationEvent,
        FALSE
    );

    *Context = context;
    {
        OBJECT_ATTRIBUTES ObjectAttributes;
        HANDLE            hThread = 0;

        DoTraceMessage(Default, "WdfDeviceCreate > PsCreateSystemThread !\n");

        InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL,
            ClassifyWorker, NULL);

        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "failed to create worker thread");
            return status;
        }

        ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL,
            KernelMode, (PVOID*)&context->Thread, NULL);

        ZwClose(hThread);
    }
    return STATUS_SUCCESS;

Abort:
    ExFreePoolWithTag(context, ST_POOL_TAG);
    return status;
}




void
ClearWfpContext(MAIN_CONTEXT* context)
{
    //FailAllPendedRequests(context);

    // Stop thread
    {
        DoTraceMessage(Default, "ClearWfpContext !StopThread");

        if (context->Thread != NULL) {
            context->Quit = TRUE;
            KeSetEvent(&context->ClassificationQueueEvent, IO_NO_INCREMENT, FALSE);

            auto status = KeWaitForSingleObject(context->Thread, Executive, KernelMode, FALSE, NULL);
            if (!NT_SUCCESS(status))
            {
                DoTraceMessage(Default, "KeWaitForSingleObject() Status=%!STATUS!", status);
            }
            ObDereferenceObject(context->Thread);
        }
    }

    WdfObjectDelete(context->ClassificationsLock);
    
    KeClearEvent(&context->ClassificationQueueEvent);

    ExFreePoolWithTag(context, ST_POOL_TAG);
}