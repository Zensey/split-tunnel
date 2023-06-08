
#include "common.h"
#include "callouts.h"


#include "wfp.h"
#include "wfp.tmh"



HANDLE g_InjectionHandle = NULL;
HANDLE g_EngineHandle = NULL;
GUID g_SessionKey = { 0 };
GUID g_ProviderKey = { 0 };
GUID g_ProviderContextKey = { 0 };
GUID g_SubLayerKey = { 0 };
GUID g_ConnectRedirectCalloutKey = { 0 };
GUID g_ConnectRedirectFilterKey = { 0 };
GUID g_ConnectRedirectPermitCalloutKey = { 0 };
GUID g_ConnectRedirectPermitFilterKey = { 0 };

pCONTEXT* g_Context;


NTSTATUS
InitializeWfp(PDRIVER_OBJECT DriverObject)
{
    ExUuidCreate(&g_SessionKey);
    ExUuidCreate(&g_ProviderKey);
    ExUuidCreate(&g_ProviderContextKey);
    ExUuidCreate(&g_SubLayerKey);
    ExUuidCreate(&g_ConnectRedirectCalloutKey);
    ExUuidCreate(&g_ConnectRedirectFilterKey);
    ExUuidCreate(&g_ConnectRedirectPermitCalloutKey);
    ExUuidCreate(&g_ConnectRedirectPermitFilterKey);

    NTSTATUS status;
    {
        status = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &g_InjectionHandle);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsInjectionHandleCreate() Status=%!STATUS!", status);
        }

        FWPS_CALLOUT Callout;
        RtlZeroMemory(&Callout, sizeof(Callout));
        Callout.calloutKey = g_ConnectRedirectCalloutKey;
        Callout.classifyFn = DriverConnectRedirectClassify;
        Callout.notifyFn = DriverNotify;

        status = FwpsCalloutRegister(DriverObject, &Callout, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsCalloutRegister(ConnectRedirect) Status=%!STATUS!", status);
        }

        RtlZeroMemory(&Callout, sizeof(Callout));
        Callout.calloutKey = g_ConnectRedirectPermitCalloutKey;
        Callout.classifyFn = DriverConnectRedirectPermitClassify;
        Callout.notifyFn = DriverNotify;

        status = FwpsCalloutRegister(DriverObject, &Callout, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsCalloutRegister(ConnectRedirect) Status=%!STATUS!", status);
        }
    }

    {
        FWPM_SESSION Session;
        RtlZeroMemory(&Session, sizeof(Session));
        Session.sessionKey = g_SessionKey;
        Session.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Session");
        Session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        status = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, &Session, &g_EngineHandle);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmEngineOpen() Status=%!STATUS!", status);
        }

        status = FwpmTransactionBegin(g_EngineHandle, 0);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmTransactionBegin() Status=%!STATUS!", status);
        }

        FWPM_PROVIDER Provider;
        RtlZeroMemory(&Provider, sizeof(Provider));
        Provider.providerKey = g_ProviderKey;
        Provider.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Provider");
        status = FwpmProviderAdd(g_EngineHandle, &Provider, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmProviderAdd() Status=%!STATUS!", status);
        }

        InitializeWfpContext(&g_Context);

        /*
        FWPM_PROVIDER_CONTEXT1 ProviderContext;
        FWP_BYTE_BLOB blob = { .size = sizeof(pCONTEXT), .data = (UINT8*)g_Context };
        ProviderContext.providerContextKey = g_ProviderContextKey;
        ProviderContext.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Provider Context");
        ProviderContext.providerKey = &g_ProviderKey;
        ProviderContext.type = FWPM_GENERAL_CONTEXT;
        ProviderContext.dataBuffer = &blob;
        Status = FwpmProviderContextAdd1(g_EngineHandle, &ProviderContext, NULL, NULL);
        if (!NT_SUCCESS(Status))
        {
            DoTraceMessage(Default, "FwpmProviderContextAdd() Status=%!STATUS!", Status);
        }
        */

        FWPM_SUBLAYER SubLayer;
        RtlZeroMemory(&SubLayer, sizeof(SubLayer));
        SubLayer.subLayerKey = g_SubLayerKey;
        SubLayer.displayData.name = const_cast<wchar_t*>(L"WfpDnsRedirect SubLayer");
        SubLayer.providerKey = &g_ProviderKey;
        SubLayer.weight = MAXUINT16;
        status = FwpmSubLayerAdd(g_EngineHandle, &SubLayer, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmSubLayerAdd() Status=%!STATUS!", status);
        }

        FWPM_CALLOUT Callout;
        RtlZeroMemory(&Callout, sizeof(Callout));
        Callout.calloutKey = g_ConnectRedirectCalloutKey;
        Callout.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Callout");
        Callout.providerKey = &g_ProviderKey;
        Callout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

        status = FwpmCalloutAdd(g_EngineHandle, &Callout, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmCalloutAdd(ConnectRedirect) Status=%!STATUS!", status);
        }

        RtlZeroMemory(&Callout, sizeof(Callout));
        Callout.calloutKey = g_ConnectRedirectPermitCalloutKey;
        Callout.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Permit Callout");
        Callout.providerKey = &g_ProviderKey;
        Callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

        status = FwpmCalloutAdd(g_EngineHandle, &Callout, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmCalloutAdd(ConnectRedirect) Status=%!STATUS!", status);
        }

        //////////////////////////////////////////

        UINT64 FilterWeight = MAXUINT64;
        FWPM_FILTER Filter;
        RtlZeroMemory(&Filter, sizeof(Filter));
        Filter.filterKey = g_ConnectRedirectFilterKey;
        Filter.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Filter");
        //Filter.flags = FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        Filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        Filter.providerKey = &g_ProviderKey;
        Filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
        Filter.subLayerKey = g_SubLayerKey;
        Filter.weight.type = FWP_UINT64;
        Filter.weight.uint64 = const_cast<UINT64*>(&FilterWeight);
        Filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN; // FWP_ACTION_CALLOUT_TERMINATING;
        Filter.action.calloutKey = g_ConnectRedirectCalloutKey;
        //Filter.providerContextKey = g_ProviderContextKey;


        FWPM_FILTER_CONDITION0 cond;
        cond.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT8;
        cond.conditionValue.uint8 = IPPROTO_TCP;

        Filter.filterCondition = &cond;
        Filter.numFilterConditions = 1;

        status = FwpmFilterAdd(g_EngineHandle, &Filter, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmFilterAdd(ConnectRedirect) Status=%!STATUS!", status);
        }


        FilterWeight = MAXUINT64 - 10;
        RtlZeroMemory(&Filter, sizeof(Filter));
        Filter.filterKey = g_ConnectRedirectPermitFilterKey;
        Filter.displayData.name = const_cast<wchar_t*>(L"Split Tunnel Connect Redirect Auth Filter");
        //Filter.flags = FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT; //FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        Filter.providerKey = &g_ProviderKey;
        Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        Filter.subLayerKey = g_SubLayerKey;
        Filter.weight.type = FWP_UINT64;
        Filter.weight.uint64 = const_cast<UINT64*>(&FilterWeight);
        Filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN; // FWP_ACTION_CALLOUT_TERMINATING;
        Filter.action.calloutKey = g_ConnectRedirectPermitCalloutKey;
        //Filter.providerContextKey = g_ProviderContextKey;

        status = FwpmFilterAdd(g_EngineHandle, &Filter, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmFilterAdd(ConnectRedirect) Status=%!STATUS!", status);
        }


        status = FwpmTransactionCommit(g_EngineHandle);
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
        status = FwpmTransactionBegin(g_EngineHandle, 0);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmTransactionBegin() Status=%!STATUS!", status);
        }

        status = FwpmFilterDeleteByKey(g_EngineHandle, &g_ConnectRedirectPermitFilterKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmFilterDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmFilterDeleteByKey(g_EngineHandle, &g_ConnectRedirectFilterKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmFilterDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmCalloutDeleteByKey(g_EngineHandle, &g_ConnectRedirectPermitCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmCalloutDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmCalloutDeleteByKey(g_EngineHandle, &g_ConnectRedirectCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmCalloutDeleteByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpmSubLayerDeleteByKey(g_EngineHandle, &g_SubLayerKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmSubLayerDeleteByKey() Status=%!STATUS!", status);
        }

        /*
        Status = FwpmProviderContextDeleteByKey(g_EngineHandle, &g_ProviderContextKey);
        if (!NT_SUCCESS(Status))
        {
            DoTraceMessage(Default, "FwpmProviderContextDeleteByKey() Status=%!STATUS!", Status);
        }
        */

        status = FwpmProviderDeleteByKey(g_EngineHandle, &g_ProviderKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmProviderDeleteByKey() Status=%!STATUS!", status);
        }

        status = FwpmTransactionCommit(g_EngineHandle);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpmTransactionCommit() Status=%!STATUS!", status);
        }

        status = FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    {
        status = FwpsCalloutUnregisterByKey(&g_ConnectRedirectCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsCalloutUnregisterByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpsCalloutUnregisterByKey(&g_ConnectRedirectPermitCalloutKey);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsCalloutUnregisterByKey(ConnectRedirect) Status=%!STATUS!", status);
        }

        status = FwpsInjectionHandleDestroy(g_InjectionHandle);
        if (!NT_SUCCESS(status))
        {
            DoTraceMessage(Default, "FwpsInjectionHandleDestroy() Status=%!STATUS!", status);
        }
    }

    return status;
}

NTSTATUS
InitializeWfpContext(pCONTEXT** Context)
{
    auto context = (pCONTEXT*)ExAllocatePoolUninitialized(NonPagedPool, sizeof(pCONTEXT), ST_POOL_TAG);
    if (context == NULL)
    {
        DbgPrint("ExAllocatePoolUninitialized() failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(*context));

    auto status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->Lock);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("WdfSpinLockCreate() failed\n");
        goto Abort;
    }

    *Context = context;

    return STATUS_SUCCESS;

Abort:
    ExFreePoolWithTag(context, ST_POOL_TAG);
    return status;
}