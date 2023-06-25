/*

*/

#include "common.h"
#include "wfp.h"
#include "pend.h"


#include "callouts.h"
#include "callouts.tmh"


extern MAIN_CONTEXT *g_Context;



NTSTATUS NTAPI DriverNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}


//
//
// Adjust properties on new TCP connections.
//
// If an app is marked for splitting, and if a new connection is explicitly made on the
// tunnel interface, or can be assumed to be routed through the tunnel interface,
// then move the connection to the Internet connected interface (LAN interface usually).
//
// FWPS_LAYER_ALE_CONNECT_REDIRECT_V4
//
void NTAPI DriverConnectRedirectClassify(
    _In_ const FWPS_INCOMING_VALUES* FixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* MetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(FlowContext);
    UNREFERENCED_PARAMETER(FixedValues);

    NT_ASSERT(
        (
            FixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4
            && FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8 == IPPROTO_TCP
        )
    );


    if (0 == (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        DoTraceMessage(Default, "Aborting connect-redirect processing because hard permit/block already applied\n");
        return;
    }


    ClassificationReset(classifyOut);

    if (!FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
    {
        DoTraceMessage(Default, "Failed to classify connection because PID was not provided\n");
        return;
    }
    DoTraceMessage(Default, "Classify PID: %llu", MetaValues->processId);


    const auto rawLocalAddress = RtlUlongByteSwap(FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32);
    const auto rawRemoteAddress = RtlUlongByteSwap(FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32);
    const auto rawLocalPort = (FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16);
    const auto rawRemotePort = (FixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16);
    auto localAddress = reinterpret_cast<const IN_ADDR*>(&rawLocalAddress);
    auto remoteAddress = reinterpret_cast<const IN_ADDR*>(&rawRemoteAddress);
    char localAddrString[32];
    char remoteAddrString[32];
    RtlIpv4AddressToStringA(localAddress, localAddrString);
    RtlIpv4AddressToStringA(remoteAddress, remoteAddrString);
    DoTraceMessage(Default, "[CONN] %s:%d -> %s:%d", localAddrString, rawLocalPort, remoteAddrString, rawRemotePort);


    PendRequest(
        g_Context,
        MetaValues->processId,
        Filter->filterId,
        FixedValues->layerId,
        const_cast<void*>(ClassifyContext),
        classifyOut
    );
}

void NTAPI DriverConnectRedirectPermitClassify(
    _In_ const FWPS_INCOMING_VALUES* FixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* MetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    const auto rawLocalAddress = RtlUlongByteSwap(FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32);
    const auto rawRemoteAddress = RtlUlongByteSwap(FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32);
    const auto rawLocalPort = (FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16);
    const auto rawRemotePort = (FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16);
    auto localAddress = reinterpret_cast<const IN_ADDR*>(&rawLocalAddress);
    auto remoteAddress = reinterpret_cast<const IN_ADDR*>(&rawRemoteAddress);
    char localAddrString[32];
    char remoteAddrString[32];
    RtlIpv4AddressToStringA(localAddress, localAddrString);
    RtlIpv4AddressToStringA(remoteAddress, remoteAddrString);
    DoTraceMessage(Default, "[CONN auth] %s:%d -> %s:%d", localAddrString, rawLocalPort, remoteAddrString, rawRemotePort);


    if (!FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
    {
        DoTraceMessage(Default, "Failed to classify connection because PID was not provided\n");
        return;
    }

    //ClassificationApplySoftPermit(ClassifyOut);
    ClassificationApplyHardPermit(ClassifyOut);
    return;
}

void ClassificationReset
(
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    //
    // According to documentation, FwpsAcquireWritableLayerDataPointer0() will update the
    // `actionType` and `rights` fields with poorly chosen values:
    //
    // ```
    // classifyOut->actionType = FWP_ACTION_BLOCK
    // classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE
    // ```
    //
    // However, in practice it seems to not make any changes to those fields.
    // But if it did we'd want to ensure the fields have sane values.
    //

    ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    ClassifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
}

void ClassificationApplyHardPermit
(
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

void ClassificationApplySoftPermit
(
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    ClassifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
}
