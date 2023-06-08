#pragma once




#define IPV4_ADDR(a, b, c, d)(((d & 0xff) << 24) | ((c & 0xff) << 16) | \
        ((b & 0xff) << 8) | (a & 0xff))



void NTAPI DriverConnectRedirectClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI DriverConnectRedirectPermitClassify(
    _In_ const FWPS_INCOMING_VALUES* FixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* MetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void ClassificationReset
(
    FWPS_CLASSIFY_OUT0* ClassifyOut
);

void ClassificationApplyHardPermit
(
    FWPS_CLASSIFY_OUT0* ClassifyOut
);

void ClassificationApplySoftPermit
(
    FWPS_CLASSIFY_OUT0* ClassifyOut
);

NTSTATUS NTAPI DriverNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter
);
