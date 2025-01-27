#pragma once



#define DEVICE_NAME         L"\\Device\\Splitter"
#define DEVICE_SYMLINK_NAME L"\\DosDevices\\Splitter"



//
// The device context performs the same job as
// a WDM device extension in the driver frameworks
//
typedef struct _DEVICE_CONTEXT
{
    WDFDEVICE               Device;

    //
    //
    //

} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

//
// This macro will generate an inline function called DeviceGetContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
//
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)


NTSTATUS
InitControlDevice(
    _In_ WDFDRIVER driver
);

VOID
InvertedEvtIoDeviceControl(WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
);


EXTERN_C_START


DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;


EXTERN_C_END
