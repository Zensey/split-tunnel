/*

*/


#include "ioctl.h"
#include "common.h"
#include "wfp.h"

#include "driver.h"
#include "driver.tmh"




#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, EvtDriverUnload)
#endif


extern MAIN_CONTEXT* g_Context;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;


    WPP_INIT_TRACING(DriverObject, RegistryPath);

    DoTraceMessage(Default, "DriverEntry() enter");

    WDF_DRIVER_CONFIG_INIT(
        &config,
        WDF_NO_EVENT_CALLBACK
    );

    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

    auto status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver
    );
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    InitializeWfp(DriverObject);
    status = InitControlDevice(driver);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    DoTraceMessage(Default, "DriverEntry() exit");

    return STATUS_SUCCESS;
}


//
// Create the minimal WDF Driver and Device objects required for a WFP callout
// driver.
//
NTSTATUS
InitControlDevice(
    _In_ WDFDRIVER driver
)
{
    NTSTATUS status;
    WDFDEVICE controlDevice;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;

    DECLARE_CONST_UNICODE_STRING(devName, DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(userDeviceName, DEVICE_SYMLINK_NAME);

    auto deviceInit = WdfControlDeviceInitAllocate(
        driver,
        &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R
    );
    if (!deviceInit)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    status = WdfDeviceInitAssignName(deviceInit, &devName);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    status = WdfDeviceCreate(
        &deviceInit,
        WDF_NO_OBJECT_ATTRIBUTES,
        &controlDevice
    );
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = WdfDeviceCreateSymbolicLink(controlDevice, &userDeviceName);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "WdfDeviceCreateSymbolicLink Status=%!STATUS!", status);
        goto Exit;
    }

    ///////////////////////////////////////////////////////////////////////////

    // IOCTL queue
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig,
        WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = InvertedEvtIoDeviceControl;
    queueConfig.PowerManaged = WdfFalse;
    status = WdfIoQueueCreate(controlDevice,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "WdfIoQueueCreate Status=%!STATUS!", status);
        goto Exit;
    }

    // Request dispatch queue
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.PowerManaged = WdfFalse;
    status = WdfIoQueueCreate(controlDevice,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &g_Context->NotificationQueue);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "WdfIoQueueCreate #2 Status=%!STATUS!", status);
        goto Exit;
    }
    
    // Request dispatch queue
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.PowerManaged = WdfFalse;
    status = WdfIoQueueCreate(controlDevice,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &g_Context->NotificationQueue2);
    if (!NT_SUCCESS(status))
    {
        DoTraceMessage(Default, "WdfIoQueueCreate #2 Status=%!STATUS!", status);
        goto Exit;
    }


    WdfControlFinishInitializing(controlDevice);
    g_Context->ControlDevice = controlDevice;
    return status;

Exit:
    if (deviceInit) {
        WdfDeviceInitFree(deviceInit);
    }
    return status;
}

VOID
InvertedEvtIoDeviceControl(
WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {

    //
    // inverted call. completed by the driver when an event occurs
    //
    case IOCTL_SPLITTER_REQUEST: {
        DoTraceMessage(Default, "InvertedEvtIoDeviceControl N");

        //
        // Be sure the user's data buffer is at least long enough for reply.
        // 
        if (OutputBufferLength < sizeof(LONG)) {
            WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
            break;
        }

        auto status = WdfRequestForwardToIoQueue(Request, g_Context->NotificationQueue);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            break;
        }
        KeSetEvent(
            &g_Context->InvertedCallEvent,
            0,
            FALSE
        );
        DoTraceMessage(Default, "InvertedEvtIoDeviceControl N KeSetEvent");

        //
        // RETURN HERE WITH REQUEST PENDING
        //
        return;
    }
    case IOCTL_SPLITTER_REPLY: {
        DoTraceMessage(Default, "InvertedEvtIoDeviceControl D");

        auto status = WdfRequestForwardToIoQueue(Request, g_Context->NotificationQueue2);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            break;
        }
        KeSetEvent(
            &g_Context->DecisionEvent,
            0,
            FALSE
        );
        DoTraceMessage(Default, "InvertedEvtIoDeviceControl D KeSetEvent");

        //
        // RETURN HERE WITH REQUEST PENDING
        //
        return;
    }

    default: {
        DoTraceMessage(Default, "InvertedEvtIoDeviceControl: Invalid IOCTL received");

        break;
    }

    }
}

VOID
DeleteControlDevice()
{
    PAGED_CODE();

    DoTraceMessage(Default, "DeleteControlDevice");

    WdfObjectDelete(g_Context->ControlDevice);
}

VOID
EvtDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();


    DoTraceMessage(Default, "DriverUnload enter");

    DeleteControlDevice();
    ClearWfp();

    DoTraceMessage(Default, "DriverUnload exit");

    WPP_CLEANUP(Driver);
}
