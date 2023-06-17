/*

*/


#include "common.h"
#include "wfp.h"

#include "driver.h"
#include "driver.tmh"



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WPP_INIT_TRACING(DriverObject, RegistryPath);

    DoTraceMessage(Default, "DriverEntry() enter");

    DriverObject->DriverUnload = DriverUnload;

    InitializeWfp(DriverObject);

    DoTraceMessage(Default, "DriverEntry() exit");

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DoTraceMessage(Default, "DriverUnload enter");

    ClearWfp();

    DoTraceMessage(Default, "DriverUnload exit");

    WPP_CLEANUP(DriverObject);
}
