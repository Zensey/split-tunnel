#pragma once



#include <wdm.h>
#include <wdf.h>

struct pCONTEXT
{
	WDFSPINLOCK Lock;

	// PENDED_CLASSIFICATION
	LIST_ENTRY Classifications;
};



NTSTATUS
InitializeWfp(PDRIVER_OBJECT DriverObject);

NTSTATUS
ClearWfp();

NTSTATUS
InitializeWfpContext(pCONTEXT** Context);


