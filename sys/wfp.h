#pragma once


#include <wdm.h>
#include <wdf.h>



struct MAIN_CONTEXT
{
	WDFDEVICE   ControlDevice;
	WDFQUEUE    NotificationQueue;
	WDFQUEUE    NotificationQueue2;


	WDFSPINLOCK ClassificationsLock;

	// PENDED_CLASSIFICATION: step 1
	LIST_ENTRY ClassificationsQueue;

	// PENDED_CLASSIFICATION: step 2
	LIST_ENTRY ResQueue;

	KEVENT ClassificationQueueEvent;
	KEVENT InvertedCallEvent;
	KEVENT DecisionEvent;


	// worker
	PKTHREAD Thread;
	BOOL Quit;

	UINT32 HostRedirect;
};

NTSTATUS
InitializeWfp(PDRIVER_OBJECT DriverObject);

NTSTATUS
ClearWfp();

NTSTATUS
InitializeWfpContext(MAIN_CONTEXT** Context);

void
ClearWfpContext(MAIN_CONTEXT* Context);
