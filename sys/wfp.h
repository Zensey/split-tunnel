#pragma once



#include <wdm.h>
#include <wdf.h>



#define IPV4_ADDR(a, b, c, d)(((d & 0xff) << 24) | ((c & 0xff) << 16) | \
        ((b & 0xff) << 8) | (a & 0xff))


#define HOST_REDIRECT IPV4_ADDR(172, 20, 37, 103)
#define PROCESS_ID 3932


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

	int hostRedirect;
};






NTSTATUS
InitializeWfp(PDRIVER_OBJECT DriverObject);

NTSTATUS
ClearWfp();

NTSTATUS
InitializeWfpContext(MAIN_CONTEXT** Context);

void
ClearWfpContext(MAIN_CONTEXT* Context);
