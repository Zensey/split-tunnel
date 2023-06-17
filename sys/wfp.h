#pragma once



#include <wdm.h>
#include <wdf.h>



#define IPV4_ADDR(a, b, c, d)(((d & 0xff) << 24) | ((c & 0xff) << 16) | \
        ((b & 0xff) << 8) | (a & 0xff))


#define HOST_REDIRECT IPV4_ADDR(172, 20, 37, 103)
#define PROCESS_ID 3932


struct MAIN_CONTEXT
{
	WDFSPINLOCK classificationsLock;
	// PENDED_CLASSIFICATION
	LIST_ENTRY classificationsQueue;
	KEVENT classificationQueueEvent;
	// worker
	PKTHREAD Thread;
	BOOL quit;

	int hostRedirect;
	UINT64 processId;
};






NTSTATUS
InitializeWfp(PDRIVER_OBJECT DriverObject);

NTSTATUS
ClearWfp();

NTSTATUS
InitializeWfpContext(MAIN_CONTEXT** Context);

void
ClearWfpContext(MAIN_CONTEXT* Context);
