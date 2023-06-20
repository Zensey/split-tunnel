#pragma once


#include "common.h"
#include "wfp.h"


struct PENDED_CLASSIFICATION
{
	LIST_ENTRY listEntry;

	UINT64 ProcessId;

	ULONGLONG Timestamp;


	// Handle used to trigger re-auth or resume processing.
	UINT64 ClassifyHandle;

	// Result of classification is recorded here.
	FWPS_CLASSIFY_OUT0 ClassifyOut;

	// Filter that triggered the classification.
	UINT64 FilterId;

	// Layer in which classification is occurring.
	UINT16 LayerId;
};


NTSTATUS
PendRequest
(
	MAIN_CONTEXT* Context,
	UINT64 ProcessId,
	UINT64 FilterId,
	UINT16 LayerId,
	void* ClassifyContext,
	FWPS_CLASSIFY_OUT0* ClassifyOut
);

void
ClassifyWorker(
	_In_ void* StartContext
);

NTSTATUS
CompleteIoctlRequest
(
	PENDED_CLASSIFICATION *req
);

NTSTATUS
CompleteIoctlResponse();

void
ReauthPendedRequest
(
	PENDED_CLASSIFICATION* Record,
	BOOL decision
);