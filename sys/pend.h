#pragma once


#include "common.h"
#include "wfp.h"


struct PENDED_CLASSIFICATION
{
	LIST_ENTRY listEntry;

	HANDLE ProcessId;

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
	HANDLE ProcessId,
	UINT64 FilterId,
	UINT16 LayerId,
	void* ClassifyContext,
	FWPS_CLASSIFY_OUT0* ClassifyOut
);

void
ClassifyWorker(
	_In_ void* StartContext
);

void
ReauthPendedRequest
(
	PENDED_CLASSIFICATION* Record
);