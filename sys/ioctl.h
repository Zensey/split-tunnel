/*

*/
#ifdef KERNEL_MODE
#include "ntddk.h"
#else
#include "windows.h"
#include "winioctl.h"
#endif

//
// The following value is arbitrarily chosen from the space defined by Microsoft
// as being "for non-Microsoft use"
//
#define FILE_DEVICE_SPLITTER FILE_DEVICE_UNKNOWN

//
// Device control codes
//
#define IOCTL_SPLITTER_REQUEST CTL_CODE(FILE_DEVICE_SPLITTER, 2049, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPLITTER_REPLY   CTL_CODE(FILE_DEVICE_SPLITTER, 2050, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPLITTER_CONFIG  CTL_CODE(FILE_DEVICE_SPLITTER, 2051, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct {
	UINT64 pid;
	UINT8  result;
} DrvRequest;

typedef struct {
	UINT32 ip;
} DrvConfig;