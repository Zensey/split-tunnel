#pragma once


#include <ntddk.h>
#include <wdm.h>
#include <initguid.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630
#include <ndis.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>
#include <mstcpip.h>




#define ST_POOL_TAG 'uuu'

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(Default, (81C29CFA,1DD4,4177,9B97,8A361B74B246), \
        WPP_DEFINE_BIT(Default) \
    )

