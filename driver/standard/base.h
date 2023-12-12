#pragma once

#define _CRT_ALLOCATION_DEFINED
#define NDIS61 1
#define NDIS_SUPPORT_NDIS61 1

#if defined(DBG)
//#define LOG_BUILD 1 //加上這個build速度很慢
#endif
#ifdef __cplusplus
#ifndef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#endif

#define FLT_MGR_LEGACY_PUSH_LOCKS
#define NTSTRSAFE_LIB
#define NTSTRSAFE_NO_CB_FUNCTIONS

extern "C"
{
#pragma warning(push, 0)
#include <initguid.h>
#include <fltKernel.h>
#include <Wdmsec.h>
#include <ntdef.h>
#include <ntimage.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include <ntdddisk.h>
	//#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <intrin.h>
#include <Aux_klib.h>
#include <wdmguid.h>
#pragma warning(pop)
#include <ntifs.h>
#include <fwpmk.h>
#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)
#include <ntddkbd.h>
#include <ntddscsi.h>
#include <srb.h>
#include <scsi.h>
#include <wsk.h>

#include <basetsd.h>
};
#else
//C的头
#include <ntifs.h>
#include <ntdef.h>
#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include <ntddscsi.h>
#include <srb.h>
#include <ntimage.h>
#include <aux_klib.h>
#include <ntstrsafe.h>
#include "ddk_stdint.h"
#endif

#ifdef __cplusplus
//STL for ddk
#include <tuple>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <array>
#include <memory>
#include <list>
#include <deque>
#include <functional>
#include <regex>
#include <utility>
#include <memory>
#include <unordered_map>
#include <sstream>
#include <atomic>
#include <set>
#endif

#define  print(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

#define _kd_print(format, ...) KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__))

constexpr bool _is_release_build() {
#if defined(DBG)
	return false;
#else
	return true;
#endif
}

constexpr bool _is_x64() {
#if defined(_AMD64_)
	return true;
#else
	return false;
#endif
}

#define _is_invalid(expression, returned)	\
	if(expression){							\
		return returned;					\
	}										\

//需要管理员处理才能工作 STATUS_DOWNGRADE_DETECTED
//恶意软件通报 STATUS_VIRUS_INFECTED
#define MAGIC_NTSTATUS     0x80070000
#define STATUS_CUSTOM_STATUS(x) (MAGIC_NTSTATUS + x) //不出错误框

#ifdef __cplusplus
//一些类型定义
#include "stdcpp.h"
#include "kernel_stl.h"
#include "singleton.hpp"
#include "spcoe_exit.hpp"
#include "unique_resource.h"
#include "../define/exapi.h"
#include "../define/keapi.h"
#include "../define/mmapi.h"
#include "../define/ntapi.h"
#include "../define/obapi.h"
#include "../define/psapi.h"
#include "../define/rtlapi.h"
#include "../define/zwapi.h"
#include "../define/ntdef.h"
#endif
