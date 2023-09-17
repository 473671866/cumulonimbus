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

#define INOUT
#ifdef ALLOC_PRAGMA
#define ALLOC_TEXT(Section, Name) __pragma(alloc_text(Section, Name))
#else
#define ALLOC_TEXT(Section, Name)
#endif
// _countof. You do not want to type RTL_NUMBER_OF, do you?
#ifndef _countof
#define _countof(x)    RTL_NUMBER_OF(x)
#endif

// Returns true when it is running on the x64 system.
// inline bool IsX64() {
// #ifdef _AMD64_
// 	return true;
// #else
// 	return false;
// #endif
// }
// Break point that works only when a debugger is attached.
#ifndef DBG_BREAK
#ifdef _ARM_
// Nullify it since an ARM device never allow us to attach a debugger.
#define DBG_BREAK()
#else
#define DBG_BREAK()               \
  if (KD_DEBUGGER_NOT_PRESENT) {  \
		  } else {                        \
	__debugbreak();               \
		  }                               \
  reinterpret_cast<void *>(0)
#endif
#endif

constexpr bool IsReleaseBuild() {
#if defined(DBG)
	return false;
#else
	return true;
#endif
}

constexpr bool IsX64() {
#if defined(_AMD64_)
	return true;
#else
	return false;
#endif
}

#define MAGIC_NTSTATUS     0x80070000
#define STATUS_CUSTOM_STATUS(x) (MAGIC_NTSTATUS + x) //不出错误框
//需要管理员处理才能工作 STATUS_DOWNGRADE_DETECTED
//恶意软件通报 STATUS_VIRUS_INFECTED

#ifdef __cplusplus
//一些类型定义
#include "singleton.hpp"
#include "kernel_stl.h"
#include "stdcpp.h"
#include "unique_resource.h"
#include "spcoe_exit.hpp"
#include "log.h"
#include "ia32.hpp"
#include "../exapi.h"
#include "../keapi.h"
#include "../mmapi.h"
#include "../ntapi.h"
#include "../obapi.h"
#include "../psapi.h"
#include "../rtlapi.h"
#include "../zwapi.h"
#include "../ntdef.h"
#endif
