#pragma once
#include <ntifs.h>

#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define MM_NOCACHE            0x8
#define MM_GUARD_PAGE         0x10
#define MM_DECOMMIT           0x10   // NO_ACCESS, Guard page
#define MM_NOACCESS           0x18   // NO_ACCESS, Guard_page, nocache.
#define MM_UNKNOWN_PROTECTION 0x100  // bigger than 5 bits!

#define MM_INVALID_PROTECTION ((ULONG)-1)  // bigger than 5 bits!

#define MM_PROTECTION_WRITE_MASK     4
#define MM_PROTECTION_COPY_MASK      1
#define MM_PROTECTION_OPERATION_MASK 7 // mask off guard page and nocache.
#define MM_PROTECTION_EXECUTE_MASK   2

#define MM_SECURE_DELETE_CHECK 0x55

//0x8 bytes (sizeof)
typedef struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Dirty1 : 1;                                                     //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Unused : 1;                                                     //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG ReservedForHardware : 4;                                        //0x0
	ULONGLONG ReservedForSoftware : 4;                                        //0x0
	ULONGLONG WsleAge : 4;                                                    //0x0
	ULONGLONG WsleProtection : 3;                                             //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
}MMPTE_HARDWARE;

//0x8 bytes (sizeof)
typedef struct _MMPTE_PROTOTYPE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG DemandFillProto : 1;                                            //0x0
	ULONGLONG HiberVerifyConverted : 1;                                       //0x0
	ULONGLONG ReadOnly : 1;                                                   //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Combined : 1;                                                   //0x0
	ULONGLONG Unused1 : 4;                                                    //0x0
	LONGLONG ProtoAddress : 48;                                               //0x0
}MMPTE_PROTOTYPE;

//0x8 bytes (sizeof)
typedef struct _MMPTE_SOFTWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG PageFileReserved : 1;                                           //0x0
	ULONGLONG PageFileAllocated : 1;                                          //0x0
	ULONGLONG ColdPage : 1;                                                   //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG UsedPageTableEntries : 10;                                      //0x0
	ULONGLONG ShadowStack : 1;                                                //0x0
	ULONGLONG Unused : 5;                                                     //0x0
	ULONGLONG PageFileHigh : 32;                                              //0x0
}MMPTE_SOFTWARE;

//0x8 bytes (sizeof)
typedef struct _MMPTE_TIMESTAMP
{
	ULONGLONG MustBeZero : 1;                                                 //0x0
	ULONGLONG Unused : 3;                                                     //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG Reserved : 16;                                                  //0x0
	ULONGLONG GlobalTimeStamp : 32;                                           //0x0
}MMPTE_TIMESTAMP;

//0x8 bytes (sizeof)
typedef struct _MMPTE_TRANSITION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG Spare : 1;                                                      //0x0
	ULONGLONG IoTracker : 1;                                                  //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG Unused : 16;                                                    //0x0
}MMPTE_TRANSITION;

//0x8 bytes (sizeof)
typedef struct _MMPTE_SUBSECTION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Unused0 : 3;                                                    //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG ColdPage : 1;                                                   //0x0
	ULONGLONG Unused1 : 3;                                                    //0x0
	ULONGLONG ExecutePrivilege : 1;                                           //0x0
	LONGLONG SubsectionAddress : 48;                                          //0x0
}MMPTE_SUBSECTION;

//0x8 bytes (sizeof)
typedef struct _MMPTE_LIST
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG OneEntry : 1;                                                   //0x0
	ULONGLONG filler0 : 2;                                                    //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG filler1 : 16;                                                   //0x0
	ULONGLONG NextEntry : 36;                                                 //0x0
}MMPTE_LIST;

//0x8 bytes (sizeof)
typedef struct _MMPTE
{
	union
	{
		ULONGLONG Long;                                                     //0x0
		volatile ULONGLONG VolatileLong;                                    //0x0
		MMPTE_HARDWARE Hard;									            //0x0
		MMPTE_PROTOTYPE Proto;										        //0x0
		MMPTE_SOFTWARE Soft;										        //0x0
		MMPTE_TIMESTAMP TimeStamp;									        //0x0
		MMPTE_TRANSITION Trans;										        //0x0
		MMPTE_SUBSECTION Subsect;									        //0x0
		MMPTE_LIST List;											        //0x0
	} u;                                                                    //0x0
}MMPTE;

//0x8 bytes (sizeof)
typedef struct _MI_ACTIVE_PFN
{
	union
	{
		struct
		{
			ULONGLONG Tradable : 1;                                           //0x0
			ULONGLONG NonPagedBuddy : 43;                                     //0x0
		} Leaf;                                                             //0x0
		struct
		{
			ULONGLONG Tradable : 1;                                           //0x0
			ULONGLONG WsleAge : 3;                                            //0x0
			ULONGLONG OldestWsleLeafEntries : 10;                             //0x0
			ULONGLONG OldestWsleLeafAge : 3;                                  //0x0
			ULONGLONG NonPagedBuddy : 43;                                     //0x0
		} PageTable;                                                        //0x0
		ULONGLONG EntireActiveField;                                        //0x0
	};
}MI_ACTIVE_PFN
;

//0x8 bytes (sizeof)
typedef struct _MIPFNBLINK
{
	union
	{
		struct
		{
			ULONGLONG Blink : 36;                                             //0x0
			ULONGLONG NodeBlinkHigh : 20;                                     //0x0
			ULONGLONG TbFlushStamp : 4;                                       //0x0
			ULONGLONG Unused : 2;                                             //0x0
			ULONGLONG PageBlinkDeleteBit : 1;                                 //0x0
			ULONGLONG PageBlinkLockBit : 1;                                   //0x0
			ULONGLONG ShareCount : 62;                                        //0x0
			ULONGLONG PageShareCountDeleteBit : 1;                            //0x0
			ULONGLONG PageShareCountLockBit : 1;                              //0x0
		};
		ULONGLONG EntireField;                                              //0x0
		volatile LONGLONG Lock;                                             //0x0
		struct
		{
			ULONGLONG LockNotUsed : 62;                                       //0x0
			ULONGLONG DeleteBit : 1;                                          //0x0
			ULONGLONG LockBit : 1;                                            //0x0
		};
	};
}MIPFNBLINK;

//0x1 bytes (sizeof)
typedef struct _MMPFNENTRY1
{
	UCHAR PageLocation : 3;                                                   //0x0
	UCHAR WriteInProgress : 1;                                                //0x0
	UCHAR Modified : 1;                                                       //0x0
	UCHAR ReadInProgress : 1;                                                 //0x0
	UCHAR CacheAttribute : 2;                                                 //0x0
}MMPFNENTRY1;

//0x1 bytes (sizeof)
typedef struct _MMPFNENTRY3
{
	UCHAR Priority : 3;                                                       //0x0
	UCHAR OnProtectedStandby : 1;                                             //0x0
	UCHAR InPageError : 1;                                                    //0x0
	UCHAR SystemChargedPage : 1;                                              //0x0
	UCHAR RemovalRequested : 1;                                               //0x0
	UCHAR ParityError : 1;                                                    //0x0
}MMPFNENTRY3;

//0x30 bytes (sizeof)
typedef struct _MMPFN
{
	union
	{
		LIST_ENTRY ListEntry;                                       //0x0
		RTL_BALANCED_NODE TreeNode;                                 //0x0
		struct
		{
			union
			{
				struct _SINGLE_LIST_ENTRY NextSlistPfn;                     //0x0
				VOID* Next;                                                 //0x0
				ULONGLONG Flink : 36;                                         //0x0
				ULONGLONG NodeFlinkHigh : 28;                                 //0x0
				MI_ACTIVE_PFN Active;                               //0x0
			} u1;                                                           //0x0
			union
			{
				MMPTE* PteAddress;                                  //0x8
				ULONGLONG PteLong;                                          //0x8
			};
			MMPTE OriginalPte;                                      //0x10
		};
	};
	MIPFNBLINK u2;                                                  //0x18
	union
	{
		struct
		{
			USHORT ReferenceCount;                                          //0x20
			MMPFNENTRY1 e1;                                         //0x22
		};
		struct
		{
			MMPFNENTRY3 e3;                                         //0x23
			struct
			{
				USHORT ReferenceCount;                                          //0x20
			} e2;                                                               //0x20
		};
		struct
		{
			ULONG EntireField;                                              //0x20
		} e4;                                                               //0x20
	} u3;                                                                   //0x20
	USHORT NodeBlinkLow;                                                    //0x24
	UCHAR Unused : 4;                                                         //0x26
	UCHAR Unused2 : 4;                                                        //0x26
	union
	{
		UCHAR ViewCount;                                                    //0x27
		UCHAR NodeFlinkLow;                                                 //0x27
		struct
		{
			UCHAR ModifiedListBucketIndex : 4;                                //0x27
			UCHAR AnchorLargePageSize : 2;                                    //0x27
		};
	};
}MMPFN;
static_assert(sizeof(MMPFN) == 0x30, "Size check");

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;