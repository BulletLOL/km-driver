#pragma once

#include <stdint.h>
#include <ntdef.h>
#include <ntifs.h>

#include <Zydis/Zydis.h>

#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>

#include "xorstr.h"
#include "crt.h"
#include "defines.h"
#include "ia32.h"

#define printf(text, ...) DbgPrintEx(DPFLTR_IHVBUS_ID, 0, XORS("[CB]: " text), ##__VA_ARGS__)
#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))
#define size_align(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define in_range(x,a,b)    (x >= a && x <= b) 
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))

#define IMAGE64(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define LDR_IS_DATAFILE(x)			(((ULONG_PTR)(x)) & (ULONG_PTR)1)
#define LDR_DATAFILE_TO_VIEW(x)		((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))

#define MM_EXECUTE_READWRITE (6)

#define WM_NULL                         0x0000
#define WM_CREATE                       0x0001
#define WM_DESTROY                      0x0002
#define WM_MOVE                         0x0003
#define WM_SIZE                         0x0005

#define WM_ACTIVATE                     0x0006

#define WA_INACTIVE     0
#define WA_ACTIVE       1
#define WA_CLICKACTIVE  2

#define WM_SETFOCUS                     0x0007
#define WM_KILLFOCUS                    0x0008
#define WM_ENABLE                       0x000A
#define WM_SETREDRAW                    0x000B
#define WM_SETTEXT                      0x000C
#define WM_GETTEXT                      0x000D
#define WM_GETTEXTLENGTH                0x000E
#define WM_PAINT                        0x000F
#define WM_CLOSE                        0x0010
#define WM_QUIT                         0x0012
#define WM_ERASEBKGND                   0x0014
#define WM_SYSCOLORCHANGE               0x0015
#define WM_SHOWWINDOW                   0x0018
#define WM_WININICHANGE                 0x001A

#if defined(_WIN64)
#define HookLength				23
#define DetourLength			14
#else
#define HookLength				5
#define DetourLength			5
#endif

extern "C" NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

inline ZydisDecoder zy_dec16;
inline ZydisDecoder zy_dec32;
inline ZydisDecoder zy_dec64;
inline ZydisFormatter zy_fmt;

// Simple Memory Introspection Counters
inline LONG volatile allocated_non_paged_pools = 0;
inline LONG volatile allocated_paged_pools = 0;
inline LONG volatile allocated_contiguous_memory_count = 0;

#if defined(_msvc) || defined(_llvm)
#pragma once

typedef unsigned __int8		u8;
typedef unsigned __int16	u16;
typedef unsigned __int32	u32;
typedef unsigned __int64	u64;

typedef signed __int8		i8;
typedef signed __int16		i16;
typedef signed __int32		i32;
typedef signed __int64		i64;
#endif

typedef struct _PAGE_INFORMATION
{
	PML4E_64* PML4E;
	PDPTE_64* PDPTE;
	PDE_64* PDE;
	PTE_64* PTE;
}PAGE_INFORMATION, * PPAGE_INFORMATION;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSCALL_DATA {
	DWORD Unique;
	DWORD Syscall;
	PVOID Arguments;
} SYSCALL_DATA, * PSYSCALL_DATA;

typedef struct _MDL_INFORMATION
{
	MDL* mdl;
	uintptr_t va;
}MDL_INFORMATION, * PMDL_INFORMATION;

typedef struct _LARGE_UNICODE_STRING
{
	ULONG Length;           // 000
	ULONG MaximumLength : 31; // 004
	ULONG bAnsi : 1;          // 004
	PWSTR Buffer;           // 008
} LARGE_UNICODE_STRING, * PLARGE_UNICODE_STRING;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	VOID* ExceptionTable;                                                   //0x10
	ULONG ExceptionTableSize;                                               //0x18
	VOID* GpValue;                                                          //0x20
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	union
	{
		USHORT SignatureLevel : 4;                                            //0x6e
		USHORT SignatureType : 3;                                             //0x6e
		USHORT Frozen : 2;                                                    //0x6e
		USHORT HotPatch : 1;                                                  //0x6e
		USHORT Unused : 6;                                                    //0x6e
		USHORT EntireField;                                                 //0x6e
	} u1;                                                                   //0x6e
	VOID* SectionPointer;                                                   //0x70
	ULONG CheckSum;                                                         //0x78
	ULONG CoverageSectionSize;                                              //0x7c
	VOID* CoverageSection;                                                  //0x80
	VOID* LoadedImports;                                                    //0x88
	union
	{
		VOID* Spare;                                                        //0x90
		struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;                    //0x90
	};
	ULONG SizeOfImageNotRounded;                                            //0x98
	ULONG TimeDateStamp;                                                    //0x9c
} _KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

