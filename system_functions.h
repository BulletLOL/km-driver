#pragma once
#include "include.h"
#include "framework.h"

namespace cv_hooked_functions {
	typedef NTSTATUS (*NTSETINFORMATIONFILE)
		(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN PVOID FileInformation,
			IN ULONG Length,
			IN FILE_INFORMATION_CLASS FileInformationClass
			);

	inline NTSETINFORMATIONFILE NtSetInformationFile = ( NTSETINFORMATIONFILE )NULL;
	inline NTSETINFORMATIONFILE Old_NtSetInformationFile = ( NTSETINFORMATIONFILE )NULL;
}

typedef struct _MEMORY_DESCRIPTOR {
	PVOID VirtualAddress;
	ULONG64 PhysicalAddress;
}MEMORY_DESCRIPTOR, * PMEMORY_DESCRIPTOR;

typedef struct _NOIR_PROTECTED_FILE_NAME {
	ERESOURCE Lock;
	SIZE_T Length;
	SIZE_T MaximumLength;
	WCHAR FileName[1];
}NOIR_PROTECTED_FILE_NAME, * PNOIR_PROTECTED_FILE_NAME;

typedef struct _NOIR_HOOK_PAGE {
	MEMORY_DESCRIPTOR OriginalPage;
	MEMORY_DESCRIPTOR HookedPage;
	PVOID Pte;
	PMDL Mdl;
}NOIR_HOOK_PAGE, * PNOIR_HOOK_PAGE;

inline PNOIR_PROTECTED_FILE_NAME NoirProtectedFile = ( PNOIR_PROTECTED_FILE_NAME )NULL;

inline PNOIR_HOOK_PAGE noir_hook_pages = ( PNOIR_HOOK_PAGE )NULL;
inline u32 noir_hook_pages_count = 0;

#define HookPages        noir_hook_pages
#define HookPageCount    noir_hook_pages_count
#define HookPageLimit    8

namespace system_functions
{
	/*utils*/
	PVOID get_base();
	uintptr_t swap_process(uintptr_t new_process);
	BOOL safe_copy(PVOID dest, PVOID src, SIZE_T size);
	uintptr_t get_loaded_module(const wchar_t* name, PLDR_DATA_TABLE_ENTRY* entry = nullptr);
	uintptr_t get_system_module(const wchar_t* name);
	uintptr_t get_routine_address(uintptr_t image, const char* name);
	uintptr_t find_pattern(uintptr_t base, const char* pattern, const char* mask);
	NTSTATUS get_module_base_address(int pid, const char* module_name, uint64_t* base_address);

	/*allocate mdl memory*/
	void free_mdl_memory(MDL_INFORMATION& memory);
	PVOID allocate_kernel_memory(const size_t _size, uintptr_t* mdl);
	bool expose_kernel_memory(PEPROCESS process, const uintptr_t kernel_address, const size_t size);

	/*control flow guard bypass*/
	NTSTATUS bypass_cfg(PEPROCESS Process);
	NTSTATUS bypass_cfg_second(PEPROCESS process, int pid, uintptr_t section_base, size_t section_size);
}

namespace main_utilities {
	ULONG get_patch_size (IN PVOID code, IN ULONG hook_length);
}