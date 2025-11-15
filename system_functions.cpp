#pragma once
#include "system_functions.h"
#include "ia32.h"
#include "phys.h"
#include "memory.h"
#include "process_functions.h"
#include "libcryvisor.hpp"

namespace system_functions
{
	typedef NTSTATUS(__fastcall* pfnMiProcessLoaderEntry)(PVOID pDriverSection, LOGICAL IsLoad);
	PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable);
	NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process);
	VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process);

	extern "C" POBJECT_TYPE * IoDriverObjectType;

	uintptr_t get_loaded_module(const wchar_t* name, PLDR_DATA_TABLE_ENTRY* entry)
	{
		if (!name || system_environment::PsLoadedModuleList == NULL || IsListEmpty(system_environment::PsLoadedModuleList))
			return NULL;

		UNICODE_STRING modName;
		RtlInitUnicodeString(&modName, name);

		for (PLIST_ENTRY pEntry = system_environment::PsLoadedModuleList->Flink; pEntry != system_environment::PsLoadedModuleList; pEntry = pEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY data = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlEqualUnicodeString(&data->BaseDllName, &modName, TRUE))
			{
				if (entry)
					*entry = data;
				return (uintptr_t)data->DllBase;
			}
		}
		return NULL;
	}

	PVOID get_kernel_base() {
		PVOID KernelBase = NULL;

		ULONG size = NULL;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
		if (STATUS_INFO_LENGTH_MISMATCH != status) {
			return KernelBase;
		}

		PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
		if (!Modules) {
			return KernelBase;
		}

		if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, Modules, size, 0))) {
			ExFreePool(Modules);
			return KernelBase;
		}

		if (Modules->NumberOfModules > 0) {
			KernelBase = Modules->Modules[0].ImageBase;
		}

		ExFreePool(Modules);
		return KernelBase;
	}

	uintptr_t get_system_module(const wchar_t* name)
	{
		NTSTATUS status = STATUS_SUCCESS;
		ANSI_STRING s_name;
		UNICODE_STRING su_name;
		RtlInitUnicodeString(&su_name, name);
		RtlUnicodeStringToAnsiString(&s_name, &su_name, TRUE);

		system_environment::PRTL_PROCESS_MODULES pModules = NULL;
		uint32_t szModules = 0;

		status = ZwQuerySystemInformation(SystemModuleInformation, 0, szModules, (PULONG)&szModules);
		if (!szModules)
		{
			RtlFreeAnsiString(&s_name);
			return 0;
		}

		pModules = ( system_environment::PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, szModules);
		if (!pModules)
		{
			RtlFreeAnsiString(&s_name);
			return 0;
		}
		RtlZeroMemory(pModules, szModules);

		status = ZwQuerySystemInformation(SystemModuleInformation, pModules, szModules, (PULONG)&szModules);
		if (!NT_SUCCESS(status))
		{
			RtlFreeAnsiString(&s_name);
			ExFreePool(pModules);
			return 0;
		}

		uintptr_t modBase = 0;
		system_environment::PRTL_PROCESS_MODULE_INFORMATION pMods = pModules->Modules;
		for (ULONG i = 0; i < pModules->NumberOfModules && !modBase; i++)
		{
			system_environment::RTL_PROCESS_MODULE_INFORMATION pMod = pMods[i];
			char* fullPath = (char*)pMod.FullPathName;
			if (fullPath && strlen(fullPath) > 0)
			{
				int32_t lastFound = -1;
				char* baseFullPath = (char*)pMod.FullPathName;
				while (*fullPath != 0)
				{
					if (*fullPath == '\\')
						lastFound = (fullPath - baseFullPath) + 1;
					fullPath++;
				}

				if (lastFound >= 0)
					fullPath = baseFullPath + lastFound;
			}
			else continue;

			ANSI_STRING s_fullPath;
			RtlInitAnsiString(&s_fullPath, fullPath);
			if (RtlEqualString(&s_fullPath, &s_name, TRUE))
				modBase = (uintptr_t)pMod.ImageBase;
		}
		RtlFreeAnsiString(&s_name);
		ExFreePool(pModules);
		return modBase;
	}

	uintptr_t get_routine_address(uintptr_t image, const char* name)
	{
		if (!image || !name)
			return NULL;
		return (uintptr_t)system_environment::RtlFindExportedRoutineByName((PVOID)image, name);
	}

	uintptr_t find_pattern(uintptr_t base, size_t range, const char* pattern, const char* mask)
	{
		const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool
		{
			for (; *mask; ++base, ++pattern, ++mask)
			{
				if (*mask == 'x' && *base != *pattern)
				{
					return false;
				}
			}

			return true;
		};

		range = range - crt::strlen(mask);

		for (size_t i = 0; i < range; ++i)
		{
			if (check_mask((const char*)base + i, pattern, mask))
			{
				return base + i;
			}
		}

		return NULL;
	}

	uintptr_t find_pattern(uintptr_t base, const char* pattern, const char* mask)
	{
		const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
		const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

		for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++)
		{
			const PIMAGE_SECTION_HEADER section = &sections[i];

			if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				const auto match = find_pattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);

				if (match)
				{
					return match;
				}
			}
		}

		return 0;
	}

	PVOID get_base() {
		PVOID addr = 0;

		ULONG size = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
		if (STATUS_INFO_LENGTH_MISMATCH != status) {
			return addr;
		}

		PSYSTEM_MODULE_INFORMATION modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
		if (!modules) {
			return addr;
		}

		if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
			ExFreePool(modules);
			return addr;
		}

		if (modules->NumberOfModules > 0) {
			addr = modules->Modules[0].ImageBase;
		}

		ExFreePool(modules);
		return addr;

	}

	BOOL safe_copy(PVOID dest, PVOID src, SIZE_T size) {
		SIZE_T returnSize = 0;
		NTSTATUS copy_memory = MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(),
			dest, size, KernelMode, &returnSize);
		if (NT_SUCCESS(copy_memory) && returnSize == size) {
			return TRUE;
		}

		printf("copy_memory %p\n", copy_memory);

		return FALSE;
	}

	MDL_INFORMATION allocate_mdl_memory(size_t size)
	{
		MDL_INFORMATION memory;

		PHYSICAL_ADDRESS lower, higher;
		lower.QuadPart = 0;
		higher.QuadPart = 0xffff'ffff'ffff'ffffULL;

		const auto pages = (size / PAGE_SIZE) + 1;

		const auto mdl = MmAllocatePagesForMdl(lower, higher, lower, pages * (uintptr_t)0x1000);

		if (!mdl)
		{
			return { 0, 0 };
		}

		const auto mapping_start_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

		if (!mapping_start_address)
		{
			return { 0, 0 };
		}

		if (!NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE)))
		{
			return { 0, 0 };
		}

		memory.mdl = mdl;
		memory.va = reinterpret_cast<uintptr_t> (mapping_start_address);

		//printf("allocated original %p\n", reinterpret_cast<uintptr_t> (mapping_start_address));

		return memory;
	}

	void free_mdl_memory(MDL_INFORMATION& memory)
	{
		MmUnmapLockedPages(reinterpret_cast<void*>(memory.va), memory.mdl);
		MmFreePagesFromMdl(memory.mdl);
		ExFreePool(memory.mdl);
	}

	PVOID allocate_kernel_memory(const size_t _size, uintptr_t* mdl)
	{
		const auto size = size_align(_size);

		auto memory = allocate_mdl_memory(size);

		while (memory.va % 0x10000 != 0)
		{
			free_mdl_memory(memory);
			memory = allocate_mdl_memory(size);
		}

		*mdl = (uintptr_t)memory.mdl;
		return (void*)memory.va;
	}

	PAGE_INFORMATION get_page_information(void* va, CR3 cr3)
	{
		ADDRESS_TRANSLATION_HELPER helper;
		UINT32 level;
		PML4E_64* pml4, * pml4e;
		PDPTE_64* pdpt, * pdpte;
		PDE_64* pd, * pde;
		PTE_64* pt, * pte;

		PAGE_INFORMATION info;

		helper.AsUInt64 = (uintptr_t)va;

		PHYSICAL_ADDRESS pa;

		pa.QuadPart = cr3.AddressOfPageDirectory << PAGE_SHIFT;

		pml4 = (PML4E_64*)MmGetVirtualForPhysical(pa);

		pml4e = &pml4[helper.AsIndex.Pml4];

		info.PML4E = pml4e;

		if (pml4e->Present == FALSE)
		{
			info.PTE = nullptr;
			info.PDE = nullptr;
			info.PDPTE = nullptr;

			goto end;
		}

		pa.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

		pdpt = (PDPTE_64*)MmGetVirtualForPhysical(pa);

		pdpte = &pdpt[helper.AsIndex.Pdpt];

		info.PDPTE = pdpte;

		if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
		{
			info.PTE = nullptr;
			info.PDE = nullptr;

			goto end;
		}

		pa.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

		pd = (PDE_64*)MmGetVirtualForPhysical(pa);

		pde = &pd[helper.AsIndex.Pd];

		info.PDE = pde;

		if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
		{
			info.PTE = nullptr;

			goto end;
		}

		pa.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

		pt = (PTE_64*)MmGetVirtualForPhysical(pa);

		pte = &pt[helper.AsIndex.Pt];

		info.PTE = pte;

		return info;

	end:
		return info;
	}

	uintptr_t swap_process(uintptr_t new_process)
	{
		auto current_thread = (uintptr_t)KeGetCurrentThread();

		auto apc_state = *(uintptr_t*)(current_thread + 0x98);
		auto old_process = *(uintptr_t*)(apc_state + 0x20);
		*(uintptr_t*)(apc_state + 0x20) = new_process;

		auto dir_table_base = *(uintptr_t*)(new_process + 0x28);
		__writecr3(dir_table_base);

		return old_process;
	}

	bool expose_kernel_memory(PEPROCESS process, const uintptr_t kernel_address, const size_t size) {
		const auto o_process = swap_process((uintptr_t)process);
		CR3 cr3{ };
		cr3.Flags = __readcr3();

		for (uintptr_t address = kernel_address; address <= kernel_address + size; address += 0x1000)
		{
			const auto page_information = get_page_information((void*)address, cr3);

			page_information.PDE->Supervisor = 1;
			page_information.PDPTE->Supervisor = 1;
			page_information.PML4E->Supervisor = 1;

			if (!page_information.PDE || (page_information.PTE && !page_information.PTE->Present))
			{

			}
			else
			{
				page_information.PTE->Supervisor = 1;
			}
		}

		swap_process(o_process);

		return true;
	}

	LONG64 resolve_relative_address(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
	{
		ULONG_PTR instr = (ULONG_PTR)Instruction;
		LONG rip_offset = *(PLONG)(instr + OffsetOffset);
		void* resolve_addr = (PVOID)(instr + InstructionSize + rip_offset);

		return (LONG64)resolve_addr;
	}

	NTSTATUS get_module_base_address(int pid, const char* module_name, uint64_t* base_address)
	{
		ANSI_STRING ansiString;
		UNICODE_STRING compareString;
		KAPC_STATE state;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PEPROCESS process = NULL;
		system_environment::PPEB pPeb = NULL;

		RtlInitAnsiString(&ansiString, module_name);
		RtlAnsiStringToUnicodeString(&compareString, &ansiString, TRUE);

		//printf("Looking for module %d\n", pid);

		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &process)))
			return STATUS_UNSUCCESSFUL;

		//printf("Found process %d\n", pid);

		const auto o_process = system_functions::swap_process((uintptr_t)process);
		pPeb = process::PsGetProcessPeb(process);

		if (pPeb)
		{
			system_environment::PPEB_LDR_DATA pLdr = ( system_environment::PPEB_LDR_DATA)pPeb->Ldr;

			if (pLdr)
			{
				for (PLIST_ENTRY listEntry = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
					listEntry != &pLdr->InLoadOrderModuleList;
					listEntry = (PLIST_ENTRY)listEntry->Flink) {

					system_environment::PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(listEntry, system_environment::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					//printf("%wZ\n", pEntry->BaseDllName);
					if (RtlCompareUnicodeString(&pEntry->BaseDllName, &compareString, TRUE) == 0)
					{
						*base_address = (uint64_t)pEntry->DllBase;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
		}
		system_functions::swap_process(o_process);
		RtlFreeUnicodeString(&compareString);
		return status;
	}

	BOOLEAN RtlIsCanonicalAddress(ULONG_PTR Address)
	{
		return (((Address & 0xFFFF800000000000) + 0x800000000000) & ~0x800000000000) == 0;
	}

	PIMAGE_NT_HEADERS NTAPI rtlp_image_ntheader_ex(_In_ PVOID Base, _In_opt_ SIZE_T Size){
		const BOOLEAN RangeCheck = Size > 0;
		constexpr ULONG SizeOfPeSignature = 4;

		if (RangeCheck && Size < sizeof(IMAGE_DOS_HEADER))
			return nullptr;
		if (static_cast<PIMAGE_DOS_HEADER>(Base)->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const ULONG e_lfanew = static_cast<PIMAGE_DOS_HEADER>(Base)->e_lfanew;
		if (RangeCheck &&
			(e_lfanew >= Size ||
				e_lfanew >= (MAXULONG - SizeOfPeSignature - sizeof(IMAGE_FILE_HEADER)) ||
				e_lfanew + SizeOfPeSignature + sizeof(IMAGE_FILE_HEADER) >= Size))
		{
			return nullptr;
		}

		const PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<PCHAR>(Base) + e_lfanew);

		if (!RtlIsCanonicalAddress(reinterpret_cast<ULONG_PTR>(NtHeaders)))
			return nullptr;

#if (defined(_KERNEL_MODE) && (_KERNEL_MODE))
		if (reinterpret_cast<ULONG_PTR>(Base) < reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
		{
			if (reinterpret_cast<ULONG_PTR>(NtHeaders) >= reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
				return nullptr;

			if (reinterpret_cast<ULONG_PTR>(reinterpret_cast<PCHAR>(NtHeaders) + sizeof(IMAGE_NT_HEADERS)) >=
				reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
				return nullptr;
		}
#endif

		if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		return NtHeaders;
	}

	ULONG rva_to_offset(_In_ PIMAGE_NT_HEADERS NtHeaders, _In_ ULONG Rva){
		PIMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
		const USHORT NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
		ULONG Result = 0;
		for (USHORT i = 0; i < NumberOfSections; ++i)
		{
			if (SectionHeaders->VirtualAddress <= Rva &&
				SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize > Rva)
			{
				Result = Rva - SectionHeaders->VirtualAddress +
					SectionHeaders->PointerToRawData;
				break;
			}
			SectionHeaders++;
		}
		return Result;
	}

	PVOID NTAPI rtlp_image_directory_entry_to_data_ex(_In_ PVOID Base, _In_ BOOLEAN MappedAsImage, _In_ USHORT DirectoryEntry, _Out_ PULONG Size){
		if (LDR_IS_DATAFILE(Base))
		{
			Base = LDR_DATAFILE_TO_VIEW(Base);
			MappedAsImage = FALSE;
		}

		const PIMAGE_NT_HEADERS NtHeaders = rtlp_image_ntheader_ex(Base, 0);
		if (NtHeaders == nullptr)
			return nullptr;

		if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes)
			return nullptr;

		const PIMAGE_DATA_DIRECTORY Directories = NtHeaders->OptionalHeader.DataDirectory;
		const ULONG Rva = Directories[DirectoryEntry].VirtualAddress;
		if (Rva == 0)
			return nullptr;

		if (reinterpret_cast<ULONG_PTR>(Base) < reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS) &&
			reinterpret_cast<ULONG_PTR>(static_cast<PCHAR>(Base) + Rva) >= reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
		{
			return nullptr;
		}

		*Size = Directories[DirectoryEntry].Size;
		if (MappedAsImage || Rva < NtHeaders->OptionalHeader.SizeOfHeaders)
		{
			return static_cast<PVOID>(static_cast<PCHAR>(Base) + Rva);
		}

		return static_cast<PVOID>(static_cast<PCHAR>(Base) + rva_to_offset(NtHeaders, Rva));
	}

	ULONGLONG get_exported_function(const ULONGLONG mod, const char* name){
		const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGLONG>(dos_header) + dos_header->e_lfanew);

		const auto data_directory = nt_headers->OptionalHeader.DataDirectory[0];
		const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mod + data_directory.VirtualAddress);

		const auto address_of_names = reinterpret_cast<ULONG*>(mod + export_directory->AddressOfNames);

		for (size_t i = 0; i < export_directory->NumberOfNames; i++)
		{
			const auto function_name = reinterpret_cast<const char*>(mod + address_of_names[i]);

			if (!_stricmp(function_name, name))
			{
				const auto name_ordinal = reinterpret_cast<unsigned short*>(mod + export_directory->AddressOfNameOrdinals)[i];

				const auto function_rva = mod + reinterpret_cast<ULONG*>(mod + export_directory->AddressOfFunctions)[name_ordinal];
				return function_rva;
			}
		}

		return 0;
	}

	NTSTATUS bypass_cfg_second(PEPROCESS process, int pid, uintptr_t section_base, size_t section_size) {
		const auto o_process = system_functions::swap_process((uintptr_t)process);//attach

		size_t size_written = 0;
		uint64_t ntdll_base_address = 0;
		auto result = get_module_base_address(pid, "ntdll.dll", &ntdll_base_address);
		if (result != STATUS_SUCCESS) {
			system_functions::swap_process(o_process);//detach
			return STATUS_UNSUCCESSFUL;
		}

		const auto rtl_initialize_nt_user_pfn = get_exported_function(ntdll_base_address, "RtlInitializeNtUserPfn");
		if (!rtl_initialize_nt_user_pfn){
			system_functions::swap_process(o_process);//detach
			return STATUS_UNSUCCESSFUL;
		}

		const auto mov_instruction = rtl_initialize_nt_user_pfn + 0x19;
		auto cfg_bitmap = resolve_relative_address((PVOID)mov_instruction, 3, 7);
		if (!cfg_bitmap){
			system_functions::swap_process(o_process);//detach
			return STATUS_UNSUCCESSFUL;
		}

		cfg_bitmap = *(LONG64*)cfg_bitmap;

		for (uintptr_t address_base = section_base; address_base < section_base + section_size; address_base += 0x8){
			auto toBit = [](LONG64 val) { return val % 64; };
			auto force_bitset = [&](LONG64* ptr, int bit) {
				auto val = *ptr;
				_bittestandset64(&val, bit);
				physical_memory::write_physical_process_memory(pid, (uintptr_t)ptr, (uintptr_t)&val, 8, &size_written);
				};

			//get bit & bit offset
			auto curBit = address_base >> 3;
			auto bitPos = (LONG64*)(cfg_bitmap + 8 * (address_base >> 9));

			if ((address_base & 0xF) == 0) {
				auto bit = toBit(curBit);
				printf("bit in cfg first %p\n", bit);
				if (!_bittest64(bitPos, bit))
					goto fixSBit;
			}
			else
			{
				//first
			fixMBit:
				curBit &= ~1ui64;
				auto bit = toBit(curBit);
				if (!_bittest64(bitPos, bit)) {
					force_bitset(bitPos, bit);
				}
			}

			//second
		fixSBit:
			curBit |= 1;
			auto bit = toBit(curBit);
			if (!_bittest64(bitPos, bit)) {
				force_bitset(bitPos, bit);
			}
		}

		system_functions::swap_process(o_process);//detach

		return STATUS_SUCCESS;
	}

	NTSTATUS bypass_cfg(PEPROCESS Process){
		PAGED_CODE();

		CONST system_environment::PPEB Peb = process::PsGetProcessPeb(Process);
		if (Peb == nullptr)
			return STATUS_NOT_FOUND;

		const auto o_process = system_functions::swap_process((uintptr_t)Process);

		CONST PIMAGE_NT_HEADERS NtHeaders = rtlp_image_ntheader_ex(Peb->ImageBaseAddress, 0);
		NTSTATUS Status = STATUS_SUCCESS;
		if (NtHeaders == nullptr || NtHeaders->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
		{
			Status = STATUS_NOT_FOUND;
			goto finished;
		}

		ULONG Size = 0;
		const PIMAGE_LOAD_CONFIG_DIRECTORY64 LoadConfigDirectory = static_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(
			rtlp_image_directory_entry_to_data_ex(Peb->ImageBaseAddress,
				TRUE,
				IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
				&Size));

		if (LoadConfigDirectory == nullptr ||
			LoadConfigDirectory->Size < FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFCheckFunctionPointer) ||
			LoadConfigDirectory->GuardCFCheckFunctionPointer == 0)
		{
			Status = STATUS_NOT_FOUND;
			goto finished;
		}

		PVOID LdrpValidateUserCallTarget, LdrpDispatchUserCallTarget = nullptr;
		__try
		{
			const PVOID* GuardCFCheckFunctionPointer = reinterpret_cast<PVOID*>(LoadConfigDirectory->GuardCFCheckFunctionPointer);
			LdrpValidateUserCallTarget = GuardCFCheckFunctionPointer != nullptr ? *GuardCFCheckFunctionPointer : nullptr;
			//printf("\tGuardCFCheckFunctionPointer: 0x%p -> 0x%p\n",
			//	GuardCFCheckFunctionPointer, LdrpValidateUserCallTarget);

			const PVOID* GuardCFDispatchFunctionPointer = reinterpret_cast<PVOID*>(LoadConfigDirectory->GuardCFDispatchFunctionPointer);
			LdrpDispatchUserCallTarget = GuardCFDispatchFunctionPointer != nullptr ? *GuardCFDispatchFunctionPointer : nullptr;
			//printf("\tGuardCFDispatchFunctionPointer: 0x%p -> 0x%p\n",
			//	GuardCFDispatchFunctionPointer, LdrpDispatchUserCallTarget);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = GetExceptionCode();
			goto finished;
		}


		if (LdrpValidateUserCallTarget == nullptr && LdrpDispatchUserCallTarget == nullptr)
		{
			Status = STATUS_SUCCESS;
			goto finished;
		}

		UCHAR Validate[] =
		{
			0x48, 0x8B, 0xC1,       // mov rax, rcx
			0x48, 0xC1, 0xE8, 0x03, // shr rax, 3
			0xC3                     // ret
		};

		size_t size_written = 0;
		if (LdrpValidateUserCallTarget != nullptr) {
			//printf("LdrpValidateUserCallTarget %p\n", LdrpValidateUserCallTarget);
			if (!NT_SUCCESS(physical_memory::write_physical_process_memory((uint32_t)PsGetProcessId(Process), (uintptr_t)LdrpValidateUserCallTarget,
				(uintptr_t)Validate, sizeof(Validate), &size_written)))
			{
				//printf("cannot write for validate\n");
				goto finished;
			}
			//printf("size_written %p\n", size_written);
			//printf("size validate %p\n", sizeof(Validate));
		}

		UCHAR Dispatch[] = { 0x48, 0xFF, 0xE0 }; // jmp rax
		if (LdrpDispatchUserCallTarget != nullptr) {
			//printf("LdrpDispatchUserCallTarget %p\n", LdrpDispatchUserCallTarget);
			if (!NT_SUCCESS(physical_memory::write_physical_process_memory((uint32_t)PsGetProcessId(Process), (uintptr_t)LdrpDispatchUserCallTarget,
				(uintptr_t)Dispatch, sizeof(Dispatch), &size_written)))
			{
				//printf("cannot write for dispatch\n");
				goto finished;
			}
			//printf("size_written %p\n", size_written);
			//printf("size dispatch %p\n", sizeof(Dispatch));
		}

	finished:
		system_functions::swap_process(o_process);

		return Status;
	}
}