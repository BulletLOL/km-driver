#pragma once
#include "include.h"

namespace physical {
	struct PHYSICAL_PAGE_INFO
	{
		PVOID BaseAddress;
		SIZE_T Size;
		PVOID PteAddress;
	};

	struct PAGE_TABLE_INFO
	{
		ULONG64 Pxe;
		ULONG64 Ppe;
		ULONG64 Pde;
		ULONG64 Pte;
		ULONG PageType;
	};

	ULONG get_process_cr3(PEPROCESS process);
	DWORD get_user_directory_table_base_offset();
	NTSTATUS allocate_physical_page(PHYSICAL_PAGE_INFO* physical_page_info, PEPROCESS p_process, SIZE_T size);
	void free_physical_page(PHYSICAL_PAGE_INFO* page_info);
	NTSTATUS read_physical_page(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 phys_page_base, PVOID buffer, SIZE_T size);
	NTSTATUS write_physical_page(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 phys_page_base, PVOID buffer, SIZE_T size);
	NTSTATUS get_page_table_info(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 cr3, ULONG64 page_address, PAGE_TABLE_INFO* page_table_info);
	NTSTATUS get_phys_page_address(PHYSICAL_PAGE_INFO* transfer_page_info, PEPROCESS p_process, ULONG64 target_cr3, PVOID page_va, PULONG64 p_physical_address);
	NTSTATUS get_phys_page_size(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 page_address, PULONG64 p_page_size, ULONG64 target_cr3);
	NTSTATUS read_physical_memory(int pid, PVOID address, PVOID buffer, PULONG p_size_read);
	NTSTATUS write_physical_memory(int pid, PVOID address, PVOID buffer, PULONG p_size_read);
}

namespace physical_memory {
	NTSTATUS write_physical_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_written);
	NTSTATUS read_physical_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_read);
}