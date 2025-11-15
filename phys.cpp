#include "phys.h"
#include "system_functions.h"

namespace physical {
	ULONG64 g_pte_base = 0;
	ULONG64 g_pde_base = 0;
	ULONG64 g_ppe_base = 0;
	ULONG64 g_pxe_base = 0;
	BOOLEAN g_is_init_pte_base_for_system = false;
	PPHYSICAL_MEMORY_RANGE g_physical_memory_ranges = 0;

	DWORD get_user_directory_table_base_offset()
	{
		RTL_OSVERSIONINFOW ver = { 0 };
		RtlGetVersion(&ver);

		switch (ver.dwBuildNumber)
		{
		case WINDOWS_1803:
			return 0x0278;
			break;
		case WINDOWS_1809:
			return 0x0278;
			break;
		case WINDOWS_1903:
			return 0x0280;
			break;
		case WINDOWS_1909:
			return 0x0280;
			break;
		case WINDOWS_2004:
			return 0x0388;
			break;
		case WINDOWS_20H2:
			return 0x0388;
			break;
		case WINDOWS_21H1:
			return 0x0388;
			break;
		default:
			return 0x0388;
		}
	}

	ULONG get_process_cr3(PEPROCESS pProcess)
	{
		PUCHAR process = (PUCHAR)pProcess;
		ULONG_PTR process_dir_base = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
		if (process_dir_base == 0)
		{
			DWORD user_dir_offset = get_user_directory_table_base_offset();
			ULONG_PTR process_user_dir_base = *(PULONG_PTR)(process + user_dir_offset);
			return process_user_dir_base;
		}
		return process_dir_base;
	}

	NTSTATUS raise_irql(KIRQL new_irql, KIRQL* old_irql)
	{
		KIRQL current_irql;

		current_irql = KeGetCurrentIrql();
		__writecr8(new_irql);
		if (old_irql)
			*old_irql = current_irql;

		return STATUS_SUCCESS;
	}

	KIRQL raise_irql_to_dpc_lv()
	{
		KIRQL old_irql;
		raise_irql(2u, &old_irql);
		return old_irql;
	}

	void lower_irql(KIRQL irql)
	{
		__writecr8(irql);
	}

	BOOLEAN is_phys_page_in_range(ULONG64 phys_page_base, ULONG64 size)
	{
		if (!g_physical_memory_ranges)
		{
			if (KeGetCurrentIrql())
				return FALSE;
			g_physical_memory_ranges = MmGetPhysicalMemoryRanges();
		}

		if (!g_physical_memory_ranges)
			return FALSE;

		ULONG64 phys_page_end = phys_page_base + size - 1;

		printf("g_physical_memory_ranges %p\n", g_physical_memory_ranges);

		ULONG64 low, high;
		for (int i = 0;; ++i)
		{
			PHYSICAL_MEMORY_RANGE physical_memory_range = g_physical_memory_ranges[i];
			if (!physical_memory_range.BaseAddress.QuadPart || !physical_memory_range.NumberOfBytes.QuadPart)
				break;

			low = (ULONG64)physical_memory_range.BaseAddress.QuadPart;
			high = low + (ULONG64)physical_memory_range.NumberOfBytes.QuadPart;

			if (phys_page_base >= low &&
				phys_page_base <= high &&
				phys_page_end >= low &&
				phys_page_end <= high)
			{
				return TRUE;
			}
		}

		return FALSE;
	}

	BOOLEAN is_va_physical_address_valid(PVOID virtual_address)
	{
		return MmGetPhysicalAddress(virtual_address).QuadPart > 0x1000;
	}

	PVOID get_pml4_base(PHYSICAL_ADDRESS directory_table_base)
	{
		PVOID virtual_for_physical = MmGetVirtualForPhysical(directory_table_base);
		if ((ULONG64)virtual_for_physical <= 0x1000)
			return NULL;
		else
			return virtual_for_physical;
	}

	NTSTATUS initialize_pte_base(PEPROCESS p_process)
	{
		if (g_is_init_pte_base_for_system)
			return STATUS_SUCCESS;

		ULONG64 cr3 = __readcr3();
		PHYSICAL_ADDRESS directory_table_base;
		directory_table_base.QuadPart = ((cr3 >> 12) & 0xFFFFFFFFFFi64) << 12;

		PULONG64 pml4_table = (PULONG64)get_pml4_base(directory_table_base);
		if (!pml4_table)
			return STATUS_UNSUCCESSFUL;

		for (ULONG64 index = 0; index < 0x200; ++index)
		{
			ULONG64 item = pml4_table[index];
			if (((item >> 12) & 0xFFFFFFFFFFi64) == ((cr3 >> 12) & 0xFFFFFFFFFFi64))
			{
				g_pte_base = (index << 39) - 0x1000000000000;
				g_pde_base = (index << 30) + (index << 39) - 0x1000000000000;
				g_ppe_base = (index << 21) + g_pde_base;
				g_pxe_base = (index << 12) + (index << 21) + g_pde_base;
				g_is_init_pte_base_for_system = TRUE;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_UNSUCCESSFUL;
	}

	ULONG64 get_pte_address(PVOID virtual_address)
	{
		return g_pte_base + 8 * (((ULONG64)virtual_address & 0xFFFFFFFFFFFFi64) >> 12);
	}

	NTSTATUS allocate_physical_page(PHYSICAL_PAGE_INFO* physical_page_info, PEPROCESS p_process, SIZE_T size)
	{
		if (!physical_page_info || size != 0x1000)
			return STATUS_INVALID_PARAMETER;

		NTSTATUS status = initialize_pte_base(p_process);
		if (!NT_SUCCESS(status))
			return status;

		PVOID base_address = MmAllocateMappingAddress(0x1000, 'axe');
		if (!base_address)
			return STATUS_NO_MEMORY;

		PVOID pte_address = (PVOID)get_pte_address(base_address);
		if (!pte_address || !is_va_physical_address_valid(pte_address))
		{
			MmFreeMappingAddress(base_address, 'axe');
			return STATUS_UNSUCCESSFUL;
		}

		physical_page_info->BaseAddress = base_address;
		physical_page_info->Size = 0x1000;
		physical_page_info->PteAddress = pte_address;

		return STATUS_SUCCESS;
	}

	void free_physical_page(PHYSICAL_PAGE_INFO* page_info)
	{
		if (page_info && page_info->BaseAddress)
		{
			MmFreeMappingAddress(page_info->BaseAddress, 'axe');
			memset(page_info, 0i64, sizeof(PHYSICAL_PAGE_INFO));
		}
	}

	NTSTATUS read_physical_page(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 phys_page_base, PVOID buffer, SIZE_T size)
	{
		BOOLEAN is_dpc_level = FALSE;
		KIRQL old_irql = 0;

		if (!phys_page_base || !buffer || size == 0 || !transfer_page_info || !transfer_page_info->BaseAddress || !transfer_page_info->PteAddress)
			return STATUS_INVALID_PARAMETER;

		if (size > transfer_page_info->Size)
			return STATUS_INVALID_PARAMETER;

		if (phys_page_base >> 12 != (phys_page_base + size - 1) >> 12)
			return STATUS_INVALID_PARAMETER;

		if (!is_phys_page_in_range(phys_page_base, size)) {

			printf("phys page not in rage\n");

			return STATUS_UNSUCCESSFUL;
		}

		if (KeGetCurrentIrql() < 2u)
		{
			old_irql = raise_irql_to_dpc_lv();
			is_dpc_level = TRUE;
		}

		if (!is_va_physical_address_valid(transfer_page_info->PteAddress))
		{
			if (is_dpc_level)
				lower_irql(old_irql);

			printf("va is not physical adddress\n");

			return STATUS_UNSUCCESSFUL;
		}

		PVOID pte_address = transfer_page_info->PteAddress;
		ULONG64 old_pte = *(ULONG64*)pte_address;
		*(ULONG64*)pte_address = (((phys_page_base >> 12) & 0xFFFFFFFFFFi64) << 12) |
			*(ULONG64*)pte_address & 0xFFF0000000000EF8 | 0x103;
		__invlpg(transfer_page_info->BaseAddress);
		RtlCopyMemory(buffer, (char*)transfer_page_info->BaseAddress + (phys_page_base & 0xFFF), size);
		*(ULONG64*)pte_address = old_pte;

		if (is_dpc_level)
			lower_irql(old_irql);

		return STATUS_SUCCESS;
	}

	NTSTATUS write_physical_page(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 phys_page_base, PVOID buffer, SIZE_T size)
	{
		BOOLEAN is_dpc_level = FALSE;
		KIRQL old_irql = 0;

		if (!phys_page_base || !buffer || size == 0 || !transfer_page_info || !transfer_page_info->BaseAddress || !transfer_page_info->PteAddress)
			return STATUS_INVALID_PARAMETER;

		if (size > transfer_page_info->Size)
			return STATUS_INVALID_PARAMETER;

		if (phys_page_base >> 12 != (phys_page_base + size - 1) >> 12)
			return STATUS_INVALID_PARAMETER;

		if (!is_phys_page_in_range(phys_page_base, size))
			return STATUS_UNSUCCESSFUL;

		if (KeGetCurrentIrql() < 2u){
			old_irql = raise_irql_to_dpc_lv();
			is_dpc_level = TRUE;
		}

		if (!is_va_physical_address_valid(transfer_page_info->PteAddress)){
			if (is_dpc_level)
				lower_irql(old_irql);

			printf("va is not physical adddress\n");

			return STATUS_UNSUCCESSFUL;
		}

		PVOID pte_address = transfer_page_info->PteAddress;
		ULONG64 old_pte = *(ULONG64*)pte_address;
		*(ULONG64*)pte_address = (((phys_page_base >> 12) & 0xFFFFFFFFFFi64) << 12) |
			*(ULONG64*)pte_address & 0xFFF0000000000EF8 | 0x103;
		__invlpg(transfer_page_info->BaseAddress);
		RtlCopyMemory((char*)transfer_page_info->BaseAddress + (phys_page_base & 0xFFF), buffer, size);
		*(ULONG64*)pte_address = old_pte;

		if (is_dpc_level)
			lower_irql(old_irql);

		return STATUS_SUCCESS;
	}

	NTSTATUS get_page_table_info(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 cr3, ULONG64 page_address, PAGE_TABLE_INFO* page_table_info)
	{
		if (!page_table_info)
			return STATUS_INVALID_PARAMETER;

		memset(page_table_info, 0i64, sizeof(PAGE_TABLE_INFO));

		NTSTATUS status = read_physical_page(transfer_page_info,	
			(((cr3 >> 12) & 0xFFFFFFFFFFi64) << 12) + 8 * ((page_address >> 39) & 0x1FF),
			page_table_info, 8);

		printf("status READ %p\n", status);

		if (NT_SUCCESS(status) && (page_table_info->Pxe & 1) == 0) {
			printf("pxe failed\n");
			return STATUS_PAGE_FAULT_PAGING_FILE;
		}

		if (NT_SUCCESS(status) && ((page_table_info->Pxe >> 12) & 0xFFFFFFFFFFi64) == ((cr3 >> 12) & 0xFFFFFFFFFFi64))
			return STATUS_SUCCESS;

		status = read_physical_page(transfer_page_info,
			(((page_table_info->Pxe >> 12) & 0xFFFFFFFFFFi64) << 12) + 8 * ((page_address >> 30) & 0x1FF),
			&page_table_info->Ppe, 8);

		if (NT_SUCCESS(status) && (page_table_info->Ppe & 1) == 0) {
			printf("ppe failed\n");
			return STATUS_PAGE_FAULT_PAGING_FILE;
		}

		if (NT_SUCCESS(status) && ((page_table_info->Ppe >> 7) & 1) != 0){
			page_table_info->PageType = 7; // 1GB large page
			return STATUS_SUCCESS;
		}

		status = read_physical_page(transfer_page_info,
			(((page_table_info->Ppe >> 12) & 0xFFFFFFFFFFi64) << 12) + 8 * ((page_address >> 21) & 0x1FF),
			&page_table_info->Pde, 8);

		if (NT_SUCCESS(status) && (page_table_info->Pde & 1) == 0) {
			printf("pde failed\n");
			return STATUS_PAGE_FAULT_PAGING_FILE;
		}

		if (NT_SUCCESS(status) && ((page_table_info->Pde >> 7) & 1) != 0){
			page_table_info->PageType = 6; // 2MB large page
			return STATUS_SUCCESS;
		}

		status = read_physical_page(transfer_page_info,
			(((page_table_info->Pde >> 12) & 0xFFFFFFFFFFi64) << 12) + 8 * ((page_address >> 12) & 0x1FF),
			&page_table_info->Pte, 8);

		if (NT_SUCCESS(status) && (page_table_info->Pte & 1) != 0){
			page_table_info->PageType = 5; // 4KB Page
			return STATUS_SUCCESS;
		}

		return STATUS_PAGE_FAULT_PAGING_FILE;
	}

	NTSTATUS get_phys_page_address(PHYSICAL_PAGE_INFO* transfer_page_info, PEPROCESS process, ULONG64 target_cr3, PVOID page_va, PULONG64 p_physical_address)
	{
		ULONG64 current_cr3;
		ULONG64 page_phys;
		SIZE_T page_size;
		PAGE_TABLE_INFO page_table_info;
		ULONG64 cr3;

		cr3 = target_cr3;
		if (!p_physical_address)
			return STATUS_INVALID_PARAMETER;

		*p_physical_address = 0;

		memset(&page_table_info, 0, 36);

		if (!target_cr3){
			current_cr3 = get_process_cr3(process);
			cr3 = current_cr3;
		}

		NTSTATUS status = get_page_table_info(transfer_page_info, cr3, (ULONG64)page_va, &page_table_info);
		if (!NT_SUCCESS(status))
			return status;

		printf("page table info status %p\n", status);
		printf("page table info %p\n", page_table_info);
		printf("page_table_info.PageType %p\n", page_table_info.PageType);

		page_phys = 0;
		page_size = 0;

		switch (page_table_info.PageType) {
		case 5u:
			page_phys = ((page_table_info.Pte >> 12) & 0xFFFFFFFFFFi64) << 12;
			page_size = 0x1000;
			break;
		case 6u:
			page_phys = ((page_table_info.Pde >> 21) & 0x7FFFFFFF) << 21;
			page_size = 0x200000;
			break;
		case 7u:
			page_phys = ((page_table_info.Ppe >> 30) & 0x3FFFFF) << 30;
			page_size = 0x40000000;
			break;
		}

		printf("page phys %p\n", page_phys);

		if (page_phys){
			*p_physical_address = (ULONG64)page_va + page_phys - (~(page_size - 1) & (ULONG64)page_va);
			return STATUS_SUCCESS;
		}
		else
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	NTSTATUS get_phys_page_size(PHYSICAL_PAGE_INFO* transfer_page_info, ULONG64 page_address, PULONG64 p_page_size, ULONG64 target_cr3)
	{
		PAGE_TABLE_INFO page_table_info;
		NTSTATUS status;

		if (!p_page_size)
			return STATUS_INVALID_PARAMETER;

		*p_page_size = 0;

		memset(&page_table_info, 0, 0x24);

		status = get_page_table_info(transfer_page_info, target_cr3, page_address, &page_table_info);
		if (!NT_SUCCESS(status))
			return status;

		switch (page_table_info.PageType) {
		case 5u:
			*p_page_size = 0x1000;
			break;
		case 6u:
			*p_page_size = 0x200000;
			break;
		case 7u:
			*p_page_size = 0x40000000;
			break;
		default:
			return STATUS_INVALID_PARAMETER;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS read_physical_memory(int pid, PVOID address, PVOID buffer, PULONG p_size_read)
	{
		BOOLEAN is_done_read;
		NTSTATUS status;
		ULONG size_left;
		ULONG offset_in_page;
		ULONG size_read;
		ULONG size_left_in_page;
		ULONG size;
		ULONG64 physical_address;
		ULONG64 page_size;
		ULONG64 page_address;
		ULONG64 directory_table_base = 0;
		PHYSICAL_PAGE_INFO transfer_page_info;

		PEPROCESS p_process = NULL;
		if (pid == 0)
			return STATUS_INVALID_PARAMETER;

		NTSTATUS nt_ret = PsLookupProcessByProcessId((HANDLE)pid, &p_process);
		if (nt_ret != STATUS_SUCCESS)
			return nt_ret;

		size_read = 0;
		memset(&transfer_page_info, 0, sizeof(transfer_page_info));

		if (!directory_table_base){
			directory_table_base = get_process_cr3(p_process);
			ObDereferenceObject(p_process);
		}

		if (address && buffer && p_size_read && *p_size_read){
			if (KeGetCurrentIrql() <= 2u){
				allocate_physical_page(&transfer_page_info, p_process, 0x1000);
				page_size = 0;
				status = get_phys_page_size(&transfer_page_info, (ULONG64)address, &page_size, directory_table_base);

				printf("get_phys_page_size status %p\n", status);

				if (!NT_SUCCESS(status) && page_size > 0x1000)
					return status;

				offset_in_page = (ULONG64)address & 0xFFF;
				page_address = (ULONG64)address & 0xFFFFFFFFFFFFF000u;
				size = *p_size_read;
				size_left = *p_size_read;

				do{
					is_done_read = FALSE;

					if (size_left >= PAGE_SIZE - offset_in_page)
						size_left_in_page = PAGE_SIZE - offset_in_page;
					else
						size_left_in_page = size_left;

					physical_address = 0;
					status = get_phys_page_address(&transfer_page_info, p_process, directory_table_base, (PVOID)page_address, &physical_address);

					printf("get_phys_page_address status %p\n", status);

					if (NT_SUCCESS(status) && physical_address){
						status = read_physical_page(
							&transfer_page_info,
							physical_address + offset_in_page,
							buffer,
							size_left_in_page);

						printf("read physical page status %p\n", status);
						printf("size_left_in_page %p\n", size_left_in_page);

						if (NT_SUCCESS(status))
						{
							size_read += size_left_in_page;
							is_done_read = TRUE;
						}
					}

					if (!is_done_read)
						memset(buffer, 0, size_left_in_page);

					buffer = (PUCHAR)buffer + size_left_in_page;
					page_address += offset_in_page + (ULONG64)size_left_in_page;
					offset_in_page = 0;
					size_left -= size_left_in_page;
				} while (size_left && size_left < size);

				if (size_read){
					*p_size_read = size_read;
					return STATUS_SUCCESS;
				}
				else{
					return STATUS_UNSUCCESSFUL;
				}
			}
			else{
				return STATUS_UNSUCCESSFUL;
			}
		}
		else{
			return STATUS_INVALID_PARAMETER;
		}
	}

	NTSTATUS write_physical_memory(int pid, PVOID address, PVOID buffer, PULONG p_size_read)
	{
		BOOLEAN is_done_read;
		NTSTATUS status;
		ULONG size_left;
		ULONG offset_in_page;
		ULONG size_read;
		ULONG size_left_in_page;
		ULONG size;
		ULONG64 physical_address;
		ULONG64 page_size;
		ULONG64 page_address;
		ULONG64 directory_table_base = 0;
		PHYSICAL_PAGE_INFO transfer_page_info;

		PEPROCESS p_process = NULL;
		if (pid == 0)
			return STATUS_INVALID_PARAMETER;

		NTSTATUS nt_ret = PsLookupProcessByProcessId((HANDLE)pid, &p_process);
		if (nt_ret != STATUS_SUCCESS)
			return nt_ret;

		size_read = 0;
		memset(&transfer_page_info, 0, sizeof(transfer_page_info));

		if (!directory_table_base)
		{
			directory_table_base = get_process_cr3(p_process);
			ObDereferenceObject(p_process);
		}

		if (address && buffer && p_size_read && *p_size_read)
		{
			if (KeGetCurrentIrql() <= 2u)
			{
				allocate_physical_page(&transfer_page_info, p_process, 0x1000);
				page_size = 0;
				status = get_phys_page_size(&transfer_page_info, (ULONG64)address, &page_size, directory_table_base);

				if (!NT_SUCCESS(status) && page_size > 0x1000)
					return status;

				offset_in_page = (ULONG64)address & 0xFFF;
				page_address = (ULONG64)address & 0xFFFFFFFFFFFFF000u;
				size = *p_size_read;
				size_left = *p_size_read;

				do
				{
					is_done_read = FALSE;

					if (size_left >= PAGE_SIZE - offset_in_page)
						size_left_in_page = PAGE_SIZE - offset_in_page;
					else
						size_left_in_page = size_left;

					physical_address = 0;
					status = get_phys_page_address(&transfer_page_info, p_process, directory_table_base, (PVOID)page_address, &physical_address);

					printf("get phys page address status %p\n", status);

					if (NT_SUCCESS(status) && physical_address)
					{
						status = write_physical_page(
							&transfer_page_info,
							physical_address + offset_in_page,
							buffer,
							size_left_in_page);

						printf("write physical page status %p\n", status);
						printf("size_left_in_page %p\n", size_left_in_page);

						if (NT_SUCCESS(status))
						{
							size_read += size_left_in_page;
							is_done_read = TRUE;
						}
					}

					if (!is_done_read)
						memset(buffer, 0, size_left_in_page);

					buffer = (PUCHAR)buffer + size_left_in_page;
					page_address += offset_in_page + (ULONG64)size_left_in_page;
					offset_in_page = 0;
					size_left -= size_left_in_page;
				} while (size_left && size_left < size);

				if (size_read)
				{
					*p_size_read = size_read;
					return STATUS_SUCCESS;
				}
				else
				{
					printf("size read is null\n");
					return STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				printf("current irql\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
		else
		{
			return STATUS_INVALID_PARAMETER;
		}
	}
}

namespace physical_memory
{
	NTSTATUS write_physical_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_written)
	{
		NTSTATUS status = STATUS_SUCCESS;
		status = physical::write_physical_memory(pid, (void*)addr, (void*)buffer, (PULONG)&size);
		
		printf("physical memory write status %p\n", status);

		return status;
	}

	NTSTATUS read_physical_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_read)
	{
		NTSTATUS status = STATUS_SUCCESS;
		status = physical::read_physical_memory(pid, (void*)addr, (void*)buffer, (PULONG)&size);
		return status;
	}
}
