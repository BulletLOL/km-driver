#include "hook.h"
#include "libcryvisor.hpp"

__int64 __fastcall core_hook::hooked_fptr(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
	if (!a1 || ExGetPreviousMode() != UserMode)
	{
		printf("!a1 || ExGetPreviousMode() != UserMode fail. arguments: %p, %p, %p, %p\n", a1, a2, a3, a4);
		return 0;
	}

	if (a3 != fptr_data::static_identifier)
	{
		//printf("arguments: % p, %p, %p, %p\n", a1, a2, a3, a4);
		if (o_fptr)
		{
			//printf("original .data ptr call.\n");
			return o_fptr(a1, a2, a3, a4);
		}
		//printf("Call failed static identifier check.\n");
		return 0;
	}

	// We in our territory now
	/*fptr_data::kernel_com com{};
	size_t read = 0;
	if (!NT_SUCCESS(memory::read_virtual(memory::get_kernel_dirbase(), a1, (uint8_t *)&com, sizeof(com), &read)) || read != sizeof(com))
	{
		printf("invalid memory sent to kernel for operation.\n");
		return 0;
	}*/

	fptr_data::kernel_com* com = (fptr_data::kernel_com*)a1;
	com->error = fptr_data::kernel_err::no_error;

	switch (static_cast<fptr_data::kernel_opr>(a4))
	{
	case fptr_data::kernel_opr::unhook_driver:
	{
		InterlockedExchangePointer((volatile PVOID*)core_hook::fptr_addr, core_hook::o_fptr);
		//printf("unloaded driver.\n");
		break;
	}
	case fptr_data::kernel_opr::get_process_base:
	{
		NTSTATUS status = STATUS_SUCCESS;

		PEPROCESS proc = process::get_by_id(com->target_pid, &status);
		if (!NT_SUCCESS(status))
		{
			com->error = fptr_data::kernel_err::invalid_process;
			com->success = false;

			//printf("get_process_base failed: invalid process.\n");
			return 1;
		}

		com->buffer = (uintptr_t)process::PsGetProcessSectionBaseAddress(proc);
		ObDereferenceObject(proc);
		break;
	}
	case fptr_data::kernel_opr::get_process_module:
	{
		// Inputs
		if (!com->target_pid)
		{
			com->error = fptr_data::kernel_err::invalid_data;
			com->success = false;
			//printf("get_process_module failed: no valid process id given.\n");
			break;
		}

		uintptr_t buffer = 0;
		com->buffer = 0;
		if (NT_SUCCESS(system_functions::get_module_base_address(com->target_pid, com->name, &buffer)))
			com->buffer = buffer;
		break;
	}
	case fptr_data::kernel_opr::get_user_module:
	{
		uintptr_t buffer = 0;
		com->buffer = 0;
		if (NT_SUCCESS(system_functions::get_module_base_address((ULONG)PsGetCurrentProcessId(), com->name, &buffer)))
			com->buffer = buffer;
		break;
	}
	case fptr_data::kernel_opr::write:
	{		
		if (com->physical) {
			if (!NT_SUCCESS(physical_memory::write_physical_process_memory(com->target_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				//printf("physical write failed: invalid data.\n");
				return FALSE;
			}
		}
		else{
			if (!NT_SUCCESS(memory::write_process_memory(com->target_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				//printf("write failed: invalid data\n");
				return FALSE;
			}
		}
		break;
	}
	case fptr_data::kernel_opr::read:
	{
		if (com->physical) {
			if (!NT_SUCCESS(physical_memory::read_physical_process_memory(com->target_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				//printf("physical read failed: invalid data.\n");
				return FALSE;
			}
		}
		else{
			if (!NT_SUCCESS(memory::read_process_memory(com->target_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				//printf("read failed: invalid data.\n");
				return FALSE;
			}
		}
		break;
	}

	case fptr_data::kernel_opr::protect:
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			DWORD protect = 0;
			if (system_functions::safe_copy(&protect, com->in_out_protect, sizeof(protect))) {
				SIZE_T size = com->size;
				uintptr_t addr = com->address;

				const auto o_process = system_functions::swap_process((uintptr_t)target_proc);
				status = ZwProtectVirtualMemory(NtCurrentProcess(), (PVOID*)&addr, &size, protect, &protect);
				if (!NT_SUCCESS(status)){
					//printf("protect throw error %p\n", status);

					system_functions::swap_process(o_process);
					ObDereferenceObject(target_proc);
					com->success = false;
					com->error = fptr_data::kernel_err::check_fail;
					return 1;
				}
				system_functions::swap_process(o_process);

				system_functions::safe_copy(com->in_out_protect, &protect, sizeof(protect));
			}
			else {
				//printf("access violation\n");

				status = STATUS_ACCESS_VIOLATION;
			}

			ObDereferenceObject(target_proc);
		}
		break;
	}
	case fptr_data::kernel_opr::alloc:
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			uintptr_t addr, size, protect;
			addr = com->address;
			size = com->size;
			protect = com->protect;

			const auto o_process = system_functions::swap_process((uintptr_t)target_proc);
			status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&addr, 0, &size, MEM_COMMIT | MEM_RESERVE, protect);
			if (!NT_SUCCESS(status)){
				system_functions::swap_process(o_process);
				ObDereferenceObject(target_proc);
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}
			system_functions::swap_process(o_process);

			com->address = addr;
			com->size = size;

			ObDereferenceObject(target_proc);
		}
		break;
	}
	case fptr_data::kernel_opr::free:
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			uintptr_t addr, size;
			addr = com->address;
			size = 0;

			const auto o_process = system_functions::swap_process((uintptr_t)target_proc);
			status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&addr, &size, MEM_RELEASE);
			if (!NT_SUCCESS(status))
			{
				//printf("free throw error %p\n", status);
				system_functions::swap_process(o_process);
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}
			system_functions::swap_process(o_process);
			ObDereferenceObject(target_proc);
		}
		break;
	}
	case fptr_data::kernel_opr::query:
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			void* p_out = (void*)com->p_out;
			void* addr = (void*)com->address;

			MEMORY_BASIC_INFORMATION Mbi;
			const auto o_process = system_functions::swap_process((uintptr_t)target_proc);
			ZwQueryVirtualMemory(NtCurrentProcess(), addr, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
			system_functions::swap_process(o_process);

			system_functions::safe_copy(p_out, &Mbi, sizeof(Mbi));

			ObDereferenceObject(target_proc);

			return STATUS_SUCCESS;
		}
		break;
	}
	case fptr_data::kernel_opr::allocate_kernel:
	{
		uintptr_t mdl = 0;
		const auto address = system_functions::allocate_kernel_memory(com->size, &mdl);
		if (!address) {
			return 0;
		}

		//printf("address %p\n", address);

		if (!mdl || !address) {
			return 0;
		}

		com->mdl = mdl;
		com->address = (uintptr_t)address;

		break;
	}
	case fptr_data::kernel_opr::free_kernel:
	{
		MDL_INFORMATION mdl = { (MDL*)com->mdl, com->address };
		system_functions::free_mdl_memory(mdl);
		break;
	}
	case fptr_data::kernel_opr::expose_kernel_target:
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			if (!system_functions::expose_kernel_memory(target_proc, (uintptr_t)com->address, com->size))
			{
				return 0;
			}
		}
		break;
	}
	case fptr_data::kernel_opr::expose_kernel_user:
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS user_proc = process::get_by_id((uint32_t)PsGetCurrentProcessId(), &status);
		if (NT_SUCCESS(status))
		{
			if (!system_functions::expose_kernel_memory(user_proc, (uintptr_t)com->address, com->size))
			{
				return 0;
			}
		}
		break;
	}
	case fptr_data::kernel_opr::cfg_bypass: {
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			status = system_functions::bypass_cfg_second(target_proc, com->target_pid, com->address, com->size);
			printf("bypass cfg status %p\n", status);
			if (status != STATUS_SUCCESS) {
				com->success = false;
				//printf("bypassing cfg failed %p.\n", status);
				return FALSE;
			}
		}
		break;
	}
	case fptr_data::kernel_opr::swap_virtual:
	{
		fptr_data::kernel_com buffer{};

		if (!system_functions::safe_copy(&buffer, com, sizeof(*com))) {
			//printf("could not copy from swap\n");
			return 0;
		}

		if (!buffer.src || !buffer.dst)
		{
			//printf("source %p & dst %p from swap is invalid\n", buffer.src, buffer.dst);
			return 0;
		}

		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			const auto o_process = system_functions::swap_process((uintptr_t)target_proc);
			uintptr_t old = 0;
			*(PVOID*)&old = InterlockedExchangePointer((PVOID*)buffer.src, (PVOID)buffer.dst);
			if (!old) {
				//printf("(%p) failed: couldn't swap pointer.\n", a4);
				system_functions::swap_process(o_process);
				return FALSE;
			}
			system_functions::swap_process(o_process);

			system_functions::safe_copy(com->old, (PVOID)&old, sizeof(old));

			ObDereferenceObject(target_proc);

			return STATUS_SUCCESS;
		}
		break;
	}
	case fptr_data::kernel_opr::find_signature:
	{
		fptr_data::kernel_com buffer{};

		if (!system_functions::safe_copy(&buffer, com, sizeof(*com))) {
			//printf("could not copy from swap\n");
			return 0;
		}

		if (!buffer.base || !buffer.signature)
		{
			//printf("source %p & dst %p from swap is invalid\n", buffer.src, buffer.dst);
			return 0;
		}

		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS target_proc = process::get_by_id(com->target_pid, &status);
		if (NT_SUCCESS(status))
		{
			const auto o_process = system_functions::swap_process((uintptr_t)target_proc);
			auto address = system_functions::find_pattern((uintptr_t)buffer.base, "\xB9\x1C\x00\x00\x00", buffer.mask);
			if (!address) {
				//printf("(%p) failed: couldn't find signature.\n", a4);
				system_functions::swap_process(o_process);
				return FALSE;
			}
			system_functions::swap_process(o_process);

			system_functions::safe_copy(com->old, (PVOID)&address, sizeof(address));

			ObDereferenceObject(target_proc);

			return STATUS_SUCCESS;
		}
		break;
	}

	default:
	{
		com->success = false;
		com->error = fptr_data::kernel_err::no_operation;
		//printf("(%p) failed: unknown operation.\n", a4);
		return 1;
	}
	}

	com->success = true;
	//printf("kernel operation completed successfully.\n");
	return 1;
}
