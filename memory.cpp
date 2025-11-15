#include "memory.h"
#include "framework.h"
#include "process_functions.h"
#include "system_functions.h"

NTSTATUS memory::write_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_written)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS target_proc = process::get_by_id(pid, &status);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(target_proc);
		return status;
	}

	size_t processed;
	status = memory::MmCopyVirtualMemory(PsGetCurrentProcess(), (void*)buffer, target_proc, (void*)addr, size, KernelMode, &processed);

	ObDereferenceObject(target_proc);

	if (!NT_SUCCESS(status)) return status;
	if (bytes_written) *bytes_written = processed;

	if (processed != size)
		return STATUS_FAIL_CHECK;
	return STATUS_SUCCESS;
}

NTSTATUS memory::read_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_read)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS target_proc = process::get_by_id(pid, &status);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(target_proc);
		return status;
	}

	size_t processed;
	status = memory::MmCopyVirtualMemory(target_proc, (void*)addr, PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &processed);

	ObDereferenceObject(target_proc);

	if (!NT_SUCCESS(status)) return status;
	if (bytes_read) *bytes_read = processed;

	if (processed != size)
		return STATUS_FAIL_CHECK;
	return STATUS_SUCCESS;
}
