#pragma once
#include "include.h"

namespace memory
{
	NTSTATUS write_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_written);
	NTSTATUS read_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_read);
}
