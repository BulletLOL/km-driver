#pragma once
#include "include.h"
#include "framework.h"

namespace process
{
	PEPROCESS get_by_id(uint32_t pid, NTSTATUS* pstatus = nullptr);
	NTSTATUS find_process(const char* process_name, PEPROCESS* process);
}