#include "process_functions.h"
#include "system_functions.h"

PEPROCESS process::get_by_id(uint32_t pid, NTSTATUS* pstatus)
{
	PEPROCESS hProc;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &hProc);
	if (!NT_SUCCESS(status))
	{
		if (pstatus)
			*pstatus = status;
		return NULL;
	}
	return hProc;
}

NTSTATUS process::find_process(const char* process_name, PEPROCESS* process) {
    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;
    char image_name[15];
    do {
        RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));
        if (strstr(image_name, process_name)) {
            ULONG active_threads;
            RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)curr_entry + 0x5F0), sizeof(active_threads));
            if (active_threads) {
                *process = curr_entry;
                return STATUS_SUCCESS;
            }
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);
    } while (curr_entry != sys_process);
    return STATUS_NOT_FOUND;
}