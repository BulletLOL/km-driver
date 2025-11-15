#include "hook.h"
#include "process_functions.h"
#include "system_functions.h"
#include <libcryvisor.hpp>

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObj);
	UNREFERENCED_PARAMETER(RegistryPath);

	uintptr_t win32kbase = system_functions::get_system_module(XORS(L"win32kbase.sys"));
	if (!win32kbase)
	{
		printf("win32kbase.sys not found in system modules, unable to load driver.\n");
		return STATUS_ABANDONED;
	}

	uintptr_t target_func = system_functions::get_routine_address(win32kbase, XORS("NtGdiPolyPolyDraw"));
	if (!target_func)
	{
		printf("unable to find target function in exports of win32kbase.sys.\n");
		return STATUS_UNSUCCESSFUL;
	}

	target_func += 0x366; // Offset

	//printf("target_func %p.\n", target_func);

	//48 8B 05 FB B9 18 00                          mov     rax, cs:qword_1C0251838

	core_hook::fptr_addr = (uintptr_t)target_func + *(uint32_t*)((uint8_t*)target_func + 3) + 7;
	core_hook::o_fptr = (core_hook::pfunc_hk_t)InterlockedExchangePointer((PVOID*)core_hook::fptr_addr, &core_hook::hooked_fptr);

	system_environment::PPEB pPeb = process::PsGetProcessPeb (IoGetCurrentProcess());

	printf ("pPeb %p\n", pPeb);

	//printf("driver successfully loaded.\n");

	return STATUS_SUCCESS;
}
