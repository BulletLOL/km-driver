#pragma once
#include <stdint.h>

#ifdef DRIVER_MODE
#include "nt.h"
#else
// User mode specific code
#endif

namespace fptr_data
{
	constexpr uint64_t static_identifier = 0xBADC0DE;

	enum class kernel_opr : uint32_t
	{
		read = 1,
		write,
		get_process_module,
		get_user_module,
		get_process_base,
		unhook_driver,
		alloc,
		free,
		protect,
		query,
		allocate_kernel,
		free_kernel,
		cfg_bypass,
		swap_virtual,
		find_signature,
		expose_kernel_target,
		expose_kernel_user
	};

	enum class kernel_err : uint16_t
	{
		invalid_process = 2,
		check_fail,
		no_operation,
		invalid_data,
		no_error = 0,
		unset_err = 1
	};

	struct kernel_com
	{
		bool success;
		kernel_err error;
		uint32_t target_pid;
		uint32_t user_pid;
		uintptr_t address;
		uintptr_t buffer;
		uintptr_t p_out;
		uintptr_t mdl;
		bool physical;
		MMVAD_FLAGS vad_flags;

		//swap
		uintptr_t src;
		uintptr_t dst;
		PVOID old;

		//protect
		PDWORD in_out_protect;

		//alloc
		uint32_t protect;

		//pattern
		uintptr_t base;
		char signature[260];
		char mask[260];
		uintptr_t out_address;

		//change bits
		bool write;
		bool execute; 

		//npt hook
		void* hook_address;
		void* proxy;
		void** detour;

		//attach & detach
		bool attach;
		uintptr_t section_base;
		size_t section_size;

		union
		{
			size_t size;
			const char* name;
		};

		size_t transfer;
	};
}