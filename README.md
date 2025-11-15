Kernel Driver Communication Framework

A Windows kernel driver that creates a hidden communication channel between userland applications and the kernel by hooking into the Windows graphics subsystem.

📌 What Is This?

This project is a kernel-mode driver that allows user-mode programs to perform privileged operations without using standard Windows driver communication (e.g., CreateFile, DeviceIoControl).

Instead of exposing a visible device, it hooks an internal function in win32kbase.sys, giving usermode a stealthy entry point into kernel space.

Think of it as a hidden backdoor-style communication path that does not look like a typical driver.

✨ Features
Memory Operations

Read/write memory of any process

Direct physical memory access (bypasses normal protections)

Allocate/free memory in remote processes

Modify memory protections (RWX, etc.)

Advanced Capabilities

Bypass Control Flow Guard (CFG)

Allocate executable kernel memory

Expose kernel memory to user-mode

Signature scanning (AOB / pattern scans)

Retrieve module base addresses

Atomic pointer swaps in target processes

Safety Features

Validates requests with a static identifier

Ensures calls originate from user mode

Proper handling of process context switching

Validates physical memory ranges before mapping

🛠️ How It Works

The driver avoids detection using a clever hooking technique:

Locates NtGdiPolyPolyDraw inside win32kbase.sys

Finds an unused function pointer inside it

Overwrites that pointer with our custom handler

Usermode calls the hooked path → kernel code executes

No device object.
No symbolic link.
No traditional IOCTL interface.

This makes it much harder for security software to detect.

🔧 Physical Memory Engine

The physical memory subsystem can:

Map any physical address into virtual memory

Support multiple page sizes: 4KB, 2MB, 1GB

Walk full x64 page tables manually

PML4 → PDPT → PD → PT

Operate safely at high IRQL

Build mappings on-the-fly for controlled access

📡 Communication Model

User-mode communicates by calling the hooked function using:

A pointer to a command structure

A static identifier for validation

An operation code

The driver processes the request and returns the results through the same structure.

🤔 Why Is This Interesting?

Typical kernel drivers leave obvious artifacts:

Device objects

IOCTL interfaces

Registry entries

This approach instead:

Creates no visible device object

Hides inside legitimate Windows internals

Uses existing system calls

Reduces detection surface for security tools

A strong proof-of-concept for stealthy kernel communication.

📄 Technical Notes

Supports Windows 10/11 x64

Uses CR3 switching for process context manipulation

Fully synchronized for multi-core environments

Implements CFG bypass (validation + dispatch patching)

Uses MDL-based allocation for aligned kernel buffers

⚠️ Warning

This project is for research and educational purposes only.
Use only on systems you own or have explicit authorization to test.
Not intended for malicious use.

📦 Requirements

Windows Driver Kit (WDK)

Visual Studio 2019 or newer

Test signing enabled, or driver signature enforcement disabled

Knowledge of Windows kernel development
