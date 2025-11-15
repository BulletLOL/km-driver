Kernel Driver Communication Framework
A Windows kernel driver that creates a hidden communication channel between userland applications and the kernel by hooking into the Windows graphics system.
What is this?
This project is a kernel-mode driver that lets user-mode programs perform privileged operations without using the normal Windows driver communication methods. Instead of creating a device that shows up in the system, it hooks an existing function in win32kbase.sys to stay under the radar.
Think of it as a secret backdoor into kernel space that doesn't look like a typical driver.
Features
Memory Operations

Read and write to any process's memory
Direct physical memory access (bypasses normal protections)
Allocate and free memory in other processes
Change memory permissions (make pages executable, writable, etc.)

Advanced Stuff

Bypass Control Flow Guard (CFG) protection
Allocate executable memory in kernel space
Expose kernel memory to userland processes
Find byte patterns in memory (signature scanning)
Get module base addresses from any process
Atomic pointer swapping in target processes

Safety Features

Validates all requests with a static identifier
Verifies calls come from user mode
Handles process context switching properly
Checks physical memory ranges before access

How it works
The driver does something clever to avoid detection:

Finds the NtGdiPolyPolyDraw function in win32kbase.sys (part of Windows graphics)
Locates an unused function pointer inside that function
Replaces it with our own handler
Now when userland calls through this pointer with the right parameters, our code runs

This means there's no visible driver device object that security tools typically look for.
Physical Memory Engine
One of the cooler parts is the physical memory access system. It can:

Map any physical address to a virtual address on the fly
Handle different page sizes (4KB, 2MB, 1GB)
Walk page tables manually (PML4 → PDPT → PD → PT)
Work safely even at high IRQL levels

Communication
Userland programs communicate by calling the hooked function with:

A pointer to a command structure
A static identifier for validation
An operation code telling it what to do

The driver processes the request and returns results through the same structure.
Why is this interesting?
Most kernel drivers use CreateFile and DeviceIoControl which are easy to detect and monitor. This approach:

Leaves no device object trail
Hides inside legitimate Windows components
Uses existing function calls
Harder for security software to spot

It's basically a proof-of-concept for stealthy kernel communication.
Technical notes

Works on Windows 10/11 x64
Uses CR3 manipulation to switch process contexts
Implements proper synchronization for multi-core safety
CFG bypass patches both validation and dispatch functions
MDL-based allocations for aligned kernel buffers

Warning
This is research code to demonstrate kernel programming techniques. It's meant for learning how Windows internals work, not for any malicious purpose. Only use this on your own systems or in authorized testing environments.

Requirements

Windows Driver Kit (WDK)
Visual Studio 2019 or newer
Test signing enabled or disable driver signature enforcement
Understanding of Windows kernel development

