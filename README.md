#Kernel Driver Communication Framework

A Windows kernel driver that creates a hidden communication channel between userland applications and the kernel by hooking into the Windows graphics subsystem.

What Is This?

This project is a kernel-mode driver that allows user-mode programs to perform privileged operations without using standard Windows driver communication paths.
Instead of exposing a device object, it hooks an internal function in win32kbase.sys, providing a stealthy kernel communication channel.

Features
Memory Operations

Read and write memory of any process

Direct physical memory access

Allocate and free memory in other processes

Modify page protections (RWX, etc.)

Advanced Capabilities

Control Flow Guard (CFG) bypass

Allocate executable kernel memory

Expose kernel memory to user-mode

Signature (pattern) scanning

Retrieve module base addresses

Atomic pointer swapping

Safety Features

Static identifier validation

Ensures the caller is from user mode

Proper process context switching

Physical memory range validation

How It Works

The driver avoids detection using a hook inside the Windows graphics driver:

Hooking Procedure

Locate NtGdiPolyPolyDraw in win32kbase.sys

Identify an unused function pointer within it

Replace this pointer with the driver’s handler

User-mode calls the function → kernel handler executes

This eliminates the need for CreateFile/DeviceIoControl, leaving no driver-visible artifacts.

Physical Memory Engine
Capabilities

Map arbitrary physical addresses

Support 4KB, 2MB, and 1GB pages

Manual page-table walking

PML4 → PDPT → PD → PT

High-IRQL safe mappings

On-demand mapping construction

Communication

User-mode sends operations by calling the hooked function with:

A pointer to a command structure

A static validation ID

An operation code

The driver performs the requested action and writes the results back into the same structure.

Why Is This Interesting?

Traditional drivers leave clear traces:

Driver objects

Device objects

IOCTL interfaces

Registry entries

This approach:

Creates no device object

Hides inside Windows graphics internals

Reuses existing system call paths

Reduces detection surface

A strong demonstration of stealthy kernel-to-user communication.

Technical Notes

Works on Windows 10/11 x64

Uses CR3 manipulation for context switching

Thread-safe with proper synchronization

CFG bypass patches both validation and dispatch routines

MDL-based kernel memory allocations

Warning

This project is intended for research and educational purposes only.
Use it only on systems you own or have explicit permission to test.

Requirements

Windows Driver Kit (WDK)

Visual Studio 2019 or newer

Test signing enabled or disabled driver signature enforcement

Understanding of Windows kernel development
