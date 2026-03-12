#pragma once

#ifndef _WIN64
#error "x64 only"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

typedef ULONG64 (*fn_CorMemLinearToPhys)(ULONG64 va);
typedef ULONG64 (*fn_CorMemMapBuffer)(ULONG64 phys, ULONG64 size);
typedef ULONG64 (*fn_CorMemUnmapBuffer)(ULONG64 user_va);

#define SYSTEM_MODULE_INFORMATION 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef NTSTATUS (NTAPI *fnNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS (NTAPI *fnRtlGetVersion)(PRTL_OSVERSIONINFOW);

struct EprocessOffsets {
    ULONG DirectoryTableBase;
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
    ULONG ImageFileName;
    ULONG Peb;
};

struct ProcessInfo {
    ULONG64 eprocess;
    ULONG64 pid;
    ULONG64 cr3;
    ULONG64 peb;
    char    name[16];
};

#define PAGE_4K        0x1000ULL
#define PAGE_MASK_4K   (PAGE_4K - 1)
#define PTE_FRAME      0x000FFFFFFFFFF000ULL
#define PDE_2MB_FRAME  0x000FFFFFFFE00000ULL
#define PDPE_1GB_FRAME 0x000FFFFFC0000000ULL
#define PTE_PRESENT    (1ULL << 0)
#define PTE_LARGE_PAGE (1ULL << 7)
