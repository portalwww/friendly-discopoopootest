#pragma once
#include "defs.h"
#include "memory.h"

inline bool GetEprocessOffsets(EprocessOffsets* o, ULONG* buildOut)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    auto pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
    if (!pRtlGetVersion) return false;

    RTL_OSVERSIONINFOW vi = {};
    vi.dwOSVersionInfoSize = sizeof(vi);
    pRtlGetVersion(&vi);
    *buildOut = vi.dwBuildNumber;

    o->DirectoryTableBase = 0x28;

    if (vi.dwBuildNumber >= 19041 && vi.dwBuildNumber <= 22631) {
        o->UniqueProcessId    = 0x440;
        o->ActiveProcessLinks = 0x448;
        o->ImageFileName      = 0x5A8;
        o->Peb                = 0x550;
        return true;
    }
    if (vi.dwBuildNumber >= 26100) {
        o->UniqueProcessId    = 0x448;
        o->ActiveProcessLinks = 0x450;
        o->ImageFileName      = 0x5B0;
        o->Peb                = 0x558;
        return true;
    }
    return false;
}

inline ULONG64 FindNtoskrnlBase()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtQSI = (fnNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG needed = 0;
    NtQSI(SYSTEM_MODULE_INFORMATION, NULL, 0, &needed);
    if (!needed) return 0;

    RTL_PROCESS_MODULES* mods = (RTL_PROCESS_MODULES*)malloc(needed);
    if (!mods) return 0;

    NTSTATUS st = NtQSI(SYSTEM_MODULE_INFORMATION, mods, needed, &needed);
    if (st != 0) { free(mods); return 0; }

    ULONG64 base = (ULONG64)mods->Modules[0].ImageBase;
    free(mods);
    return base;
}

inline ULONG64 ResolvePsInitialSystemProcess(ULONG64 ntBase)
{
    HMODULE local = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!local) return 0;

    FARPROC sym = GetProcAddress(local, "PsInitialSystemProcess");
    if (!sym) { FreeLibrary(local); return 0; }

    ULONG64 rva = (ULONG64)sym - (ULONG64)local;
    FreeLibrary(local);

    ULONG64 eprocess = 0;
    if (!ReadKernelMemory(ntBase + rva, &eprocess, sizeof(eprocess)))
        return 0;
    return eprocess;
}

inline bool FindProcessByName(const EprocessOffsets& o, ULONG64 systemEprocess,
                               const char* target, ProcessInfo* out)
{
    bool found = false;
    ULONG64 curEp = systemEprocess;
    int n = 0;

    do {
        ULONG64 pid = 0;
        char name[16] = {};
        ReadKernelMemory(curEp + o.UniqueProcessId, &pid, sizeof(pid));
        ReadKernelMemory(curEp + o.ImageFileName, name, 15);
        name[15] = '\0';

        if (_stricmp(name, target) == 0 && !found) {
            out->eprocess = curEp;
            out->pid      = pid;
            strncpy_s(out->name, sizeof(out->name), name, _TRUNCATE);
            ReadKernelMemory(curEp + o.DirectoryTableBase, &out->cr3, 8);
            ReadKernelMemory(curEp + o.Peb, &out->peb, 8);
            found = true;
        }

        ULONG64 flink = 0;
        if (!ReadKernelMemory(curEp + o.ActiveProcessLinks, &flink, 8))
            break;
        curEp = flink - o.ActiveProcessLinks;
        n++;
    } while (curEp != systemEprocess && n < 1024);

    return found;
}
