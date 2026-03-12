#pragma once
#include "defs.h"

extern fn_CorMemLinearToPhys  pfnLinearToPhys;
extern fn_CorMemMapBuffer     pfnMapBuffer;
extern fn_CorMemUnmapBuffer   pfnUnmapBuffer;

inline ULONG64 LinearToPhys(ULONG64 kernelVA)
{
    return pfnLinearToPhys(kernelVA);
}

inline PVOID MapPhysical(ULONG64 physAddr, SIZE_T size)
{
    return (PVOID)pfnMapBuffer(physAddr, (ULONG64)size);
}

inline void UnmapPhysical(PVOID userVA)
{
    pfnUnmapBuffer((ULONG64)userVA);
}

inline bool ReadPhysicalMemory(ULONG64 physAddr, PVOID buffer, SIZE_T size)
{
    PBYTE dst = (PBYTE)buffer;
    SIZE_T done = 0;
    while (done < size) {
        ULONG64 cur      = physAddr + done;
        ULONG64 pageBase = cur & ~PAGE_MASK_4K;
        ULONG   off      = (ULONG)(cur & PAGE_MASK_4K);
        SIZE_T  chunk    = min(size - done, (SIZE_T)(PAGE_4K - off));

        PVOID mapped = MapPhysical(pageBase, PAGE_4K);
        if (!mapped) return false;
        memcpy(dst + done, (PBYTE)mapped + off, chunk);
        UnmapPhysical(mapped);
        done += chunk;
    }
    return true;
}

inline bool WritePhysicalMemory(ULONG64 physAddr, const PVOID data, SIZE_T size)
{
    PBYTE src = (PBYTE)data;
    SIZE_T done = 0;
    while (done < size) {
        ULONG64 cur      = physAddr + done;
        ULONG64 pageBase = cur & ~PAGE_MASK_4K;
        ULONG   off      = (ULONG)(cur & PAGE_MASK_4K);
        SIZE_T  chunk    = min(size - done, (SIZE_T)(PAGE_4K - off));

        PVOID mapped = MapPhysical(pageBase, PAGE_4K);
        if (!mapped) return false;
        memcpy((PBYTE)mapped + off, src + done, chunk);
        UnmapPhysical(mapped);
        done += chunk;
    }
    return true;
}

inline bool ReadKernelMemory(ULONG64 kva, PVOID buffer, SIZE_T size)
{
    PBYTE dst = (PBYTE)buffer;
    SIZE_T done = 0;
    while (done < size) {
        ULONG64 curVA = kva + done;
        SIZE_T  chunk = min(size - done, (SIZE_T)(PAGE_4K - (curVA & PAGE_MASK_4K)));

        ULONG64 phys = LinearToPhys(curVA);
        if (!phys) return false;

        ULONG64 pageBase = phys & ~PAGE_MASK_4K;
        ULONG   off      = (ULONG)(phys & PAGE_MASK_4K);

        PVOID mapped = MapPhysical(pageBase, PAGE_4K);
        if (!mapped) return false;
        memcpy(dst + done, (PBYTE)mapped + off, chunk);
        UnmapPhysical(mapped);
        done += chunk;
    }
    return true;
}

inline ULONG64 TranslateVA(ULONG64 cr3, ULONG64 va)
{
    ULONG64 indices[4] = {
        (va >> 39) & 0x1FF,
        (va >> 30) & 0x1FF,
        (va >> 21) & 0x1FF,
        (va >> 12) & 0x1FF,
    };

    ULONG64 tablePhys = cr3 & PTE_FRAME;

    for (int level = 0; level < 4; level++) {
        ULONG64 entry = 0;
        if (!ReadPhysicalMemory(tablePhys + indices[level] * 8, &entry, 8))
            return 0;
        if (!(entry & PTE_PRESENT))
            return 0;
        if ((entry & PTE_LARGE_PAGE) && level == 1)
            return (entry & PDPE_1GB_FRAME) | (va & 0x3FFFFFFFULL);
        if ((entry & PTE_LARGE_PAGE) && level == 2)
            return (entry & PDE_2MB_FRAME) | (va & 0x1FFFFFULL);

        tablePhys = entry & PTE_FRAME;
    }
    return tablePhys | (va & PAGE_MASK_4K);
}

inline bool ReadProcessMemory(ULONG64 cr3, ULONG64 va, PVOID buf, SIZE_T size)
{
    PBYTE dst = (PBYTE)buf;
    SIZE_T done = 0;
    while (done < size) {
        ULONG64 curVA = va + done;
        ULONG   off   = (ULONG)(curVA & PAGE_MASK_4K);
        SIZE_T  chunk = min(size - done, (SIZE_T)(PAGE_4K - off));

        ULONG64 phys = TranslateVA(cr3, curVA);
        if (!phys) return false;
        if (!ReadPhysicalMemory(phys, dst + done, chunk))
            return false;
        done += chunk;
    }
    return true;
}

inline bool WriteProcessMemory(ULONG64 cr3, ULONG64 va, const PVOID data, SIZE_T size)
{
    PBYTE src = (PBYTE)data;
    SIZE_T done = 0;
    while (done < size) {
        ULONG64 curVA = va + done;
        ULONG   off   = (ULONG)(curVA & PAGE_MASK_4K);
        SIZE_T  chunk = min(size - done, (SIZE_T)(PAGE_4K - off));

        ULONG64 phys = TranslateVA(cr3, curVA);
        if (!phys) return false;
        if (!WritePhysicalMemory(phys, src + done, chunk))
            return false;
        done += chunk;
    }
    return true;
}
