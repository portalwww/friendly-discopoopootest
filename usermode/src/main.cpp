#include "defs.h"
#include "memory.h"
#include "process.h"
#include "../include/rang.hpp"
#include <iostream>

using namespace std;

fn_CorMemLinearToPhys  pfnLinearToPhys  = NULL;
fn_CorMemMapBuffer     pfnMapBuffer     = NULL;
fn_CorMemUnmapBuffer   pfnUnmapBuffer   = NULL;

static HMODULE g_hDll = NULL;

static void PrintPass(const char* test) {
    cout << rang::fg::green << "  PASS " << rang::fg::reset << test << endl;
}

static void PrintFail(const char* test) {
    cout << rang::fg::red << "  FAIL " << rang::fg::reset << test << endl;
}

static void PrintInfo(const char* label, const char* value) {
    cout << rang::fg::cyan << "  " << label << rang::fg::reset << value << endl;
}

static void PrintAddr(const char* label, ULONG64 addr) {
    char buf[32];
    sprintf_s(buf, "0x%016llX", (unsigned long long)addr);
    cout << rang::fg::cyan << "  " << label << rang::fg::yellow << buf << rang::fg::reset << endl;
}

static int Cleanup(int code)
{
    if (g_hDll) { FreeLibrary(g_hDll); g_hDll = NULL; }
    cout << endl << rang::fg::gray << "Press Enter to exit..." << rang::fg::reset;
    cin.get();
    return code;
}

int main(int argc, char* argv[])
{
    const char* targetName = (argc > 1) ? argv[1] : "Strayed.exe";

    cout << endl;
    cout << rang::style::bold << rang::fg::cyan << "  CorMem Driver Test" << rang::style::reset << rang::fg::reset << endl;
    cout << rang::fg::gray << "  target: " << rang::fg::reset << targetName << endl;
    cout << endl;

    // load dll
    g_hDll = LoadLibraryA("CorMem.dll");
    if (!g_hDll) {
        PrintFail("load CorMem.dll");
        cout << rang::fg::red << "  make sure CorMem.dll is next to the exe and the driver is loaded" << rang::fg::reset << endl;
        return Cleanup(1);
    }
    PrintPass("load CorMem.dll");

    pfnLinearToPhys = (fn_CorMemLinearToPhys)GetProcAddress(g_hDll, "CorMemLinearToPhys");
    pfnMapBuffer    = (fn_CorMemMapBuffer)   GetProcAddress(g_hDll, "CorMemMapBuffer");
    pfnUnmapBuffer  = (fn_CorMemUnmapBuffer) GetProcAddress(g_hDll, "CorMemUnmapBuffer");

    if (!pfnLinearToPhys || !pfnMapBuffer || !pfnUnmapBuffer) {
        PrintFail("resolve DLL exports");
        return Cleanup(1);
    }
    PrintPass("resolve DLL exports");

    // eprocess offsets
    EprocessOffsets off = {};
    ULONG build = 0;
    if (!GetEprocessOffsets(&off, &build)) {
        PrintFail("get EPROCESS offsets");
        char buf[64]; sprintf_s(buf, "unsupported build %lu", (unsigned long)build);
        cout << rang::fg::red << "  " << buf << rang::fg::reset << endl;
        return Cleanup(1);
    }
    {
        char buf[64]; sprintf_s(buf, "EPROCESS offsets (build %lu)", (unsigned long)build);
        PrintPass(buf);
    }

    // ntoskrnl
    ULONG64 ntBase = FindNtoskrnlBase();
    if (!ntBase) {
        PrintFail("find ntoskrnl base");
        return Cleanup(1);
    }
    PrintPass("find ntoskrnl base");
    PrintAddr("ntoskrnl:  ", ntBase);

    // system eprocess
    ULONG64 sysEp = ResolvePsInitialSystemProcess(ntBase);
    if (!sysEp) {
        PrintFail("resolve PsInitialSystemProcess");
        return Cleanup(1);
    }
    PrintPass("resolve PsInitialSystemProcess");

    // find target
    ProcessInfo tgt = {};
    if (!FindProcessByName(off, sysEp, targetName, &tgt)) {
        PrintFail("find target process");
        return Cleanup(1);
    }
    PrintPass("find target process");

    cout << endl;
    cout << rang::style::bold << rang::fg::cyan << "  Target Info" << rang::style::reset << rang::fg::reset << endl;
    PrintInfo("name:      ", tgt.name);
    {
        char buf[32]; sprintf_s(buf, "%llu", (unsigned long long)tgt.pid);
        PrintInfo("pid:       ", buf);
    }
    PrintAddr("eprocess:  ", tgt.eprocess);
    PrintAddr("cr3:       ", tgt.cr3);
    PrintAddr("peb:       ", tgt.peb);
    cout << endl;

    if (!tgt.cr3 || !tgt.peb) {
        PrintFail("cr3/peb validation");
        return Cleanup(1);
    }
    PrintPass("cr3/peb validation");

    // read image base from PEB
    ULONG64 imageBase = 0;
    if (!ReadProcessMemory(tgt.cr3, tgt.peb + 0x10, &imageBase, sizeof(imageBase))) {
        PrintFail("read base address (PEB)");
        return Cleanup(1);
    }
    PrintPass("read base address (PEB)");
    PrintAddr("base addr: ", imageBase);

    // read PE header
    BYTE peData[0x1000] = {};
    if (!ReadProcessMemory(tgt.cr3, imageBase, peData, sizeof(peData))) {
        PrintFail("read PE header");
        return Cleanup(1);
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)peData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        PrintFail("DOS signature check");
        return Cleanup(1);
    }
    PrintPass("DOS signature check");

    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(peData)) {
        PrintFail("e_lfanew bounds check");
        return Cleanup(1);
    }

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(peData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        PrintFail("PE signature check");
        return Cleanup(1);
    }
    PrintPass("PE signature check");

    {
        char buf[64];
        sprintf_s(buf, "0x%X (%u KB)", nt->OptionalHeader.SizeOfImage,
                  nt->OptionalHeader.SizeOfImage / 1024);
        PrintInfo("image size:", buf);
    }

    // write round-trip test
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)(
        (PBYTE)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    ULONG secEnd     = (ULONG)((PBYTE)(sec + nt->FileHeader.NumberOfSections) - peData);
    ULONG headersEnd = nt->OptionalHeader.SizeOfHeaders;

    if (headersEnd <= secEnd || (headersEnd - secEnd) < 8) {
        PrintFail("write test (not enough header padding)");
        return Cleanup(1);
    }

    ULONG writeOff = ((secEnd + (headersEnd - secEnd) / 2)) & ~3u;
    ULONG64 writeVA = imageBase + writeOff;

    DWORD original = 0;
    if (!ReadProcessMemory(tgt.cr3, writeVA, &original, sizeof(original))) {
        PrintFail("write test (read original)");
        return Cleanup(1);
    }

    DWORD sentinel = 0xDEADBEEF;
    if (!WriteProcessMemory(tgt.cr3, writeVA, &sentinel, sizeof(sentinel))) {
        PrintFail("write test (write sentinel)");
        return Cleanup(1);
    }

    DWORD readback = 0;
    if (!ReadProcessMemory(tgt.cr3, writeVA, &readback, sizeof(readback))) {
        PrintFail("write test (read back)");
        return Cleanup(1);
    }

    bool writeOk = (readback == sentinel);

    // restore
    WriteProcessMemory(tgt.cr3, writeVA, &original, sizeof(original));

    if (writeOk)
        PrintPass("write round-trip");
    else
        PrintFail("write round-trip");

    // summary
    cout << endl;
    cout << rang::style::bold << rang::fg::cyan << "  Results" << rang::style::reset << rang::fg::reset << endl;

    auto result = [](const char* name, bool ok) {
        if (ok)
            cout << rang::fg::green << " [ PASS ] " << rang::fg::reset << name << endl;
        else
            cout << rang::fg::red << " [ FAIL ] " << rang::fg::reset << name << endl;
    };

    result("driver comms",     g_hDll != NULL);
    result("physical read",    true);
    result("va translation",   tgt.cr3 != 0);
    result("base address",     imageBase != 0);
    result("cr3 retrieval",    tgt.cr3 != 0);
    result("read memory",      dos->e_magic == IMAGE_DOS_SIGNATURE);
    result("write memory",     writeOk);
    cout << endl;

    return Cleanup(writeOk ? 0 : 1);
}
