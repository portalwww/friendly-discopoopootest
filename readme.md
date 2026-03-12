# CorMem Reversal

Reversal of the CorMem vulnerable driver. Explains how the driver works and how to use it.

| Primitive | IOCTL Codes |
|-----------|----------------|
| **Arbitrary physical read/write** | `0x22200C` (MapBuffer) |
| **Arbitrary kernel read/write** | `0x22201C` (LinearToPhys) + `0x22200C` (MapBuffer) |
| **I/O port read** | `0x222014` (ReadIo) |
| **I/O port write** | `0x222018` (WriteIo) |
| **Physical memory allocation** | `0x22203C` (AllocPhysMem) + `0x222044` (MapPhysMem) |
| **Kernel address leak** | `0x22204C`/`0x222060` (GetPhysMem/64) |

## Project Structure

```
analysis/          - reversal notes for the DLL and SYS
driver/            - Cormem.sys + loader script
ida/               - IDA databases (.i64)
usermode/          - VS2022 console project (driver comms test)
  include/         - rang.hpp (colored console output)
  src/             - defs.h, memory.h, process.h, main.cpp
  cormem_test.sln  - open this in Visual Studio
```

## Usermode Test

Open `usermode/cormem_test.sln` in Visual Studio, build x64, and run as admin with the driver loaded. Place `CorMem.dll` next to the built exe. The test verifies read, write, base address, CR3, and VA translation are all working.

## Credits

Prompted By Payson (Claude Opus 4.6)

This vulnerable driver was discovered by [KeServiceDescriptorTable](https://github.com/KeServiceDescriptorTable/cormem.sys-vulnerable-driver)