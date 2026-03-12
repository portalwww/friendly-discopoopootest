# CorMem.sys Kernel Driver — BYOVD Attack Surface Analysis

## Executive Summary

**CorMem.sys** is a signed Windows kernel-mode driver from the **Teledyne DALSA Sapera LT SDK**, an industrial imaging and frame-grabber framework. The driver provides direct hardware memory management primitives for interfacing with image acquisition boards (e.g., PCIe frame grabbers). It exposes **26+ IOCTL handlers** through a single device object accessible to any user on the system.

From a BYOVD (Bring Your Own Vulnerable Driver) perspective, this driver is **critically dangerous**. It provides an unprivileged attacker with:

- **Arbitrary physical memory read/write** via `\Device\PhysicalMemory` section mapping
- **Arbitrary I/O port read/write** via direct `IN`/`OUT` x86 instructions
- **Virtual-to-physical address translation** via `MmGetPhysicalAddress`
- **Physical memory allocation and user-space mapping** via MDL primitives
- **No access control** — the device is created with default (permissive) security descriptors

These primitives are sufficient to achieve **full kernel compromise** from an unprivileged user-mode process, including: disabling security products (EDR/AV), escalating privileges, installing rootkits, and bypassing all Windows security mechanisms.

---

## 1. Binary Metadata

| Property | Value |
|----------|-------|
| **File** | CorMem.sys |
| **Type** | Windows kernel-mode driver (64-bit) |
| **Product** | Teledyne DALSA Sapera LT SDK |
| **Version String** | `"9.00"` (embedded in DriverEntry) |
| **Source Files** (from debug strings) | `..\WinNT\cormem.c`, `..\..\..\Common\Kernel\WinNT\corlibk.c` |
| **PDB Path** | Not embedded (stripped) |
| **Device Name** | `\Device\CORMEM` |
| **Symbolic Link** | `\DosDevices\CORMEM` (user-mode: `\\.\CORMEM`) |
| **Device Type** | `0x22` (`FILE_DEVICE_UNKNOWN`) |
| **Total Functions** | 93 |
| **Total Imports** | 47 (ntoskrnl.exe + HAL.dll) |

---

## 2. Import Analysis

### ntoskrnl.exe Imports (46)

The import table reveals the full scope of dangerous kernel APIs this driver uses:

**Physical Memory & MDL Operations:**
| Import | Purpose |
|--------|---------|
| `MmGetPhysicalAddress` | Translate virtual address → physical address |
| `MmIsAddressValid` | Validate virtual address (unreliable in race conditions) |
| `MmMapLockedPagesSpecifyCache` | Map MDL pages into user-mode address space |
| `MmUnmapLockedPages` | Unmap MDL pages from user-mode |
| `MmAllocatePagesForMdl` | Allocate physical pages (arbitrary ranges) |
| `MmFreePagesFromMdl` | Free MDL-allocated physical pages |
| `MmAllocateContiguousMemory` | Allocate physically contiguous DMA memory |
| `MmFreeContiguousMemory` | Free contiguous memory |
| `MmProbeAndLockPages` | Lock user-mode pages in physical memory |
| `MmUnlockPages` | Unlock MDL pages |
| `IoAllocateMdl` | Create Memory Descriptor List |
| `IoFreeMdl` | Free MDL |

**Section Object Operations (Physical Memory Mapping):**
| Import | Purpose |
|--------|---------|
| `ZwOpenSection` | Open `\Device\PhysicalMemory` section |
| `ZwMapViewOfSection` | Map physical address range into process VA space |
| `ZwUnmapViewOfSection` | Unmap section view |
| `ZwClose` | Close section handle |
| `ObReferenceObjectByHandle` | Reference section object from handle |

**Device & IRP Management:**
| Import | Purpose |
|--------|---------|
| `IoCreateDevice` | Create `\Device\CORMEM` |
| `IoCreateSymbolicLink` | Create `\DosDevices\CORMEM` |
| `IoDeleteDevice` | Cleanup on unload |
| `IoDeleteSymbolicLink` | Cleanup on unload |
| `IoIs32bitProcess` | WOW64 detection for struct layout |
| `IoGetCurrentProcess` | Process context tracking |
| `IoBuildDeviceIoControlRequest` | Build internal IOCTLs |
| `IofCallDriver` | Forward IRPs |
| `IofCompleteRequest` | Complete IRPs |
| `IoGetDeviceObjectPointer` | Get device object reference |

**Synchronization & Registry:**
| Import | Purpose |
|--------|---------|
| `KeInitializeMutex` | Initialize kernel mutex |
| `KeWaitForSingleObject` | Acquire mutex |
| `KeReleaseMutex` | Release mutex |
| `ExAllocatePoolWithTag` | Allocate pool memory |
| `ExFreePoolWithTag` | Free pool memory |
| `RtlGetVersion` | Get OS version |
| `RtlQueryRegistryValues` | Read pool configuration from registry |
| `RtlWriteRegistryValue` | Write configuration to registry |
| `PsGetProcessId` | Get process ID for tracking |

### HAL.dll Imports (1)

| Import | Purpose |
|--------|---------|
| `HalTranslateBusAddress` | Translate bus-relative address to physical address (used in physical memory mapping) |

---

## 3. DriverEntry Analysis

**Address:** `0x140004B04`

```
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
```

### Initialization Flow

1. **Store driver globals:** Saves `DriverObject` and `RegistryPath` globally
2. **Get OS version:** Calls `RtlGetVersion()` and stores version info
3. **Create device:** `IoCreateDevice(\Device\CORMEM, type=0x22, characteristics=0)`
   - **No security descriptor** — uses system default (accessible to all users)
   - Device type `FILE_DEVICE_UNKNOWN` (0x22)
   - No exclusive access flag
4. **Create symbolic link:** `IoCreateSymbolicLink(\DosDevices\CORMEM, \Device\CORMEM)`
5. **Set dispatch handlers:** ALL major functions routed to a single handler:
   - `IRP_MJ_CREATE` (0) → `sub_140002C5C`
   - `IRP_MJ_CLOSE` (2) → `sub_140002C5C`
   - `IRP_MJ_DEVICE_CONTROL` (14) → `sub_140002C5C`
   - `IRP_MJ_INTERNAL_DEVICE_CONTROL` (15) → `sub_140002C5C`
6. **Set unload handler:** `DriverUnload` → `sub_140006A64`
7. **Initialize memory pools:** Calls `sub_14000550C(RegistryPath)` which:
   - Allocates 5 kernel mutexes for synchronization
   - Reads pool block counts from registry (32-bit and 64-bit pool counts)
   - Allocates **contiguous physical memory** via `MmAllocateContiguousMemory` for:
     - **Messaging pool** — stored at `BaseAddress` / `qword_140010198` (phys addr)
     - **32-bit object pools** — up to 128 blocks, stored in `qword_14000E858[]` (VA), `qword_14000E850[]` (PA), `dword_14000E860[]` (sizes)
     - **64-bit object pools** — up to 128 blocks, stored in `qword_14000F458[]` (VA), `qword_14000F450[]` (PA), `dword_14000F460[]` (sizes)
   - Creates memory manager objects for each pool block
8. **Get process reference:** Stores `IoGetCurrentProcess()` in global for process tracking
9. **Optionally obtain device object reference:** Calls `IoGetDeviceObjectPointer` for `\Device\CORMEM`

### Security Assessment of DriverEntry

| Check | Present? |
|-------|----------|
| Custom security descriptor on device | **NO** |
| `FILE_DEVICE_SECURE_OPEN` flag | **NO** |
| Administrator-only access check | **NO** |
| Exclusive device access | **NO** |
| Digital signature verification | Only Windows loader enforcement |

**Result:** Any process on the system can open `\\.\CORMEM` and send IOCTLs.

---

## 4. Main Dispatch Routine

**Address:** `0x140002C5C`

All IRP major functions (CREATE, CLOSE, DEVICE_CONTROL, INTERNAL_DEVICE_CONTROL) are handled by a single monolithic dispatch function.

### IRP_MJ_CREATE (Open Device)

- Calls `sub_14000498C(Object)` to acquire global mutex
- Increments `dword_1400101A4` (open handle count)
- On first open: calls `IoGetDeviceObjectPointer(\Device\CORMEM)` and stores reference
- **No access control** — any caller is permitted

### IRP_MJ_CLOSE (Close Device)

- Decrements `dword_1400101A4` (open handle count)  
- Calls `sub_140003630()` — iterates through **all pool memory managers** for both 32-bit and 64-bit pools
  - For each pool: calls `sub_140002154()` which frees allocated blocks belonging to the closing process
  - Also cleans messaging pool memory manager
- Calls `sub_140004144(process_handle)` — walks the MDL descriptor linked list and frees/unlocks MDLs allocated by the closing process:
  - For MDLs from `MmAllocatePagesForMdl`: calls `MmFreePagesFromMdl` + `ExFreePoolWithTag`
  - For locked user-buffer MDLs: calls `MmUnlockPages` + `IoFreeMdl` for each MDL in chain
- Calls `sub_140004290(process_handle)` — walks a secondary linked list and frees pool-tagged allocations for the closing process

### IRP_MJ_DEVICE_CONTROL (IOCTL Dispatch)

1. Checks `IoIs32bitProcess(Irp)` for WOW64 compatibility
2. Extracts `IoControlCode` from current stack location
3. Routes to specific handler via cascading if/else chain (not a switch table)
4. All IOCTLs use `METHOD_BUFFERED` with `FILE_ANY_ACCESS`

### IRP_MJ_INTERNAL_DEVICE_CONTROL

- Single IOCTL code `0x222008` — **GETFUNCTIONS**
- Returns an array of 17 internal function pointers to the caller
- This allows other kernel drivers to call CorMem functions directly (internal kernel API export)

---

## 5. Complete IOCTL Reference Table

All IOCTLs use device type `0x22` (FILE_DEVICE_UNKNOWN), `METHOD_BUFFERED`, `FILE_ANY_ACCESS`.

| IOCTL Code | Name | Handler Address | Kernel APIs Used | Attack Relevance |
|-----------|------|----------------|-----------------|-----------------|
| `0x222000` | MapPool | `sub_1400067E8` | `sub_14000147C` → ZwOpenSection + ZwMapViewOfSection | **CRITICAL** — Maps pre-allocated pool memory (physical) into user-space |
| `0x222004` | FreeBuffer | `sub_140003CD0` → `sub_1400037A8` | VA→PA translation via pool lookup, then free | Low |
| `0x222008` | GetFunctions (Internal) | Inline | Returns 17 function pointers | Medium — kernel info leak |
| `0x22200C` | MapBuffer | `sub_140006154` | `sub_14000147C` → ZwOpenSection + ZwMapViewOfSection | **CRITICAL** — Maps arbitrary physical address to user-space |
| `0x222010` | UnmapBuffer | `sub_140006E40` | ZwUnmapViewOfSection(NtCurrentProcess) | Low |
| `0x222014` | ReadIo | `sub_140006AA4` | `__inbyte`, `__inword`, `__indword` | **CRITICAL** — Arbitrary I/O port read |
| `0x222018` | WriteIo | `sub_140006F7C` | `__outbyte`, `__outword`, `__outdword` | **CRITICAL** — Arbitrary I/O port write |
| `0x22201C` | LinearToPhys | `sub_1400060A0` | `MmGetPhysicalAddress` | **HIGH** — VA-to-PA translation oracle |
| `0x222020` | FreeBuffer2 | (same as 0x222004) | Pool VA→PA lookup + free | Low |
| `0x222024` | LockSGBuffer | `sub_140006BF4` → `sub_140002A7C` | IoAllocateMdl + MmProbeAndLockPages | Medium |
| `0x222028` | UnlockSGBuffer | `sub_140006B74` | MmUnlockPages + IoFreeMdl | Low |
| `0x22202C` | UnlockAllSGBuffers | `sub_140004144` + `sub_140004290` | Walk MDL lists, MmUnlockPages, IoFreeMdl, MmFreePagesFromMdl | Low |
| `0x222030` | AllocBufferObj | `sub_1400065F8` | Pool memory manager allocation (32-bit pool) | Medium |
| `0x222034` | AllocBufferMsg | `sub_140002988` | Messaging pool memory manager allocation | Low |
| `0x222038` | GetMsgBoundary | Inline | Returns `qword_14000E038` | Low — info leak |
| `0x22203C` | AllocPhysMem | `sub_1400024DC` | `MmAllocatePagesForMdl(Low, High, Skip, Size)` | **HIGH** — Allocate arbitrary physical memory |
| `0x222040` | FreePhysMem | `sub_140004C9C` | MmFreePagesFromMdl + ExFreePoolWithTag | Low |
| `0x222044` | MapPhysMem | `sub_1400062EC` | `MmMapLockedPagesSpecifyCache(mdl, UserMode)` | **CRITICAL** — Map kernel MDL to user-space |
| `0x222048` | UnmapPhysMem | `sub_140006EC8` | MmUnmapLockedPages | Low |
| `0x22204C` | GetPhysMem | `sub_140005264` | Read scatter-gather list from MDL (32-bit) | Medium — physical address leak |
| `0x222050` | BufferObjStatus | `sub_140003B8C` | Pool status query | Low — info leak |
| `0x222054` | BufferMsgStatus | `sub_1400039AC` | Pool status query | Low — info leak |
| `0x222058` | CreateMdlAndLock | `sub_140004A20` | IoAllocateMdl + MmProbeAndLockPages | Medium |
| `0x22205C` | GetPoolBlockCount | Inline | Returns `dword_140010168 + dword_140010164 + 1` | Low — info leak |
| `0x222060` | GetPhysMem64 | `sub_1400053B8` | Read scatter-gather list from MDL (64-bit) | Medium — physical address leak |
| `0x222064` | AllocBufferObj64 | `sub_140006428` | Pool memory manager allocation (64-bit pool) | Medium |
| `0x222068` | BufferObj64Status | `sub_140003A70` | Pool status query (64-bit) | Low — info leak |

---

## 6. Critical IOCTL Handler Deep-Dive

### 6.1 MapBuffer / MapPool — Arbitrary Physical Memory Mapping

**Core function:** `sub_14000147C`  
**Called by:** IOCTL `0x22200C` (MapBuffer via `sub_140006154`) and IOCTL `0x222000` (MapPool via `sub_1400067E8`)

This is the **most dangerous primitive** in the driver. It maps an arbitrary physical address range directly into the calling process's virtual address space.

#### Pseudocode Flow

```c
NTSTATUS MapPhysicalToUser(PHYSICAL_ADDRESS PhysAddr, SIZE_T Size, PVOID *UserVA)
{
    UNICODE_STRING PhysMemName;
    OBJECT_ATTRIBUTES ObjAttr;
    HANDLE SectionHandle;
    
    // 1. Optionally translate bus address to physical address
    HalTranslateBusAddress(InterfaceType, BusNumber, PhysAddr, &AddressSpace, &TranslatedAddr);
    
    // 2. Open \Device\PhysicalMemory with FULL ACCESS
    RtlInitUnicodeString(&PhysMemName, L"\\Device\\PhysicalMemory");
    InitializeObjectAttributes(&ObjAttr, &PhysMemName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ZwOpenSection(&SectionHandle, SECTION_ALL_ACCESS, &ObjAttr);  // 0xF001F
    
    // 3. Map physical range into CURRENT PROCESS
    ViewBase = NULL;
    ViewSize = Size;
    SectionOffset = TranslatedAddr;
    ZwMapViewOfSection(
        SectionHandle,
        NtCurrentProcess(),     // Maps into calling process
        &ViewBase,
        0,                      // No zero-bits requirement
        ViewSize,               // Commit size
        &SectionOffset,         // Physical offset
        &ViewSize,              // View size
        ViewShare,              // Inherit disposition
        0,                      // Allocation type
        PAGE_READWRITE | PAGE_NOCACHE  // 0x10 = PAGE_NOCACHE
    );
    
    ZwClose(SectionHandle);
    *UserVA = ViewBase;
    return STATUS_SUCCESS;
}
```

#### Attack Impact

An attacker can map **any physical address** into their process with **read/write** permissions and **no caching** (device-style access). This allows:

- **Reading/writing kernel memory** by targeting physical pages backing kernel structures
- **Reading/writing any process memory** by calculating physical addresses
- **Modifying page tables** for arbitrary code execution in kernel context
- **Patching PatchGuard** data structures to disable kernel integrity checks
- **Modifying `_EPROCESS` token** to escalate privileges

#### Input Validation

**None.** The physical address and size come directly from the user-mode IOCTL buffer with zero validation.

---

### 6.2 ReadIo / WriteIo — Arbitrary I/O Port Access

**ReadIo Handler:** `sub_140006AA4` (IOCTL `0x222014`)  
**WriteIo Handler:** `sub_140006F7C` (IOCTL `0x222018`)

#### ReadIo Pseudocode

```c
NTSTATUS ReadIo(PVOID InputBuffer, ULONG InputSize, PVOID OutputBuffer, ULONG OutputSize)
{
    ULONG Size = *(DWORD*)(InputBuffer + 0);     // 1, 2, or 4 bytes
    USHORT Port = *(WORD*)(InputBuffer + 4);      // Port address
    
    switch (Size) {
        case 1: *(BYTE*)OutputBuffer  = __inbyte(Port);  break;
        case 2: *(WORD*)OutputBuffer  = __inword(Port);  break;
        case 4: *(DWORD*)OutputBuffer = __indword(Port);  break;
    }
    return STATUS_SUCCESS;
}
```

#### WriteIo Pseudocode

```c
NTSTATUS WriteIo(PVOID InputBuffer, ULONG InputSize)
{
    ULONG Size  = *(DWORD*)(InputBuffer + 0);     // 1, 2, or 4 bytes
    USHORT Port = *(WORD*)(InputBuffer + 4);       // Port address
    ULONG Value = *(DWORD*)(InputBuffer + 8);      // Value to write
    
    switch (Size) {
        case 1: __outbyte(Port, (BYTE)Value);   break;
        case 2: __outword(Port, (WORD)Value);   break;
        case 4: __outdword(Port, (DWORD)Value); break;
    }
    return STATUS_SUCCESS;
}
```

#### Attack Impact

Direct `IN`/`OUT` instruction execution from user-mode. No port address validation. Enables:

- **PCI configuration space read/write** (ports `0xCF8`/`0xCFC`) — reconfigure any PCI device
- **CMOS/RTC manipulation** (ports `0x70`/`0x71`)
- **Legacy interrupt controller programming** (ports `0x20`/`0x21`, `0xA0`/`0xA1`)
- **DMA controller manipulation** for DMA attacks
- **SMI triggering** via port `0xB2` — potentially reaching SMM code
- **Platform-specific chipset register access** — disable security features at hardware level

---

### 6.3 LinearToPhys — Virtual-to-Physical Address Translation

**Handler:** `sub_1400060A0` (IOCTL `0x22201C`)

#### Pseudocode

```c
NTSTATUS LinearToPhys(PVOID InputBuffer, PVOID OutputBuffer)
{
    PVOID VirtualAddress = *(PVOID*)InputBuffer;
    
    PHYSICAL_ADDRESS PhysAddr = MmGetPhysicalAddress(VirtualAddress);
    
    *(PHYSICAL_ADDRESS*)OutputBuffer = PhysAddr;
    return STATUS_SUCCESS;
}
```

#### Attack Impact

Provides an **address translation oracle** that converts any kernel virtual address to its physical address. Combined with the MapBuffer IOCTL (which maps physical addresses to user-space), this creates a complete **arbitrary kernel read/write** chain:

1. Locate target kernel virtual address (e.g., `_EPROCESS.Token` of your process)
2. Call `LinearToPhys` IOCTL to get the physical address
3. Call `MapBuffer` IOCTL to map that physical page into your process
4. Read/write kernel data from user-mode at will

**No validation** on the virtual address. Calling `MmGetPhysicalAddress` on an invalid address can cause a **blue screen** (BSOD), but the driver does not check `MmIsAddressValid` first.

---

### 6.4 AllocPhysMem — Physical Memory Allocation

**Handler:** `sub_1400024DC` (IOCTL `0x22203C`)

#### Pseudocode

```c
NTSTATUS AllocPhysMem(PVOID InputBuffer, PVOID OutputBuffer)
{
    PHYSICAL_ADDRESS LowAddr  = *(PHYSICAL_ADDRESS*)(InputBuffer + 0);
    PHYSICAL_ADDRESS HighAddr = *(PHYSICAL_ADDRESS*)(InputBuffer + 8);
    PHYSICAL_ADDRESS SkipBytes = *(PHYSICAL_ADDRESS*)(InputBuffer + 16);
    SIZE_T TotalBytes = *(SIZE_T*)(InputBuffer + 24);
    
    PMDL Mdl = MmAllocatePagesForMdl(LowAddr, HighAddr, SkipBytes, TotalBytes);
    
    // Store MDL in linked list at unk_14000C168 with process tracking
    // Allocate descriptor node, link MDL, store requesting process handle
    
    *(PMDL*)OutputBuffer = Mdl;  // Return MDL pointer to user-mode
    return STATUS_SUCCESS;
}
```

#### Attack Impact

Allocates physical pages from **user-specified address ranges**. The MDL is stored in a kernel-managed linked list and can later be:
- **Mapped into user-space** via `MapPhysMem` IOCTL (`0x222044`)
- **Queried for physical addresses** via `GetPhysMem` IOCTL (`0x22204C`)

The user controls `LowAddress`, `HighAddress`, `SkipBytes`, and `TotalBytes` — all parameters to `MmAllocatePagesForMdl`. No range validation.

---

### 6.5 MapPhysMem — Map MDL to User-Space

**Handler:** `sub_1400062EC` (IOCTL `0x222044`)

#### Pseudocode

```c
NTSTATUS MapPhysMem(PVOID InputBuffer, PVOID OutputBuffer)
{
    // Look up MDL from internal descriptor list by index/handle
    PMDL Mdl = LookupMdlDescriptor(InputBuffer);
    
    PVOID UserVA = MmMapLockedPagesSpecifyCache(
        Mdl,
        UserMode,           // Map into user-space
        MmCached,           // Cached mapping
        NULL,               // No preferred base
        FALSE,              // No bug-check on failure
        NormalPagePriority   // Normal priority
    );
    
    *(PVOID*)OutputBuffer = UserVA;
    return STATUS_SUCCESS;
}
```

Maps kernel MDL pages directly into the calling user-mode process. Combined with `AllocPhysMem`, provides user-mode access to allocated physical pages.

---

### 6.6 LockSGBuffer — Scatter-Gather Buffer Lock

**Core function:** `sub_140002A7C` (called from `sub_140006BF4`, IOCTL `0x222024`)

```c
NTSTATUS LockSGBuffer(PVOID UserBuffer, SIZE_T Length)
{
    // Splits large buffers into multiple MDLs (page-aligned chunks)
    // For each chunk:
    PMDL Mdl = IoAllocateMdl(UserVA, ChunkSize, FALSE, FALSE, NULL);
    MmProbeAndLockPages(Mdl, UserMode, IoModifyAccess);  // Read+Write
    
    // Links MDLs together: Mdl->Next = PreviousMdl
    // Stores descriptor with process tracking in linked list
}
```

Locks arbitrary user-mode buffer pages in physical memory and creates MDLs. The `IoModifyAccess` flag means locked pages get read+write access. The resulting scatter-gather list (physical page frame numbers) is returned to user-mode via `GetPhysMem`/`GetPhysMem64` IOCTLs.

---

### 6.7 FreeBuffer — VA-to-PA Translation

**Handler:** `sub_140003CD0` (IOCTL `0x222004`)

Performs virtual address to physical address translation for the driver's internal memory pools:

1. Checks if VA falls within **messaging pool** range → converts to physical using stored base PA
2. Iterates **32-bit pool blocks** → checks if VA is in range → converts using stored PA offset
3. Iterates **64-bit pool blocks** → checks if VA is in range → converts using stored PA offset

This function reveals the driver's internal memory layout and physical addresses of all allocated pools.

---

## 7. Driver Unload

**Handler:** `sub_140006A64`

```c
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    sub_140002618();  // Free all resources:
                      // - MmFreeContiguousMemory for all 64-bit pool blocks
                      // - Destroy all 64-bit pool memory managers
                      // - MmFreeContiguousMemory for all 32-bit pool blocks
                      // - Destroy all 32-bit pool memory managers
                      // - MmFreeContiguousMemory for messaging pool
                      // - Destroy messaging pool memory manager
                      // - ExFreePoolWithTag for all 5 mutexes
    
    IoDeleteSymbolicLink(L"\\DosDevices\\CORMEM");
    IoDeleteDevice(DriverObject->DeviceObject);
    
    if (byte_14000C148)
        ObfDereferenceObject(DeviceObject);  // Release cached device reference
}
```

---

## 8. WOW64 Support

The dispatch routine calls `IoIs32bitProcess(Irp)` at every IOCTL entry point. When a 32-bit process is detected:

- Input/output buffer structure layouts change (pointers are 4 bytes instead of 8)
- Different offsets are used for reading physical addresses and sizes
- Some handlers have separate code paths (e.g., `GetPhysMem` vs `GetPhysMem64`)

This means the driver can be exploited from both **native 64-bit** and **WOW64 32-bit** processes.

---

## 9. Global Data Structures

### Memory Pool Arrays

| Global | Type | Purpose |
|--------|------|---------|
| `BaseAddress` | PVOID | Messaging pool kernel virtual address |
| `qword_140010198` | PHYSICAL_ADDRESS | Messaging pool physical address |
| `NumberOfBytes` | ULONG | Messaging pool size |
| `dword_140010164` | ULONG | 32-bit pool block count |
| `dword_140010168` | ULONG | 64-bit pool block count |
| `qword_14000E050[128]` | PVOID[] | 32-bit pool memory manager objects |
| `qword_14000E858[128]` | PVOID[] | 32-bit pool kernel VAs (indexed as [3*i]) |
| `qword_14000E850[128]` | PHYSICAL_ADDRESS[] | 32-bit pool physical addresses (indexed as [3*i]) |
| `dword_14000E860[128]` | ULONG[] | 32-bit pool sizes (indexed as [3*i]) |
| `qword_14000E450[128]` | PVOID[] | 64-bit pool memory manager objects |
| `qword_14000F458[128]` | PVOID[] | 64-bit pool kernel VAs (indexed as [3*i]) |
| `qword_14000F450[128]` | PHYSICAL_ADDRESS[] | 64-bit pool physical addresses (indexed as [3*i]) |
| `dword_14000F460[128]` | ULONG[] | 64-bit pool sizes (indexed as [3*i]) |

### MDL Tracking

| Global | Purpose |
|--------|---------|
| `unk_14000C168` | Head of MDL descriptor linked list |
| `unk_14000C198` | Head of secondary allocation linked list |
| `off_14000C000` | Tail pointer for MDL list |
| `off_14000C008` | Tail pointer for secondary list |

### Synchronization

| Global | Purpose |
|--------|---------|
| `Object` | Mutex for MDL descriptor list |
| `qword_140010178` | Mutex for secondary allocation list |
| `P` | Mutex for messaging pool operations |
| `qword_14000E018` | Mutex for 32-bit pool operations |
| `qword_14000E010` | Mutex for 64-bit pool operations |

### Device State

| Global | Purpose |
|--------|---------|
| `dword_1400101A4` | Open handle count |
| `qword_1400101B0` | IoGetCurrentProcess() result from DriverEntry |
| `DeviceObject` | Cached device object reference |
| `byte_14000C148` | Flag: device object reference obtained |

---

## 10. BYOVD Attack Surface Analysis

### 10.1 Vulnerability Classification

| Vulnerability | CWE | CVSS Impact |
|--------------|-----|-------------|
| Arbitrary physical memory read/write | CWE-782: Exposed IOCTL with Insufficient Access Control | Critical (10.0) |
| Arbitrary I/O port read/write | CWE-782 | Critical (10.0) |
| VA-to-PA translation oracle | CWE-200: Information Exposure | High (8.0) |
| Physical memory allocation + user mapping | CWE-782 | Critical (9.0) |
| No device access control | CWE-732: Incorrect Permission Assignment | High (8.0) |

### 10.2 Attack Primitives Summary

| Primitive | IOCTLs Required | Difficulty |
|-----------|----------------|------------|
| **Arbitrary physical read/write** | `0x22200C` (MapBuffer) | Trivial |
| **Arbitrary kernel read/write** | `0x22201C` (LinearToPhys) + `0x22200C` (MapBuffer) | Trivial |
| **I/O port read** | `0x222014` (ReadIo) | Trivial |
| **I/O port write** | `0x222018` (WriteIo) | Trivial |
| **Physical memory allocation** | `0x22203C` (AllocPhysMem) + `0x222044` (MapPhysMem) | Easy |
| **Kernel address leak** | `0x22204C`/`0x222060` (GetPhysMem/64) | Easy |

### 10.3 Exploit Chains

#### Chain 1: Privilege Escalation (Token Swap)

**Complexity:** Trivial  
**IOCTLs used:** `0x22201C` + `0x22200C`

1. Get own `_EPROCESS` kernel address (via `NtQuerySystemInformation` or other known techniques)
2. Send `LinearToPhys` IOCTL (`0x22201C`) with address of `_EPROCESS.Token`
3. Receive physical address of the token page
4. Send `MapBuffer` IOCTL (`0x22200C`) to map that physical page into user-space
5. Overwrite `Token` field with SYSTEM process token value
6. Current process now runs as NT AUTHORITY\SYSTEM

#### Chain 2: Disable EDR/AV Kernel Callbacks

**Complexity:** Easy  
**IOCTLs used:** `0x22201C` + `0x22200C`

1. Enumerate loaded kernel modules to find security product driver base addresses
2. Locate callback registration structures (e.g., `PsSetCreateProcessNotifyRoutine` callbacks in `nt!PspCreateProcessNotifyRoutine` array)
3. Use `LinearToPhys` to get physical addresses of callback array entries
4. Map via `MapBuffer` and **zero out** or **replace** callback pointers
5. EDR process creation, thread creation, and image load notifications are silently disabled

#### Chain 3: Kernel Code Execution via PTE Manipulation

**Complexity:** Moderate  
**IOCTLs used:** `0x22201C` + `0x22200C`

1. Allocate a user-mode page containing shellcode
2. Use `LinearToPhys` to get the physical address of the PTE for your shellcode page
3. Map PTE physical page via `MapBuffer`
4. Modify PTE flags: clear `User` bit, set `Executable` bit → page becomes kernel-mode executable
5. Trigger execution via registered callback or APC

#### Chain 4: SMM/Hardware Attack via I/O Ports

**Complexity:** Advanced  
**IOCTLs used:** `0x222014` + `0x222018`

1. Use `WriteIo` to write to port `0xB2` (SMI trigger port) with crafted values
2. Or use port `0xCF8`/`0xCFC` to reconfigure PCI devices (e.g., disable IOMMU)
3. Or reprogram legacy DMA controllers for DMA-based attacks
4. Port `0x70`/`0x71` access allows CMOS/BIOS settings manipulation

#### Chain 5: Physical Memory Scan

**Complexity:** Trivial  
**IOCTLs used:** `0x22200C`

1. Iterate through physical address ranges (0 → max physical address)
2. Map each page via `MapBuffer` 
3. Scan for kernel structures, credential material, encryption keys
4. Equivalent to a cold-boot attack without physical access

### 10.4 Comparison to Known BYOVD Drivers

| Feature | CorMem.sys | RTCore64.sys (MSI) | dbutil_2_3.sys (Dell) | IQVW64E.sys (Intel) |
|---------|-----------|-------------------|---------------------|-------------------|
| Phys mem R/W | **Yes** (\Device\PhysicalMemory) | Yes (MmMapIoSpace) | Yes (MmMapIoSpace) | Yes (MmMapIoSpace) |
| I/O port R/W | **Yes** (IN/OUT) | Yes | No | No |
| VA→PA translation | **Yes** | No | No | No |
| MDL allocation + mapping | **Yes** | No | No | No |
| Access control | **None** | None | None | None |
| Signed | **Yes** (WHQL/Authenticode) | Yes | Yes | Yes |
| Known in-the-wild abuse | Not yet publicly | Yes (BlackByte) | Yes (multiple) | Yes (Lazarus) |

**CorMem.sys provides a superset of capabilities** compared to most known BYOVD drivers, combining physical memory access, I/O port access, address translation, and memory allocation primitives in a single driver.

---

## 11. Detection & Mitigation

### Detection Signatures

#### Driver Loading
```
EventID: 7045 (System) - Service installation
ServiceName: CORMEM or CorMem
ImagePath: *\CorMem.sys

EventID: 6 (Sysmon) - Driver loaded
ImageLoaded: *\CorMem.sys
```

#### Device Access
```
File object creation targeting: \Device\CORMEM
DeviceIoControl calls to: \\.\CORMEM
```

#### Suspicious IOCTL Patterns
```
Rapid sequences of:
- IOCTL 0x22201C (LinearToPhys) followed by 0x22200C (MapBuffer) = kernel R/W chain
- IOCTL 0x222014/0x222018 (ReadIo/WriteIo) to ports 0xCF8/0xCFC = PCI config access
- IOCTL 0x22203C (AllocPhysMem) + 0x222044 (MapPhysMem) = memory allocation chain
```

#### YARA Rule
```yara
rule BYOVD_CorMem_Driver
{
    meta:
        description = "Teledyne DALSA CorMem.sys - BYOVD capable driver"
        author = "Analyst"
        severity = "Critical"
        
    strings:
        $device = "\\Device\\CORMEM" wide
        $symlink = "\\DosDevices\\CORMEM" wide
        $physmem = "\\Device\\PhysicalMemory" wide
        $src1 = "cormem.c" ascii
        $src2 = "corlibk.c" ascii
        $version = "9.00" ascii
        $dbg1 = "CORMEM.SYS:" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        ($device or $symlink) and
        ($physmem or $src1) and
        any of ($dbg1, $version)
}
```

### Mitigation Strategies

| Mitigation | Effectiveness | Implementation |
|-----------|--------------|----------------|
| **HVCI (Hypervisor-protected Code Integrity)** | High | Blocks unsigned/vulnerable driver loading (if driver is blocklisted) |
| **Microsoft Vulnerable Driver Blocklist** | High | Submit hash for inclusion in `DriverSiPolicy.p7b` |
| **WDAC (Windows Defender Application Control)** | High | Block driver by hash, publisher, or file name |
| **ASR Rules** | Medium | Block driver installation by non-admin processes |
| **EDR driver load monitoring** | Medium | Alert on CorMem.sys loading outside expected environments |
| **Remove from DALSA SDK installations** | High | Uninstall driver if Sapera LT not actively required |
| **Restrict device object ACL** | Partial | Requires driver modification — not practical for BYOVD |

### Driver Hash Collection

For blocklist submissions, collect:
- SHA-256 hash of CorMem.sys
- Authenticode signature thumbprint
- Version resource details
- All known versions from Sapera LT SDK releases (7.x, 8.x, 9.x)

---

## 12. Technical Summary

CorMem.sys is a **textbook BYOVD target** that provides the complete set of kernel exploitation primitives through a clean, well-structured IOCTL interface. The driver's legitimate purpose — managing DMA-capable memory for industrial frame grabbers — requires these dangerous capabilities by design. However, the complete absence of access control makes it trivially exploitable by any process on the system.

**Key statistics:**
- **6 critical-severity IOCTLs** providing direct hardware/memory access
- **26 total IOCTL handlers** covering memory allocation, mapping, I/O, and status queries
- **Zero security checks** on device open or IOCTL dispatch
- **Both 32-bit and 64-bit** process support (WOW64 aware)
- **Cleanly signed** as part of a legitimate industrial SDK
- **Self-contained** — no dependencies on other Sapera components for exploitation

The driver represents one of the most capable BYOVD targets available, exceeding the functionality of most publicly documented vulnerable drivers by combining physical memory mapping, I/O port access, address translation, and physical memory allocation in a single binary.
