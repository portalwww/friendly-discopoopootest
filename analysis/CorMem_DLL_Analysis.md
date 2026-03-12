# CorMem.dll — Full Reverse Engineering Analysis & BYOVD Assessment

## 1. Executive Summary

**CorMem.dll** is a user-mode companion DLL for the **CorMem.sys** kernel driver, both part of the **Teledyne DALSA Sapera LT** industrial imaging framework. The DLL acts as a thin wrapper that sends IOCTL commands to the `\\.\CORMEM` kernel device, providing user-mode applications with direct access to:

- **Physically contiguous memory allocation/deallocation**
- **Physical ↔ Kernel ↔ User-mode address translation**
- **Physical memory read/write (I/O port access)**
- **MDL creation and memory locking**
- **Scatter-gather buffer management**
- **Physical memory mapping into user-space**

The driver exposes **extremely dangerous primitives** — arbitrary physical memory read, write, and mapping — making both CorMem.sys and this DLL high-value BYOVD (Bring Your Own Vulnerable Driver) targets.

---

## 2. Binary Metadata

| Property | Value |
|---|---|
| **Filename** | CorMem.dll |
| **Type** | 64-bit Windows DLL (x86-64) |
| **Build Path** | `D:\Jenkins\jobs\SaperaLTBuild\workspace\Pdb\x64\CorMem.pdb` |
| **Source Path** | `d:\jenkins\jobs\SaperaLTBuild\workspace\externals\CorLib\SharedMutex.c` |
| **Vendor** | Teledyne DALSA (formerly Coreco Imaging) |
| **Product** | Sapera LT SDK — Memory Management Module |
| **Device Name** | `\\.\CORMEM` |
| **Mutex Name** | `CORECO_CORMEM_DLL_MUTEX` |
| **Imports From** | KERNEL32, USER32, ADVAPI32, CorLog.dll, VCRUNTIME140 |

---

## 3. Architecture Overview

```
┌─────────────────────────┐
│  User-mode Application  │
│  (Sapera LT / Attacker) │
└────────────┬────────────┘
             │ LoadLibrary / Direct calls
             ▼
┌─────────────────────────┐
│      CorMem.dll         │
│  (User-mode wrapper)    │
│                         │
│  - Mutex synchronization│
│  - Address translation  │
│    (Phys↔Kernel↔User)   │
│  - IOCTL dispatch       │
└────────────┬────────────┘
             │ DeviceIoControl → \\.\CORMEM
             ▼
┌─────────────────────────┐
│     CorMem.sys          │
│  (Kernel-mode driver)   │
│                         │
│  - Physical mem alloc   │
│  - DMA buffer mgmt      │
│  - I/O port R/W         │
│  - MDL create/lock      │
│  - Phys mem mapping     │
└─────────────────────────┘
```

---

## 4. Initialization Flow

### 4.1 DllMain (DLL_PROCESS_ATTACH)

```
DllMain(DLL_PROCESS_ATTACH):
  1. Create shared mutex "CORECO_CORMEM_DLL_MUTEX" with NULL DACL
     → Security descriptor allows ALL access (no ACL restrictions)
  2. Call sub_180002220() to open the driver device
  3. Increment global reference counter (InterlockedIncrement)
```

### 4.2 Driver Device Connection — `sub_180002220`

```c
hDevice = CreateFileA("\\\\.\\CORMEM", 0xC0000000, 0, 0, OPEN_EXISTING, 
                      FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, 0);
```

If the device cannot be opened, a `MessageBoxA` displays:
> *"Cannot find driver CORMEM.SYS (memory allocator)!"*

After opening, the DLL:
1. Calls `CorMemGetPoolBlockCount()` → IOCTL `0x22205C` to get the number of contiguous memory pool blocks
2. Validates block count ≤ 257 (`0x101`)
3. Iterates through each pool block, calling `CorMemMapPool()` → IOCTL `0x222000` to retrieve and cache physical, kernel, user addresses + sizes in a global lookup table

### 4.3 DllMain (DLL_PROCESS_DETACH)

```
DllMain(DLL_PROCESS_DETACH):
  1. Acquire the mutex
  2. Unmap all pool buffer mappings via CorMemUnmapBuffer
  3. CloseHandle(hDevice)
  4. Decrement reference counter
  5. Release and close mutex
```

### 4.4 NULL DACL Security Descriptor

The `sub_180001290` function creates a security descriptor for the shared mutex by calling:
```c
InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);  // NULL DACL = everyone full access
```

This means **any user on the system** can interact with the mutex — there is no privilege separation on the synchronization primitive.

---

## 5. Global Address Translation Table

On initialization, the DLL populates a global lookup table (up to 257 entries) at address `0x180007050`. Each 32-byte entry stores:

| Offset | Field | Description |
|--------|-------|-------------|
| +0x00 (`unk_180007050`) | Physical Address | Base physical address of the pool block |
| +0x08 (`unk_180007058`) | Kernel Address | Kernel virtual address mapping |
| +0x10 (`unk_180007060`) | User Address | User-space virtual address mapping |
| +0x18 (`unk_180007068`) | Size | Size of the memory block in bytes |

This table enables the following **client-side** (no IOCTL needed) address translation functions:

| Function | Translation |
|----------|------------|
| `CorMemMapPhysToKernel(phys)` | Physical → Kernel VA |
| `CorMemMapPhysToUser(phys)` | Physical → User VA |
| `CorMemMapKernelToPhys(kva)` | Kernel VA → Physical |
| `CorMemMapKernelToUser(kva)` | Kernel VA → User VA |
| `CorMemMapUserToKernel(uva)` | User VA → Kernel VA |
| `CorMemMapUserToPhys(uva)` | User VA → Physical |

Each translation function iterates through the table, finds the matching pool block based on address range, and computes the offset to the target address space.

---

## 6. Complete IOCTL Reference

All IOCTLs target device type `0x22` (FILE_DEVICE_UNKNOWN), function range `0x800+`, using METHOD_BUFFERED and FILE_ANY_ACCESS. The base IOCTL formula: `CTL_CODE(0x22, FuncCode, METHOD_BUFFERED, FILE_ANY_ACCESS)`.

### 6.1 Pool & Buffer Management

| IOCTL Code | Function | In Size | Out Size | Description |
|-----------|----------|---------|----------|-------------|
| `0x222000` | `CorMemMapPool` | 4 | 0x1C | Query pool block info (phys addr, kernel addr, user addr, size) by index |
| `0x22200C` | `CorMemMapBufferEx` | 0x18 | 8 | Map a physical buffer into user-space; returns user VA |
| `0x222010` | `CorMemUnmapBuffer` | 8 | 0 | Unmap a previously mapped buffer |

### 6.2 I/O Port Read/Write

| IOCTL Code | Function | In Size | Out Size | Description |
|-----------|----------|---------|----------|-------------|
| **`0x222014`** | **`CorMemReadIo`** | 0xC | 4 | **Read from physical I/O port** — takes (size, phys_addr) |
| **`0x222018`** | **`CorMemWriteIo`** | 0x10 | 0 | **Write to physical I/O port** — takes (size, phys_addr, value) |

### 6.3 Address Translation

| IOCTL Code | Function | In Size | Out Size | Description |
|-----------|----------|---------|----------|-------------|
| `0x22201C` | `CorMemLinearToPhys` | 8 | 8 | Translate a linear (virtual) address to physical address |

### 6.4 Scatter-Gather Buffer Locking

| IOCTL Code | Function | In Size | Out Size | Description |
|-----------|----------|---------|----------|-------------|
| `0x222020` | `CorMemFreeBuffer` | 8 | 0 | Free a contiguous buffer (takes phys addr) |
| `0x222024` | `CorMemLockSGBuffer` | 0x1C | 0xC | Lock scatter-gather buffer; returns descriptor + count |
| `0x222028` | `CorMemUnlockSGBuffer` | 8 | 0 | Unlock a scatter-gather buffer |
| `0x22202C` | `CorMemUnlockAllSGBuffer` | 0 | 0 | Unlock all scatter-gather buffers |

### 6.5 Contiguous Memory Allocation

| IOCTL Code | Function | In Size | Out Size | Description |
|-----------|----------|---------|----------|-------------|
| `0x222030` | `CorMemAllocBufferExEx` | 0x10 | 0x10 | Allocate contiguous buffer (standard) |
| `0x222034` | `CorMemAllocMsgEx` | 0x10 | 0x10 | Allocate messaging buffer |
| `0x222038` | `CorMemGetMessagingBoundaryUser` | 0 | 8 | Get messaging memory boundary (user VA) |

### 6.6 Physical Memory Operations

| IOCTL Code | Function | In Size | Out Size | Description |
|-----------|----------|---------|----------|-------------|
| **`0x22203C`** | **`CorMemAllocPhysMemory`** | 0x20 | 0x10 | **Allocate physical memory** — takes 4 QWORDs |
| **`0x222040`** | **`CorMemFreePhysMemory`** | 8 | 0 | **Free physical memory** |
| **`0x222044`** | **`CorMemMapPhysMemory`** | 8 | 8 | **Map physical address to accessible memory** |
| **`0x222048`** | **`CorMemUnmapPhysMemory`** | 0x10 | 0 | **Unmap physical memory** |
| **`0x22204C`** | **`CorMemGetPhysMemory`** | 0x14 | 4 | **Read physical memory** — takes (phys_addr, size, flags) |

### 6.7 Status & Information

| IOCTL Code | Function | In Size | Out Size | Description |
|-----------|----------|---------|----------|-------------|
| `0x222050` | `CorMemGetBufferMemStatus` | 0 | 0x1C | Query buffer pool memory status |
| `0x222054` | `CorMemGetMsgMemStatus` | 0 | 0x1C | Query messaging pool memory status |
| `0x222058` | `CorMemCreateMdlAndLockForVirtualBuffer` | 0x10 | 8 | Create MDL for virtual buffer and lock in memory |
| `0x22205C` | `CorMemGetPoolBlockCount` | 0 | 4 | Get number of contiguous memory pool blocks |
| `0x222060` | `CorMemGetPhysMemory_64` | 0x14 | 4 | Read physical memory (64-bit variant) |
| `0x222064` | `CorMemAllocBuffer64Ex` | 0x10 | 0x10 | Allocate contiguous buffer (64-bit addresses) |
| `0x222068` | `CorMemGetBuffer64MemStatus` | 0 | 0x2C | Query 64-bit buffer pool memory status |

---

## 7. Exported Functions (30 total)

### Memory Allocation
| Export | Wraps To | IOCTL |
|--------|----------|-------|
| `CorMemAllocBuffer(size, &phys, &user)` | CorMemAllocBufferExEx | `0x222030` |
| `CorMemAllocBufferEx(size, flags, align, &phys, &user)` | CorMemAllocBufferExEx | `0x222030` |
| `CorMemAllocBufferExEx(size, flags, align, &phys, &user)` | — | `0x222030` |
| `CorMemAllocBuffer64Ex(size, flags, align, &phys, &user)` | — | `0x222064` |
| `CorMemAllocMsg(size, &phys, &user)` | CorMemAllocMsgEx | `0x222034` |
| `CorMemAllocMsgEx(size, flags, align, &phys, &user)` | — | `0x222034` |
| `CorMemAllocPhysMemory(a1, a2, a3, a4, &out)` | — | `0x22203C` |

### Memory Deallocation
| Export | IOCTL |
|--------|-------|
| `CorMemFreeBuffer(user_addr)` | `0x222020` |
| `CorMemFreeMsg(user_addr)` | `0x222020` (thunk to FreeBuffer) |
| `CorMemFreePhysMemory(phys_addr)` | `0x222040` |

### Memory Mapping
| Export | IOCTL |
|--------|-------|
| `CorMemMapBuffer(phys, size)` | `0x22200C` |
| `CorMemMapBufferEx(phys, size, flags)` | `0x22200C` |
| `CorMemMapPhysMemory(phys, &user)` | `0x222044` |
| `CorMemMapPool(idx, &kern, &phys, &user, &size)` | `0x222000` |
| `CorMemUnmapBuffer(user_addr)` | `0x222010` |
| `CorMemUnmapPhysMemory(user, phys)` | `0x222048` |

### Address Translation (Client-side, no IOCTL)
| Export | Translation |
|--------|------------|
| `CorMemMapPhysToKernel(phys)` | Physical → Kernel |
| `CorMemMapPhysToUser(phys)` | Physical → User |
| `CorMemMapKernelToPhys(kern)` | Kernel → Physical |
| `CorMemMapKernelToUser(kern)` | Kernel → User |
| `CorMemMapUserToKernel(user)` | User → Kernel |
| `CorMemMapUserToPhys(user)` | User → Physical |
| `CorMemLinearToPhys(va)` | Virtual → Physical (via driver `0x22201C`) |

### I/O Port Access
| Export | IOCTL |
|--------|-------|
| `CorMemReadIo(phys_addr, size, &value)` | `0x222014` |
| `CorMemWriteIo(phys_addr, size, value)` | `0x222018` |

### Scatter-Gather & MDL
| Export | IOCTL |
|--------|-------|
| `CorMemLockSGBuffer(desc, va, flags, ctx, &count, &handle)` | `0x222024` |
| `CorMemUnlockSGBuffer(handle)` | `0x222028` |
| `CorMemUnlockAllSGBuffer()` | `0x22202C` |
| `CorMemCreateMdlAndLockForVirtualBuffer(va, size, &mdl)` | `0x222058` |

### Status Queries
| Export | IOCTL |
|--------|-------|
| `CorMemGetPoolBlockCount(&count)` | `0x22205C` |
| `CorMemGetBufferMemStatus(&status)` | `0x222050` |
| `CorMemGetBuffer64MemStatus(&status)` | `0x222068` |
| `CorMemGetMsgMemStatus(&status)` | `0x222054` |
| `CorMemGetMessagingBoundaryUser()` | `0x222038` |
| `CorMemGetPhysMemory(phys, size, flags, &data)` | `0x22204C` |
| `CorMemGetPhysMemory_64(phys, size, flags, &data)` | `0x222060` |

---

## 8. BYOVD Attack Surface Analysis

### 8.1 Why This Driver/DLL is Dangerous

The CorMem.sys + CorMem.dll pair provides a **complete physical memory exploitation toolkit** from user-mode. The driver was designed for legitimate DMA and frame-grabber hardware operations in the Teledyne DALSA Sapera imaging SDK, but the IOCTLs it exposes are **functionally equivalent to kernel-mode exploitation primitives**.

### 8.2 Critical Attack Primitives

#### Primitive 1: Arbitrary Physical Memory Read
```c
// Read 4 bytes from any physical address
DWORD value;
CorMemReadIo(target_phys_addr, 4, &value);      // IOCTL 0x222014

// OR via the physical memory read interface
DWORD data;
CorMemGetPhysMemory(phys_addr, size, flags, &data);  // IOCTL 0x22204C
```

#### Primitive 2: Arbitrary Physical Memory Write
```c
// Write any value to any physical address
CorMemWriteIo(target_phys_addr, 4, malicious_value); // IOCTL 0x222018
```

#### Primitive 3: Map Arbitrary Physical Memory to User-Space
```c
// Map any physical address range into user-mode process
QWORD user_mapped;
CorMemMapPhysMemory(arbitrary_phys_addr, &user_mapped); // IOCTL 0x222044
// Now read/write kernel memory structures via user_mapped pointer
```

#### Primitive 4: Virtual-to-Physical Translation
```c
// Translate any virtual address to physical (information leak)
QWORD phys = CorMemLinearToPhys(kernel_virtual_addr);  // IOCTL 0x22201C
```

#### Primitive 5: Physical Memory Allocation in Kernel
```c
// Allocate physically contiguous memory visible from kernel
QWORD phys_out, user_out;
CorMemAllocPhysMemory(size, alignment, low, high, &result); // IOCTL 0x22203C
```

#### Primitive 6: MDL Creation and Locking
```c
// Lock arbitrary virtual buffers in physical memory using MDLs
QWORD mdl_handle;
CorMemCreateMdlAndLockForVirtualBuffer(va, size, &mdl_handle); // IOCTL 0x222058
```

### 8.3 BYOVD Attack Scenarios

#### Scenario 1: Disable DSE / Patch the Kernel
1. Use `CorMemLinearToPhys()` to translate known kernel addresses to physical
2. Use `CorMemMapPhysMemory()` to map the kernel's `.text` section into user-space
3. Patch `ci.dll!CiValidateImageHeader` or modify `nt!g_CiEnabled` to disable Driver Signature Enforcement
4. Load unsigned malicious drivers

#### Scenario 2: Token Privilege Escalation
1. Locate the current process EPROCESS via known offsets
2. Use `CorMemLinearToPhys` + `CorMemMapPhysMemory` to map the token structure
3. Overwrite `Token.Privileges` to grant `SeDebugPrivilege`, `SeTcbPrivilege`, etc.
4. OR copy the SYSTEM token to the current process

#### Scenario 3: EDR/AV Bypass via Kernel Callback Removal
1. Enumerate `PsSetCreateProcessNotifyRoutine` callbacks via known kernel offsets
2. Map the callback array into user-space
3. Null out or redirect EDR callback entries
4. Process/thread creation events will no longer be reported to security software

#### Scenario 4: Direct I/O Port Manipulation
1. `CorMemReadIo` / `CorMemWriteIo` provide raw I/O port access
2. Can be used to interact with hardware directly (PCI configuration space, chipset registers)
3. Potentially disable IOMMU or modify hardware security settings

#### Scenario 5: PPL (Protected Process Light) Bypass
1. Map the target protected process's EPROCESS structure via physical memory
2. Clear the `Protection` field to downgrade from PPL
3. Now `OpenProcess` with full access to previously protected processes (lsass.exe, csrss.exe)

### 8.4 Exploitation Advantages

| Advantage | Detail |
|-----------|--------|
| **Signed Driver** | CorMem.sys is legitimately signed by Teledyne DALSA, accepted by Windows |
| **No Admin Check** | The DLL creates device handles with no apparent privilege verification beyond CreateFile |
| **NULL DACL** | Shared mutex uses NULL DACL — no access control |
| **Pre-built API** | Address translation functions already implemented client-side |
| **Stable IOCTLs** | METHOD_BUFFERED IOCTLs are reliable and crash-resistant |
| **Thin wrapper** | The DLL is trivial to reverse and replicate — or use directly via LoadLibrary |

### 8.5 If Only the .sys is Available

An attacker doesn't even need CorMem.dll — the IOCTL interface can be called directly:
```c
HANDLE hDev = CreateFileA("\\\\.\\CORMEM", GENERIC_READ | GENERIC_WRITE, 
                          0, NULL, OPEN_EXISTING, 
                          FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, NULL);

// Direct IOCTL for arbitrary physical read (ReadIo)
struct { int size; QWORD phys_addr; } in = { 4, 0x1000 };
DWORD value, br;
DeviceIoControl(hDev, 0x222014, &in, 0xC, &value, 4, &br, NULL);
```

The DLL merely adds mutex synchronization and the convenience of the address translation lookup table.

---

## 9. Detection & Mitigation

### 9.1 Detection Indicators
- **Driver load**: Monitor for `CorMem.sys` being loaded (service creation or `NtLoadDriver`)
- **Device access**: Watch for handles opened to `\\.\CORMEM`
- **Named mutex**: Creation of `CORECO_CORMEM_DLL_MUTEX`
- **File hashes**: Alert on known CorMem.sys/CorMem.dll hashes
- **IOCTL monitoring**: Flag IOCTLs `0x222014`, `0x222018`, `0x222044`, `0x22204C` (the most dangerous ones)

### 9.2 Mitigation
- **HVCI (Hypervisor-Enforced Code Integrity)**: Prevents unsigned code from executing in kernel, limits physical memory mapping abuse
- **Microsoft Vulnerable Driver Blocklist**: Submit CorMem.sys hash for inclusion
- **ASR rules**: Block unsigned/untrusted driver loads
- **Sysmon**: Monitor driver load events (Event ID 6) and device access

---

## 10. Summary of Dangerous IOCTLs (Quick Reference)

| Danger Level | IOCTL | Primitive | Why It Matters |
|:---:|--------|-----------|----------------|
| 🔴 CRITICAL | `0x222014` | Physical I/O Read | Read any physical address |
| 🔴 CRITICAL | `0x222018` | Physical I/O Write | Write any physical address |
| 🔴 CRITICAL | `0x222044` | Map Physical to User | Map kernel/phys mem to userspace |
| 🔴 CRITICAL | `0x22204C` | Read Physical Memory | Direct physical memory read |
| 🔴 CRITICAL | `0x222060` | Read Phys Mem (64-bit) | 64-bit physical memory read |
| 🟠 HIGH | `0x22201C` | VA-to-Physical Translation | KASLR bypass / info leak |
| 🟠 HIGH | `0x22203C` | Allocate Physical Memory | Kernel memory allocation from usermode |
| 🟠 HIGH | `0x222058` | Create MDL + Lock | Lock arbitrary memory via MDL |
| 🟡 MEDIUM | `0x22200C` | Map Buffer to User | Map driver-managed buffer |
| 🟡 MEDIUM | `0x222030` | Alloc Contiguous Buffer | DMA-capable memory allocation |
| 🟢 LOW | `0x222050` | Query Buffer Status | Information only |
| 🟢 LOW | `0x22205C` | Query Pool Block Count | Information only |

---

## 11. Conclusion

CorMem.dll is a fully functional user-mode interface to the CorMem.sys kernel driver from the Teledyne DALSA Sapera LT imaging SDK. While designed for legitimate industrial camera frame-grabber DMA operations, the driver exposes an extremely permissive set of IOCTLs that grant:

1. **Arbitrary physical memory read/write** — full kernel compromise
2. **Physical memory mapping to user-space** — bypass all kernel protections
3. **Virtual-to-physical address translation** — defeat KASLR
4. **I/O port access** — hardware-level manipulation
5. **MDL creation** — lock and access arbitrary memory regions

These capabilities make CorMem.sys a **top-tier BYOVD target**, comparable to well-known vulnerable drivers like RTCore64.sys (MSI), dbutil_2_3.sys (Dell), and ene.sys. The DLL provides a convenient, already reversed API surface that an attacker can use directly via `LoadLibrary` + `GetProcAddress`, or bypass entirely by issuing raw IOCTLs to the `\\.\CORMEM` device.
