# PS5 Hypervisor Bypass Research

## Executive Summary

This document analyzes the current state of PS5 security research, comparing the Byepervisor implementation (FW 1.xx-2.50) with kstuff, and explores potential exploitation paths via mast1c0re and PSP game saves.

---

## 1. Understanding the Security Layers

### PS5 Security Architecture (Ring Model)

```
Ring -3: AMD PSP (Platform Security Processor)
         └─ Secure boot, key management, crypto operations

Ring -2: SMM (System Management Mode)
         └─ BIOS-level operations, power management

Ring -1: Hypervisor
         └─ VM isolation, memory virtualization, SMAP/XOM enforcement

Ring 0:  FreeBSD Kernel (Guest OS)
         └─ Process management, syscalls, drivers

Ring 3:  Userland
         └─ Games, apps, web browser
```

### What Each Layer Controls

| Layer | Controls | Current Exploit Status |
|-------|----------|----------------------|
| PSP | Hardware keys, secure boot chain, SoC init | **No public exploits** |
| Hypervisor | NPT (Nested Page Tables), XOM, SMAP, GMET | **Exploited up to FW 2.xx** (Byepervisor) |
| Kernel | Process isolation, memory protection, syscalls | **Exploited up to FW 10.40** |
| Userland | App sandboxing, JIT permissions | **Multiple entry points** |

---

## 2. Byepervisor vs Kstuff: Detailed Comparison

### Byepervisor (FW 1.xx - 2.50)

**What It Is:** A true hypervisor exploit that achieves code execution in Ring -1

**How It Works:**
1. Exploits shared jump tables between hypervisor and guest kernel
2. Hijacks `VMMCALL_HV_SET_CPUID_PS4` hypercall entry
3. Runs ROP chain in hypervisor context
4. Disables Nested Paging (NPT) and Guest Mode Execute Trap (GMET)
5. Allows disabling eXecute Only Memory (XOM) in kernel PTEs

**Capabilities:**
```
✓ Full hypervisor code execution
✓ Disable hardware-enforced XOM (code pages become readable)
✓ Disable GMET (execute arbitrary code without traps)
✓ Modify NPT (full control over physical memory virtualization)
✓ Bypass SMAP at hardware level
✓ Potential bootloader modification
✓ True "jailbreak" - hardware-level security disabled
```

**Current Implementation in etaHEN (Source Code/bootstrapper/Byepervisor/):**
```cpp
// From main.cpp - The Byepervisor flow
bool Byepervisor() {
    // 1. Set shellcore auth (privilege escalation)
    kernel_set_ucred_authid(getpid(), 0x4800000000000007);

    // 2. Clear XOTEXT bit - make kernel text RW
    for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
        CLEAR_PDE_BIT(pte, XOTEXT);  // Remove execute-only
        SET_PDE_BIT(pte, RW);         // Enable write
    }

    // 3. Copy HEN binary to kernel code cave
    kernel_copyin(&KELF[i], kdlsym(KERNEL_SYM_CODE_CAVE) + i, 0x1000);

    // 4. Install kexec syscall (replaces syscall 0x11)
    install_kexec();

    // 5. Execute HEN in kernel context
    kexec(kdlsym(KERNEL_SYM_CODE_CAVE));
}
```

### Kstuff (Current - All Supported FW)

**What It Is:** A kernel-level FSELF/FPKG handler that runs as a signed module

**How It Works:**
1. Loaded as binary blob after kernel exploit
2. Hooks specific syscalls for FSELF authentication
3. Provides fake auth info for unsigned executables
4. Bypasses DRM/license checks for FPKGs

**Capabilities:**
```
✓ Load unsigned ELF files (FSELF)
✓ Install fake packages (FPKG)
✓ Bypass license/RIF validation
✓ Run homebrew applications

✗ Cannot read kernel code (XOM still enforced on FW 3.xx+)
✗ Cannot modify hypervisor state
✗ Limited to software-level bypasses
✗ SMAP still enforced at hypervisor level
```

**Pause/Resume Mechanism (daemon/source/msg.cpp):**
```cpp
void pause_resume_kstuff(bool pause) {
    // Modifies syscall argument count to enable/disable
    // 0xffff = paused, 0xdeb7 = active
    kernel_copyin(&value, sysentvec + syscall_offset, 2);
}
```

### Comparison Table

| Feature | Byepervisor (≤2.50) | Kstuff (3.xx+) |
|---------|---------------------|----------------|
| **Execution Level** | Ring -1 (Hypervisor) | Ring 0 (Kernel) |
| **XOM Bypass** | Hardware disable | Software hooks |
| **SMAP Bypass** | Full | Kernel primitives only |
| **Code Reading** | Full kernel dump | Cannot read code |
| **Persistent** | Survives some reboots | Session-based |
| **FPKG Support** | Yes | Yes |
| **FSELF Support** | Yes | Yes |
| **Kernel Dumping** | Full | Data only |
| **HV Modification** | Yes | No |

---

## 3. What a Full Hypervisor Bypass Enables

### Currently Possible (Byepervisor FW ≤2.50)

1. **Kernel Code Dumping**
   - Read decrypted kernel text
   - Analyze system calls, find new vulns
   - Reverse engineer Sony's security checks

2. **True Code Execution**
   - Run any code without signature checks
   - No need for ROP chains after initial exploit
   - Direct function calls in kernel

3. **Hardware Feature Access**
   - Modify CPU virtualization settings
   - Access performance counters
   - Potential GPU compute unlocking

4. **Secure Memory Access**
   - Read/write protected memory regions
   - Access inter-VM communication buffers
   - Potential sflash/NOR access

### What Would Be Possible (FW 3.xx+ HV Exploit)

If Flatz's unreleased FW 4.51 hypervisor exploit (or similar) becomes available:

1. **Unified Jailbreak Experience**
   - Same capabilities as FW ≤2.50
   - Full kernel dump capability
   - Hardware-level security bypass

2. **Better CFI Bypass**
   - Disable Control Flow Integrity at HV level
   - More reliable code execution
   - Simplified payloads

3. **Cross-Firmware Consistency**
   - Single exploit methodology
   - Easier homebrew development
   - More reliable game backups

---

## 4. Mast1c0re Exploitation Path

### What Is Mast1c0re?

Mast1c0re exploits the PS2 emulator on PS4/PS5 to achieve native code execution WITHOUT needing a kernel exploit.

**Key Properties:**
- JIT (Just-In-Time) compilation privilege
- Essentially unpatchable (physical game ownership)
- Persistent entry point
- Works on latest firmware

### Technical Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    MAST1C0RE CHAIN                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. PS2 Game with Exploitable Save                          │
│     └─> Stack buffer overflow in emulator                   │
│                                                             │
│  2. Escape PS2 Sandbox                                      │
│     └─> Control PS2 emulator process (JIT context)          │
│                                                             │
│  3. JIT Code Generation                                     │
│     └─> Write native PS5 code via JIT compiler              │
│                                                             │
│  4. Native Code Execution                                   │
│     └─> Full userland code execution (Ring 3)               │
│                                                             │
│  5. Chain with Kernel Exploit                               │
│     └─> IPV6/UMTX/Lapse for Ring 0                          │
│                                                             │
│  6. Chain with Hypervisor Exploit (if available)            │
│     └─> Byepervisor techniques for Ring -1                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Advantages for Hypervisor Research

1. **Persistent Entry Point**
   - Not patched by firmware updates
   - Always available with physical game
   - Doesn't require WebKit exploit

2. **JIT Privileges**
   - Can generate native code
   - Bypasses userland code signing
   - Better than ROP-only exploitation

3. **Research Platform**
   - Stable environment for testing
   - Reproducible exploitation
   - Debug kernel without WebKit instability

### Implementation Approach

```
Required Components:
├── Exploitable PS2 Game (Okage: Shadow King, others)
├── Corrupted Save File (USB or cloud)
├── Stage 1: PS2 ROP chain
├── Stage 2: JIT payload generator
├── Stage 3: Native shellcode
└── Stage 4: Kernel exploit loader
```

---

## 5. PSP Game Save Exploitation Path

### Concept

Similar to mast1c0re, but targeting PS4's PSP emulator (for PSP Classics).

### Current Status

**Less Explored Than PS2:**
- PSP emulator is different architecture
- Fewer known exploitable games
- Different save format

**Potential Advantages:**
- Alternative entry point
- May have different security assumptions
- PSP games have known save exploits

### Research Approach

```
Investigation Steps:
1. Identify PSP Classics on PS Store
2. Research known PSP save exploits (PSP homebrew scene)
3. Test if exploits work in PS4/PS5 emulator
4. Analyze emulator sandboxing
5. Develop escape techniques
```

### Known PSP Save Exploits (Historical)

| Game | Exploit Type | Firmware |
|------|--------------|----------|
| TIFF Exploit | Image parser overflow | PSP 2.00 |
| Lumines | Save game overflow | PSP 2.60 |
| GTA:LCS | Save game overflow | PSP 2.00 |
| Patapon 2 | Demo save exploit | PSP 6.20 |

**Note:** These may not directly translate to PS4/PS5 emulator exploitation.

---

## 6. Recommended Research Priorities

### High Priority (Actionable Now)

1. **Mast1c0re Integration**
   ```
   - Set up PS2 exploit chain
   - Test on current FW
   - Chain with existing kernel exploits
   - Document as alternative entry point
   ```

2. **Kernel Exploit Documentation**
   ```
   - Document IPV6/UMTX exploit flow
   - Map to etaHEN implementation
   - Identify adaptation points for new FW
   ```

3. **Byepervisor Analysis**
   ```
   - Deep dive into HV jump table hijack
   - Understand FW 3.xx changes that broke it
   - Identify potential similar vectors
   ```

### Medium Priority (Research Required)

4. **FW 3.xx+ Hypervisor Analysis**
   ```
   - Monitor Flatz/community releases
   - Analyze HV changes in FW 3.00
   - Document new security measures
   ```

5. **PSP Emulator Investigation**
   ```
   - Identify available PSP Classics
   - Test known exploits
   - Analyze emulator sandbox
   ```

### Long-term (Advanced Research)

6. **PSP Secure Processor**
   ```
   - Understand AMD PSP architecture
   - Monitor academic research
   - Hardware glitching research
   ```

---

## 7. Technical Deep Dive: Memory Mirroring Attack

The current etaHEN Byepervisor uses a clever paging attack to access kernel memory:

### mirror.cpp Analysis

```cpp
void *mirror_page(uint64_t kernel_va) {
    // 1. Extract kernel physical address
    kernel_pa = pmap_kextract(kernel_va);

    // 2. Allocate user-space page
    user_mirror = mmap(0, 0x4000, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    // 3. Prefault to ensure PTE exists
    *(uint64_t *)(user_mirror) = 0x40404040;

    // 4. Remap user page to kernel physical address
    orig_pa = remap_page(pmap, (uint64_t)user_mirror, kernel_pa);

    // Result: user_mirror now points to kernel memory!
}
```

### paging.cpp: Page Table Manipulation

```cpp
uint64_t remap_page(uint64_t pmap, uint64_t va, uint64_t new_pa) {
    // Find the Page Table Entry for user VA
    pte_addr = find_pte(pmap, va, &pte);

    // Replace physical address in PTE
    SET_PDE_ADDR(pte, new_pa);

    // Write modified PTE back
    kernel_copyin(&pte, pte_addr, sizeof(pte));

    // User VA now maps to kernel PA!
}
```

### Why This Works (FW ≤2.50)

1. **No NPT Enforcement**: Hypervisor doesn't validate guest page tables
2. **Shared Address Space**: Kernel and user share same pmap structure
3. **Direct Physical Access**: DMAP provides linear physical memory map

### Why This Fails (FW 3.xx+)

1. **NPT Active**: Hypervisor validates all memory accesses
2. **GMET Enabled**: Guest modifications trigger hypervisor traps
3. **Hardened SMAP**: User pages can't map kernel physical memory

---

## 8. APIC Suspend/Resume Attack Vector (Flatz Technique)

### Overview

This technique, shared directly by Flatz, exploits the timing window during suspend/resume
cycles to execute code BEFORE the hypervisor restarts. This is potentially applicable to
FW 3.xx+ where other HV exploits are patched.

### Technical Details

**The Vulnerability:**
```
struct apic_ops is located in the kernel .data segment (RW permissions)
With KRW (kernel read/write), you can overwrite function pointers inside it
```

**Target Structure (from FreeBSD apicvar.h):**
```c
// Note: Removed from FreeBSD mainline in 2022 (commit e0516c7553da)
// PS5's FreeBSD fork (based on older version) still has it
// Full structure has ~28 function pointers (224 bytes on x86_64)

struct apic_ops {
    // Core APIC operations
    void (*create)(u_int, int);
    void (*init)(vm_paddr_t);
    void (*xapic_mode)(void);           // <-- TARGET: offset 0x10
    bool (*is_x2apic)(void);
    void (*setup)(int);
    void (*dump)(const char *);
    void (*disable)(void);
    void (*eoi)(void);

    // ID and status
    int  (*id)(void);
    int  (*intr_pending)(u_int);
    void (*set_logical_id)(u_int, u_int, u_int);
    u_int (*cpuid)(u_int);

    // Vector management
    u_int (*alloc_vector)(u_int, u_int);
    u_int (*alloc_vectors)(u_int, u_int *, u_int, u_int);
    void (*enable_vector)(u_int, u_int);
    void (*disable_vector)(u_int, u_int);
    void (*free_vector)(u_int, u_int, u_int);

    // PMC, CMC, ELVT operations
    int  (*enable_pmc)(void);
    void (*disable_pmc)(void);
    void (*reenable_pmc)(void);
    void (*enable_cmc)(void);
    int  (*enable_mca_elvt)(void);

    // IPI operations
    void (*ipi_raw)(register_t, u_int);
    void (*ipi_vectored)(u_int, int);
    int  (*ipi_wait)(int);
    int  (*ipi_alloc)(inthand_t *);
    void (*ipi_free)(int);

    // LVT operations
    int  (*set_lvt_mask)(u_int, u_int, u_char);
    int  (*set_lvt_mode)(u_int, u_int, u_int32_t);
    int  (*set_lvt_polarity)(u_int, u_int, enum intr_polarity);
    int  (*set_lvt_triggermode)(u_int, u_int, enum intr_trigger);
};

// Scanner note: Look for ~28 consecutive kernel .text pointers in .data
// Known FW 4.03 reference offset: allproc @ 0x27EDCB8
```

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                 APIC SUSPEND/RESUME ATTACK                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PHASE 1: SETUP (Before Suspend)                                 │
│  ─────────────────────────────────                              │
│  1. Gain kernel R/W via IPV6/UMTX/Lapse exploit                  │
│  2. Locate apic_ops structure in kernel .data                    │
│  3. Prepare ROP chain payload                                    │
│  4. Overwrite xapic_mode function pointer → ROP gadget           │
│  5. Bypass CFI (required - this is the challenge)                │
│  6. Trigger system suspend (rest mode)                           │
│                                                                  │
│  PHASE 2: EXECUTION (During Resume)                              │
│  ──────────────────────────────────                              │
│  7. System resumes from rest mode                                │
│  8. Kernel initializes BEFORE hypervisor restarts                │
│  9. Kernel calls apic_ops->xapic_mode()                          │
│  10. Our ROP chain executes in pre-HV context                    │
│  11. Apply kernel patches (XOM disable, code patches)            │
│  12. Hypervisor starts but protections already bypassed          │
│                                                                  │
│  PHASE 3: POST-EXPLOIT                                           │
│  ─────────────────────────                                       │
│  13. Re-run exploit payload after resume                         │
│  14. Full kernel access with HV protections disabled             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Works

The critical insight is the **timing window**:

```
Normal Boot Sequence:
  PSP Init → Bootloader → Hypervisor → Kernel
                              ↑
                     HV enforces XOM/NPT

Resume Sequence:
  PSP Resume → Kernel Resume → Hypervisor Resume
                    ↑
        CODE EXECUTES HERE (no HV protection yet!)
```

During resume, the kernel reinitializes hardware (including APIC) before the
hypervisor is fully operational. This creates a window where:

1. Kernel code runs without HV oversight
2. Page table modifications aren't validated by NPT
3. XOM enforcement isn't active yet

### CFI Bypass Challenge

The main obstacle is Control Flow Integrity (CFI):

```
CFI Check Flow:
  call [function_ptr]
    → CFI validates target is legitimate function
    → If invalid, triggers kernel panic via cfi_check_fail()
```

**Potential CFI Bypass Approaches:**

1. **Find CFI-Compatible Gadget**
   ```
   Look for existing kernel functions that:
   - Are valid CFI targets
   - Perform useful operations (stack pivot, etc.)
   - Can chain to ROP payload
   ```

2. **Corrupt CFI Metadata**
   ```
   If CFI tables are in writable memory, modify them
   to mark our target as valid
   ```

3. **Use Legitimate Function as Trampoline**
   ```
   Point to real function that eventually calls
   user-controlled pointer without CFI check
   ```

4. **Race CFI Initialization**
   ```
   During resume, CFI might not be fully initialized
   when APIC code runs - needs testing
   ```

### FW 4.03 Discovered Offsets

**Found via kernel .data dump analysis (January 2025):**

```
apic_ops offset:        0x170650 (from kernel .data base)
xapic_mode offset:      apic_ops + 0x10 (3rd pointer in struct)

Full structure dump at 0x170650:
  [0] create:          0xffffffffd2d889a6
  [1] init:            0xffffffffd2dfa321
  [2] xapic_mode:      0xffffffffd2e3bcca  <-- TARGET
  [3] is_x2apic:       0xffffffffd2e61b33
  [4] setup:           0xffffffffd2e0cc4b
  [5] dump:            0xffffffffd2de6afa
  [6] disable:         0xffffffffd2dada30
  [7] eoi:             0xffffffffd2d5a27e
  ... (28 total function pointers)
```

**To use in exploit:**
```c
uint64_t kdata_base = /* get from exploit */;
uint64_t apic_ops = kdata_base + 0x170650;
uint64_t xapic_mode_ptr = apic_ops + 0x10;

// Overwrite with ROP gadget (requires CFI bypass)
kernel_write8(xapic_mode_ptr, rop_gadget_addr);

// Trigger suspend -> resume executes our code before HV
```

### Current Status

Per Flatz:
> "By the way, it's not the method that has been patched in 5.00.
> Actually I'm not even sure if has been patched at all, needs testing"

**This means:**
- Potentially works on FW 3.xx - 4.51+
- May even work on newer firmware
- Requires testing and CFI bypass development

### Integration with etaHEN

The current Byepervisor already uses suspend/resume! See `main.cpp`:

```cpp
// Check if this is a resume state
if (kernel_read4(kdlsym(KERNEL_SYM_DATA_CAVE)) != 0x1337) {
    // First run - set flag and trigger suspend
    kernel_write4(kdlsym(KERNEL_SYM_DATA_CAVE), 0x1337);
    flash_notification("[etaHEN] Entering rest mode...");
    sceSystemStateMgrEnterStandby();
    return false;
}
// Second run (after resume) - exploit continues
```

The APIC technique could be integrated as an alternative code path for FW 3.xx+.

### Research Tasks

```
COMPLETED:
├── ✅ Locate apic_ops in PS5 kernel (FW 4.03)
│   └── Offset: 0x170650 from kernel .data base
├── ✅ Verify structure still exists
│   └── Confirmed: 28 function pointers, matches FreeBSD apic_ops
├── ✅ Map function pointer offsets
│   └── xapic_mode at struct offset 0x10 (position [2])
└── ✅ Document full structure with addresses

High Priority (REMAINING):
├── Identify CFI bypass candidates
│   └── Options: JIT spray, race condition, or find unchecked call
├── Test timing window during resume
│   └── Verify CFI state when xapic_mode is called
├── Find usable ROP gadgets (XOM blocks .text reading)
└── Build proof-of-concept

Medium Priority:
├── Develop ROP chain for pre-HV context
├── Test on multiple firmware versions
├── Document any firmware-specific differences
└── Create proof-of-concept payload

Integration:
├── Add apic_ops offset to kdlsym tables
├── Implement APIC overwrite in Byepervisor
├── Add CFI bypass code
└── Test full exploit chain
```

---

## 9. Additional Attack Vectors

### A. Hypercall Interface Analysis

FW 3.xx moved hypervisor out of kernel, but hypercalls still exist:

```
Research Areas:
├── VMMCALL instruction usage
├── Hypercall argument validation
├── Cross-VM communication
└── HV service routines
```

### B. Hardware Feature Abuse

```
Potential Targets:
├── AMD SEV (Secure Encrypted Virtualization)
├── SME (Secure Memory Encryption)
├── Performance counters
└── Debug registers (if accessible)
```

### C. Race Conditions

```
Timing Windows:
├── HV ↔ Guest context switches
├── Interrupt handling
├── Page table updates
└── JIT compilation windows
```

### D. Other Kernel Structures in RW Segments

Following Flatz's pattern, look for other exploitable structures:

```
Potential Targets:
├── Other *_ops structures (console_ops, bus_ops, etc.)
├── Callback tables
├── Interrupt handlers
├── Timer callbacks
└── Any function pointer in .data segment
```

---

## 10. Resources & References

### Official Byepervisor
- GitHub: https://github.com/PS5Dev/Byepervisor
- Presented at hardwear.io NL 2024

### Mast1c0re
- CTurt's writeup: https://cturt.github.io/mast1c0re.html
- Part 1: PS2 emulator escape
- Part 2: (Unreleased) Further exploitation

### Recent Kernel Exploits
- Lapse (FW ≤10.40): TheFloW, disclosed 2025-04-18
- IPV6 Kernel Exploit: Cryptogenic
- UMTX Exploit: FreeBSD-based

### PS5 Security Research
- PS5 Dev Wiki: https://www.psdevwiki.com/ps5/
- Wololo news: https://wololo.net/

---

## 11. Conclusion

### Current State

| Firmware | Kernel Exploit | HV Exploit | Full JB |
|----------|---------------|------------|---------|
| 1.xx-2.50 | Yes | Yes (Byepervisor) | **Yes** |
| 3.xx-4.51 | Yes | Private (Flatz) | Partial |
| 5.xx-10.40 | Yes | No | Partial |
| 10.60+ | Unknown | No | No |

### Recommended Path Forward

1. **Immediate**: Set up mast1c0re as stable entry point
2. **Short-term**: Document current Byepervisor for educational purposes
3. **Medium-term**: Monitor community for FW 3.xx+ HV exploit releases
4. **Long-term**: Investigate new HV attack surfaces

### Key Insight

The difference between "kernel jailbreak" (kstuff) and "true jailbreak" (Byepervisor) is significant:
- **Kstuff**: Software workarounds, limited capabilities
- **Byepervisor**: Hardware-level control, full system access

For FW 3.xx+, the community is effectively "kernel jailbroken" but not "hypervisor jailbroken" - which limits advanced capabilities like kernel dumping and hardware feature access.
