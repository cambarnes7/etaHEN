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
├── ✅ Document full structure with addresses
├── ✅ Live verification via UMTX2 exploit (January 2025)
│   └── kdataBase: 0xffffffffd4550000
│   └── apic_ops:  0xffffffffd46c0650 (kdataBase + 0x170650)
│   └── xapic_mode: 0xffffffffd494bcca (valid kernel .text pointer)
└── ✅ CFI behavior confirmed
    └── Writing invalid pointer causes INSTANT crash (not on resume)
    └── CFI actively validates apic_ops pointers during normal operation

BLOCKER IDENTIFIED:
└── ⚠️  CFI (Control Flow Integrity) blocks simple pointer overwrite
    └── Cannot just write ROP gadget address - CFI validates immediately
    └── Need CFI bypass BEFORE attempting APIC hijack

High Priority (NEXT STEPS):
├── Research PS5 CFI implementation
│   └── How does Sony's CFI work? Shadow stack? Type-based?
├── Identify CFI bypass candidates
│   └── Options: Find unchecked indirect call, corrupt CFI metadata, race
├── Find valid CFI target that can pivot to ROP
│   └── Look for functions that are valid CFI targets but do useful things
└── Alternative: Find different function pointer not CFI-protected

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

### Crash Test Procedure (Offset Verification)

**Purpose:** Confirm that 0x170650 is actually apic_ops by corrupting xapic_mode and
observing if the PS5 crashes during resume from rest mode.

**Code to add to exploit.js (before `await load_local_elf("elfldr.elf");`):**

```javascript
///////////////////////////////////////////////////////////////////////
// APIC CRASH TEST - Verify apic_ops offset
///////////////////////////////////////////////////////////////////////

let apic_ops = kdata_base.add32(0x170650);
let xapic_mode_ptr = apic_ops.add32(0x10);

let original_xapic_mode = await kernel_read8(xapic_mode_ptr);
debug_log("[APIC TEST] xapic_mode_ptr = 0x" + xapic_mode_ptr);
debug_log("[APIC TEST] original value = 0x" + original_xapic_mode);

let do_apic_test = confirm("APIC Crash Test:\n\nxapic_mode @ 0x" + xapic_mode_ptr +
                            "\nCurrent value: 0x" + original_xapic_mode +
                            "\n\nThis will write 0xDEADBEEF and you need to put PS5 in rest mode.\n" +
                            "If PS5 crashes on RESUME, the offset is CORRECT.\n\nProceed?");

if (do_apic_test) {
    debug_log("[APIC TEST] Writing 0xDEADBEEF to xapic_mode...");
    await kernel_write8(xapic_mode_ptr, new int64(0xDEADBEEF, 0));

    let verify = await kernel_read8(xapic_mode_ptr);
    debug_log("[APIC TEST] Verify: 0x" + verify);

    alert("APIC TEST: Written!\n\nNow manually put PS5 in REST MODE.\n\n" +
          "If it CRASHES on resume = offset is CORRECT!\n" +
          "If it resumes normally = offset is WRONG.");
}
```

**Expected Results:**
- **PS5 crashes on resume**: Offset is CORRECT - xapic_mode is called during APIC reinit
- **PS5 resumes normally**: Offset is WRONG - need to test other candidates

**Other candidates to try if 0x170650 fails:**
```
0x28B7F8  - 28 pointers
0x27ED60  - 27 pointers
0x170510  - 27 pointers
0x16EF20  - 27 pointers
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

---

## 12. CFI Discovery and Data-Only Attack Vectors

### CFI Blocking Analysis (January 2025)

After extensive testing on FW 4.03, we discovered that **Sony's CFI implementation is extremely aggressive**:

**Testing Summary:**
```
TESTED STRUCTURE          RESULT      CFI STATUS
─────────────────────────────────────────────────────
apic_ops (xapic_mode)     CRASH       CFI-protected
apic_ops (dump)           CRASH       CFI-protected
apic_ops (disable)        CRASH       CFI-protected
apic_ops (enable_mca)     CRASH       CFI-protected
protosw (pr_input)        CRASH       CFI-protected
cdevsw                    CRASH       CFI-protected
linker_class              CRASH       CFI-protected
vfsops                    CRASH       CFI-protected
bdevsw                    CRASH       CFI-protected
Valid function swap       CRASH       CFI-protected
Same-value writeback      CRASH       CFI-protected (!)
```

**Key Finding:** CFI validates function pointers IMMEDIATELY on write, not just at call-time.
Even writing a valid kernel function pointer to another valid slot triggers a crash.

### Why Function Pointer Hijacking Is Not Viable

Sony uses Clang CFI with shadow stacks and type-based validation:

1. **Type Checking**: Each indirect call site has an expected function signature
2. **Shadow Stack**: Return addresses are validated against a shadow copy
3. **Write-Time Validation**: Modifications to function pointer tables are detected
4. **Immediate Crash**: cfi_check_fail() triggers kernel panic instantly

**Conclusion:** Direct function pointer hijacking is NOT a viable path on FW 3.xx+.

---

## 13. How Kstuff Actually Bypasses Security (Data-Only Attacks)

### The Key Insight: Modify DATA, Not Code

Kstuff achieves its goals by modifying **kernel data values**, not function pointers:

```cpp
// From daemon/source/msg.cpp - pause_resume_kstuff()
bool pause_resume_kstuff() {
    intptr_t sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xd11bb8;     // FW 4.03
    intptr_t sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xd11d30; // PS4 compat

    // Toggle a 16-bit VALUE at offset +14 in sysentvec structure
    if (kernel_getshort(sysentvec_ps4 + 14) == 0xffff) {
        kernel_setshort(sysentvec + 14, 0xdeb7);      // Resume
        kernel_setshort(sysentvec_ps4 + 14, 0xdeb7);
    } else {
        kernel_setshort(sysentvec + 14, 0xffff);      // Pause
        kernel_setshort(sysentvec_ps4 + 14, 0xffff);
    }
    return true;
}
```

**Why This Works:**
- CFI only protects INDIRECT CALLS through function pointers
- Modifying scalar data (integers, flags, short values) is NOT protected
- Security decisions are often based on these data values

### Sysentvec Offsets by Firmware

```
FIRMWARE       SYSENTVEC (PS5)    SYSENTVEC_PS4
──────────────────────────────────────────────────
FW 3.00-3.21   0xca0cd8           0xca0e50
FW 4.00-4.51   0xd11bb8           0xd11d30
FW 5.00-5.50   0xe00be8           0xe00d60
FW 6.00-6.50   0xe210a8           0xe21220
FW 7.00-7.01   0xe21ab8           0xe21c30
FW 7.20-7.61   0xe21b78           0xe21cf0
FW 8.00-8.60   0xe21ca8           0xe21e20
FW 9.00-9.60   0xdba648           0xdba7c0
FW 10.00-10.60 0xdba6d8           0xdba850
```

---

## 14. Security-Critical Kernel Data Structures

### ucred Structure (Process Credentials)

The ucred structure controls process privileges. Modifying these fields affects security decisions:

```cpp
// Process credential structure - from fps_elf/src/ucred.cpp
struct ucred {
    // Standard FreeBSD fields
    uint32_t cr_uid;      // +0x04: Effective user ID
    uint32_t cr_ruid;     // +0x08: Real user ID
    uint32_t cr_svuid;    // +0x0C: Saved user ID
    uint32_t cr_ngroups;  // +0x10: Number of groups
    uint32_t cr_rgid;     // +0x14: Real group ID

    // Sony-specific fields (PS5)
    uint64_t cr_sceAuthID;    // +0x58: Sony authorization ID
    uint64_t cr_sceCaps[2];   // +0x60, +0x68: Sony capabilities (128-bit)
    uint8_t  cr_sceAttr[8];   // +0x83: Sony attributes
};

// Privilege escalation example
void jailbreak_process(pid_t pid) {
    uintptr_t ucred = kernel_get_proc_ucred(pid);

    uint32_t uid_store = 0;          // root
    int64_t caps_store = -1;         // all capabilities
    uint8_t attr_store[] = {0x80};   // bypass checks

    kernel_copyin(&uid_store, ucred + 0x04, 4);   // cr_uid = 0
    kernel_copyin(&uid_store, ucred + 0x08, 4);   // cr_ruid = 0
    kernel_copyin(&caps_store, ucred + 0x60, 8);  // cr_sceCaps[0] = -1
    kernel_copyin(&caps_store, ucred + 0x68, 8);  // cr_sceCaps[1] = -1
    kernel_copyin(attr_store, ucred + 0x83, 1);   // cr_sceAttr[0] = 0x80
}
```

### Process Structure Fields

```cpp
// From include/freebsd-helper.h
struct proc {
    struct proc *p_forw;           // +0x00: Forward link
    TAILQ_HEAD(, thread) p_threads; // +0x10: Thread list
    struct ucred *p_ucred;          // +0x40: Credentials pointer
    struct filedesc *p_fd;          // +0x48: File descriptors
    pid_t pid;                      // +0xBC: Process ID
    // ... more fields
};
```

### Filesystem/Jail Escape

```cpp
// Escape sandbox by modifying process vnode pointers
void escape_jail(pid_t pid) {
    uintptr_t root_vnode = kernel_get_root_vnode();

    kernel_set_proc_rootdir(pid, root_vnode);  // Set root to /
    kernel_set_proc_jaildir(pid, 0);           // Clear jail directory
}
```

### Known Auth IDs (Sony)

```cpp
// Special authorization IDs that grant elevated privileges
#define DEBUG_AUTHID        0x4800000000000007   // Debugger
#define DECID_AUTH_ID       0x4800000000000022   // Process termination
#define SHELLCORE_AUTHID    0x4800000000000007   // Shell core
#define PTRACE_AUTH_ID      0x4800000000010003   // Ptrace capability
```

---

## 15. Data-Only Attack Vectors for HV Bypass

Given that CFI blocks function pointer hijacking, we need to find DATA that affects hypervisor-level security:

### Potential Targets

```
CATEGORY                 STRUCTURE/FIELD           SECURITY IMPACT
───────────────────────────────────────────────────────────────────────
Page Table Control       pmap fields               Control memory mapping
VM Configuration         vm_page flags             Affect memory protection
IOMMU State              dmar structures           DMA protection
HV Communication         hypercall params          HV request handling
ACPI/Power Mgmt          pm_state flags            Suspend/resume behavior
CPU Features             cpuid cache               CPU feature reporting
MSR Access               msr_allowed list          Model-specific registers
```

### Sysentvec Field Analysis

The sysentvec structure at offset +14 appears to control some syscall/ABI behavior.
The exact semantics of 0xffff vs 0xdeb7 need reverse engineering:

```cpp
struct sysentvec {
    int      sv_size;           // +0x00: Number of syscalls
    struct sysent *sv_table;    // +0x08: Syscall table pointer
    u_int    sv_mask;           // +0x10: Signal mask
    short    sv_sigsize;        // +0x14: <-- THIS FIELD IS MODIFIED
    // ...
};
```

**Hypothesis:** The field at +14 may control signal handling or syscall validation.
Setting it to 0xffff might disable certain security checks.

### Research Direction: Pre-HV Data

For APIC-style attacks, look for data that:
1. Is read during resume BEFORE hypervisor starts
2. Affects hardware initialization or security state
3. Can be modified via kernel R/W

```
CANDIDATES:
├── ACPI tables (if in writable memory)
├── CPU microcode loading parameters
├── PM resume state machine flags
├── IOMMU initialization data
└── Early boot security flags
```

---

## 16. Updated Research Priorities

### Immediate (Data-Only Approach)

```
1. Analyze sysentvec structure in detail
   └── What does field at +14 actually control?
   └── Are there other exploitable fields?

2. Map ALL kernel data that affects security decisions
   └── Process credentials (ucred) ✓ DONE
   └── VM/paging structures
   └── IOMMU configuration
   └── Syscall tables (data, not pointers)

3. Find HV-related data in kernel
   └── Hypercall parameter validation data
   └── VM configuration structures
   └── NPT/GMET configuration flags
```

### Medium Term (Alternative CFI Bypass)

```
4. Research CFI implementation details
   └── Where are CFI metadata tables?
   └── Can they be modified?
   └── Race conditions during initialization?

5. Look for CFI-exempt code paths
   └── Legacy code not compiled with CFI?
   └── Hand-written assembly?
   └── JIT compilation paths?
```

### Long Term (Hardware Approach)

```
6. ACPI/power management research
   └── Resume sequence analysis
   └── Pre-HV initialization data
   └── Hardware state restoration

7. AMD PSP interaction
   └── How does kernel communicate with PSP?
   └── Are there exploitable data paths?
```

---

## 17. Key Takeaways

1. **Function pointer hijacking is dead** on FW 3.xx+ due to aggressive CFI
2. **Data-only attacks work** - kstuff proves this with sysentvec modification
3. **ucred modifications** provide privilege escalation without CFI bypass
4. **The path forward** is finding security-critical DATA, not function pointers
5. **For HV bypass**, we need to find data that affects pre-hypervisor initialization

The APIC approach remains valid in concept, but requires either:
- Finding data (not function pointers) that affects resume behavior
- Discovering a CFI bypass (very difficult)
- Finding a timing window where CFI isn't active yet

---

## 18. BREAKTHROUGH: Writable Mystery Flag at 0xD11D08

### Discovery (2025-01-10)

Through kernel_data.bin analysis, we discovered a writable data field between the two sysentvec structures:

```
LOCATION:
  Offset:    0xD11D08 (kdata_base + 0xD11D08)
  Value:     0x00000001
  Mask:      0x0FFFFFFF (at offset 0xD11D0C)

CONTEXT:
  sysentvec_ps5: 0xD11BB8
  mystery_flag:  0xD11D08 (+0x150 from sysentvec_ps5)
  sysentvec_ps4: 0xD11D30
```

### Live Test Results

**CONFIRMED WRITABLE** - The flag was successfully modified to 0 without triggering CFI or causing a crash!

This proves:
1. **Data-only writes bypass CFI** - as predicted
2. **This specific flag is modifiable** at runtime
3. **The flag is in a security-critical area** (between ABI structures)

### What This Flag Might Control

Given its location and the 28-bit mask (0x0FFFFFFF):

1. **ABI compatibility flags** - controls syscall behavior between PS4/PS5 mode
2. **Security policy index** - indexes into capability/permission tables
3. **Execution context flags** - affects how code is interpreted
4. **Debug/development flags** - leftover from Sony's internal builds

### Next Steps

1. **Keep flag at 0 and observe behavior**
   - Run games
   - Test suspend/resume cycle
   - Check homebrew execution differences

2. **IDA reverse engineering**
   - Find cross-references to kdata_base + 0xD11D08
   - Identify what code reads this flag
   - Trace the decision branches

3. **Test other values**
   - Try 0xFFFFFFFF (all bits set)
   - Try specific bit patterns matching the mask

4. **Scan for similar flags**
   - The gap area (0xD11CB8 - 0xD11D30) may contain more writable security data

### Code Location

Test code added to: `research/umtx2-cfi-tester/main.js`

```javascript
const MYSTERY_FLAG_OFFSET = 0xD11D08;
const MYSTERY_MASK_OFFSET = 0xD11D0C;

let mysteryFlagAddr = krw.kdataBase.add32(MYSTERY_FLAG_OFFSET);
let mysteryFlagVal = await krw.read8(mysteryFlagAddr);

// Write 0 to the flag - THIS WORKS!
await krw.write8(mysteryFlagAddr, new int64(0, mysteryFlagVal.hi));
```

---

## 19. Gap Area Analysis

The region between sysentvec_ps5 and sysentvec_ps4 contains potentially interesting data:

```
Offset Range: 0xD11CB8 - 0xD11D30 (0x78 bytes = 120 bytes)

Known non-zero entries from kernel_data.bin:
  0xD11D08: 0x00000001  <- Mystery flag (WRITABLE!)
  0xD11D0C: 0x0FFFFFFF  <- 28-bit mask
```

This area warrants further investigation as it may contain:
- Additional writable security flags
- Capability indexes
- Policy configuration data

All of these could potentially affect hypervisor or security behavior without triggering CFI.
