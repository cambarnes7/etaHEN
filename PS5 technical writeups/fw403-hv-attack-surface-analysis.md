# PS5 FW 4.03 Hypervisor Attack Surface Analysis

## Educational Security Research — Personal Device

Comprehensive analysis of the PS5 hypervisor barrier on firmware 4.03, where kernel
read/write exists (via IPV6/UMTX exploits) but the hypervisor remains intact. Maps all
available primitives, attack surfaces, and potential research directions.

---

## Table of Contents

1. [The Problem: What Changed at FW 3.00](#1-the-problem-what-changed-at-fw-300)
2. [What Works on FW 4.03 (Building Blocks)](#2-what-works-on-fw-403-building-blocks)
3. [What Does NOT Work on FW 4.03](#3-what-does-not-work-on-fw-403)
4. [Attack Surface 1: SBL/SAMU Mailbox](#4-attack-surface-1-sblsamu-mailbox)
5. [Attack Surface 2: VMEXIT/VMMCALL Handlers](#5-attack-surface-2-vmexitvmmcall-handlers)
6. [Attack Surface 3: GPU DMA / IOMMU](#6-attack-surface-3-gpu-dma--iommu)
7. [Attack Surface 4: Side-Channels & Speculative Execution](#7-attack-surface-4-side-channels--speculative-execution)
8. [Prioritized Research Roadmap](#8-prioritized-research-roadmap)
9. [References](#9-references)

---

## 1. The Problem: What Changed at FW 3.00

### FW <= 2.70 (Byepervisor works)

The hypervisor was **integrated into the kernel binary**. Two vulnerabilities existed:

**Jump Table Exploit:** The HV's VMMCALL dispatch table (array of relative offsets) was
stored in kernel `.data` — guest-writable. Overwrite an entry, trigger `VMMCALL`, get HV
code execution. The ROP chain zeros `VMCB+0x90` (the `NP_ENABLE` field), disabling both
Nested Paging and GMET simultaneously.

**QA Flags Exploit (Primary):** QA flags including the System Level (SL) debug flag were
shared between HV and guest kernel, stored in kernel `.data`. When SL flag is set, the HV
constructs NPT *without* xotext or write-protection on kernel `.text`. The flags were not
reinitialized by the secure loader on resume from sleep. Set the flag → sleep → resume →
kernel `.text` is readable and writable.

### FW >= 3.00 (Both patched)

1. **HV separated from kernel binary** — jump tables, code, and data are in HV-only memory
2. **QA flags reinitialized on resume** — the sleep/wake trick no longer works
3. HV `.data` is no longer mapped into the guest address space

### The Result on FW 4.03

```
Guest PTE modifications (clearing XOTEXT, setting RW):
  → Succeed at guest level (kernel R/W works)
    → BUT NPT still enforces xotext + write-protection on .text physical pages
      → CPU read of .text → #NPF → kernel panic
      → CPU write to .text → #NPF → kernel panic
      → CPU execution of .text → ALLOWED (that's what execute-only means)
```

---

## 2. What Works on FW 4.03 (Building Blocks)

### Tier A: Fully Functional (kernel R/W only)

| Primitive | Details |
|-----------|---------|
| **kernel_copyout / kernel_copyin** | Arbitrary kernel `.data` read/write |
| **kernel_read4 / kernel_write4** | 32-bit kernel memory access |
| **Auth ID escalation** | `ucred+0x58` → set to `0x4800000000000007` (ShellCore) |
| **Capability modification** | `ucred+0x60`, `ucred+0x68` → arbitrary caps |
| **UID escalation** | `ucred+0x04/0x08/0x0C` → set to 0 (root) |
| **Sandbox escape** | Redirect `fd_rdir`/`fd_jdir` to root vnode |
| **Page table walking** | `find_pml4e/pdpe/pde/pte()` via DMAP |
| **VA→PA translation** | `pmap_kextract()` for any kernel address |
| **DMAP resolution** | `get_dmap_addr(pa)` for physical→virtual |
| **User page remapping** | `remap_page()` / `mirror_page()` — alias kernel physical pages into userspace |
| **Network operations** | Sockets, FTP (1337), dump server (9003), KLOG (9081), ELF loader (9021) |
| **Filesystem access** | Full filesystem via jailbreak |
| **Userland hijacking** | Process injection, thread manipulation, userland hooks |
| **SBL mailbox messaging** | Can send arbitrary commands to SAMU (see Section 4) |

### Tier C: Partially Functional

| Primitive | Works | Blocked |
|-----------|-------|---------|
| **Syscall table** | Can READ sysent entries | Cannot MODIFY handler pointers (writes to .text pages) |
| **kdlsym** | Resolves .data symbols | .text symbol reads may panic depending on NPT config |
| **Guest PTE modification** | Can clear XOTEXT in guest PTEs | NPT overrides — no actual effect |

---

## 3. What Does NOT Work on FW 4.03

| Capability | Why |
|-----------|-----|
| Kernel code execution (kexec) | Cannot write code to .text; code caves in .data are not executable (GMET) |
| Kernel function hooking | Requires writing to .text |
| SELF signature bypass | Requires patching AuthMgr functions in .text |
| Syscall handler installation | Handler code must be in .text |
| CFI bypass patches | `cfi_check_fail()` is in .text |
| Disabling SMAP/SMEP | HV intercepts CR4 writes |
| Disabling WP bit | HV intercepts CR0 writes |
| Reading kernel .text directly | NPT xotext enforcement → #NPF → panic |

---

## 4. Attack Surface 1: SBL/SAMU Mailbox

**Relevance:** Flatz reportedly achieved HV bypass up to FW 4.51 via a PS4 game save path
that interacts with SBL. Bugs in secure module parsing give execution **above** the HV.

### Mailbox Architecture

The SBL communication channel uses kernel `.data` structures accessible with kernel R/W:

```
MMIO Base:     0xE0500000 (accessible via DMAP)
Command Reg:   MMIO + 0x10564  (cmd << 8)
Mailbox PA:    MMIO + 0x10568  (physical address of message buffer)
Mailbox Num:   14 (0xE)
Mailbox Size:  0x800 per slot
```

Message header (`sbl_msg_header`, 0x18 bytes):
```
+0x00  uint32_t cmd          — Command ID (e.g., 6 for AUTHMGR)
+0x04  uint16_t query_len    — Input buffer size
+0x06  uint16_t recv_len     — Output buffer size
+0x08  uint64_t message_id   — Auto-incremented tracker
+0x10  uint64_t to_ret       — Return/handle value
```

Payload follows at `mailbox_addr + 0x18`.

**There is ZERO validation at kernel level.** All fields are passed directly to the secure
module.

### Critical Functions (AUTHMGR, cmd=6)

#### VERIFY_HEADER (function 0x01)

Attacker controls:
- `self_header_pa` — physical address of SELF header (points SBL parser at arbitrary memory)
- `self_header_size` — no bounds checking
- `auth_id` — authentication ID

The SBL will parse whatever is at the attacker-provided physical address as a SELF header.
A malformed header with crafted segment definitions could trigger parser bugs.

#### LOAD_SELF_SEGMENT (function 0x02)

Attacker controls:
- `chunk_table_pa` — physical address of chunk table (SBL iterates entries)
- `segment_index` — no bounds validation
- `is_block_table` — flag toggling different code paths

#### LOAD_SELF_BLOCK (function 0x06) — MOST CRITICAL

Attacker controls almost every field:
```
+0x08  uint64_t out_pa         — WHERE SBL writes decrypted output
+0x10  uint64_t in_pa          — WHERE SBL reads encrypted input
+0x30  uint32_t aligned_size   — Buffer size (integer overflow potential)
+0x34  uint32_t size            — Unaligned size
+0x3C  uint32_t segment_index  — Index into SBL tables
+0x40  uint32_t block_index    — Block index
+0x44  uint32_t service_id     — Context handle
+0x48  uint8_t  digest[0x20]   — SHA256 digest
+0x70  uint16_t is_compressed  — Toggles decompression code path
+0x74  uint16_t is_plain_elf   — Toggles ELF handling code path
```

**Attack vectors:**
- Arbitrary memory read: set `in_pa` to target, `out_pa` to attacker buffer
- Arbitrary memory write: if SBL doesn't validate decryption output before writing to `out_pa`
- Integer overflow: `aligned_size` and `size` mismatch could cause buffer overflow in SBL
- State machine abuse: call LOAD_BLOCK without VERIFY_HEADER, double-FINALIZE, etc.

#### FINALIZE_CTX (function 0x05)

Attacker controls:
- `context_id` — could trigger use-after-free if SBL accesses freed context

### Chunk Table Structure

```
Header (0x20 bytes):
  +0x00  uint64_t first_pa       — First entry PA
  +0x08  uint64_t data_size      — Data size
  +0x10  uint64_t used_entries   — Number of entries to iterate

Entry (0x10 bytes each):
  +0x00  uint64_t pa             — Physical address
  +0x08  uint64_t size           — Size
```

All fields attacker-controlled. If SBL doesn't validate `used_entries`, it reads beyond
the allocated table.

### SPAWN / UNLOAD Structures

```
sbl_spawn (0x28 bytes):
  +0x18  char sm_code[8]   — Secure module code ID (attacker-controlled)

sbl_unload (0x08 bytes):
  +0x00  uint64_t function — Handle (attacker-controlled)
```

SPAWN with crafted `sm_code` could potentially load arbitrary secure modules.

### Why This Matters

The data flow has NO kernel-side validation:

```
Attacker (kernel R/W)
  → sceSblServiceRequest() — copies structures to mailbox via kernel_copyin()
    → sceSblDriverSendMsg() — writes mailbox PA + cmd to MMIO registers
      → SBL Secure Module — parses message, may not validate all fields
        → If parsing bug → code execution above HV
```

This matches Flatz's reported PS4 vector: game save → kernel → SBL → parsing bug → HV bypass.

---

## 5. Attack Surface 2: VMEXIT/VMMCALL Handlers

### Intercepted VMEXIT Events

| Event | Guest-Controlled Data | HV Handler Must... |
|-------|----------------------|-------------------|
| VMEXIT_CPUID | EAX (leaf), ECX (subleaf) | Emulate CPUID, return values |
| VMEXIT_CR_WRITE | New CR value from guest GPR | Validate protected bits |
| VMEXIT_CR_READ | Target register encoding | Return sanitized CR |
| VMEXIT_MSR | ECX (MSR index), EDX:EAX (value) | Filter via MSRPM bitmap |
| VMEXIT_VMMCALL | RAX (hypercall ID), other GPRs | Dispatch to handler, parse args |
| VMEXIT_NPF | EXITINFO1 (error code), EXITINFO2 (faulting GPA) | Handle page fault |
| VMEXIT_EFER_WRITE | New EFER value | Mask SVME, NXE, xotext bits |

### Complete Hypercall Table (FW 3.00+)

| ID | Name | Attack Interest |
|----|------|----------------|
| 0x0 | HV_GET_MESSAGE_CONF | Low |
| 0x1 | HV_GET_MESSAGE_COUNT | Low |
| 0x2 | **HV_START_LOADING_SELF** | **HIGH** — HV parses SELF data from guest |
| 0x3 | **HV_FINISH_LOADING_SELF** | **HIGH** — Completion of SELF loading |
| 0x4 | HV_SET_CPUID_PS4 | Medium — was the jump table target |
| 0x5 | HV_SET_CPUID_PPR | Medium |
| 0x6 | **HV_IOMMU_SET_GUEST_BUFFERS** | **HIGH** — IOMMU configuration |
| 0x7 | **HV_IOMMU_ENABLE_DEVICE** | **HIGH** — Device enablement |
| 0x8 | **HV_IOMMU_BIND_PASID** | **HIGH** — PASID binding |
| 0x9 | **HV_IOMMU_UNBIND_PASID** | **HIGH** — PASID unbinding |
| 0xA | HV_IOMMU_CHECK_CMD_COMPLETION | Medium |
| 0xB | HV_IOMMU_CHECK_EVLOG_REGS | Medium |
| 0xC | HV_IOMMU_READ_DEVICE_TABLE | Medium — info leak potential |
| 0xD | HV_GET_TMR_VIOLATION_ERROR | Low |
| 0xE | HV_VMCLOSURE_INVOCATION | Low |
| 0xF | HV_STARTUP_MP | Low |
| 0x10 | HV_DISABLE_STARTUP_MP | Low |

### IOMMU Hypercalls (0x6-0xB) — Most Promising

Six hypercalls deal with IOMMU configuration. Arguments come from guest registers which
**survive across the VMEXIT boundary** (only RAX, RIP, RSP are restored to host values;
all other GPRs retain guest values). The HV must validate these arguments:

- `BIND_PASID` / `UNBIND_PASID` — complex state management, potential use-after-free
- `SET_GUEST_BUFFERS` — if the HV trusts guest-provided buffer addresses...
- `ENABLE_DEVICE` — could potentially enable DMA for a device with insufficient IOMMU restrictions

### SELF-Loading Hypercalls (0x2-0x3)

The guest kernel invokes these when loading SELF binaries. The HV processes SELF data from
guest memory. A crafted SELF with malformed headers could trigger parsing bugs in the HV's
SELF verification code.

### Potential Bug Classes

| Bug Class | Where | How |
|-----------|-------|-----|
| Integer overflow in hypercall ID check | VMMCALL dispatch | Signed vs unsigned comparison on guest RAX |
| Type confusion in EXITINTINFO | NPF/exception handler | Crafted type field (bits 10:8) in VMCB 0x088 |
| VMCB clean bits stale state | Any handler | HV forgets to dirty cached state after modification |
| NRIP trust | Instruction emulation | HV advances RIP without validation |
| NPF handler GPA confusion | #NPF handler | Crafted memory access → unexpected GPA in EXITINFO2 |
| IOMMU state machine bugs | PASID bind/unbind | Double-unbind, bind-after-free |
| CR write filter bypass | CR interception | Denylist vs allowlist — undocumented bits |

### Register Preservation (Critical for Exploitation)

On AMD SVM, **VMEXIT preserves guest GPR state** (except RAX/RIP/RSP). The Byepervisor
exploit used this: set R9, RBX, RSI, R12 in guest context before VMMCALL, and those values
are visible in the HV handler. Any future exploit would use the same technique — prepare
a register context in the guest that becomes a JOP/ROP context in the HV.

---

## 6. Attack Surface 3: GPU DMA / IOMMU

### Memory Architecture

```
CPU path:  VA → Guest PTE → GPA → NPT → HPA
GPU path:  GVA → GART/GPUVM → Device PA → IOMMU → HPA
```

**GPU DMA does NOT go through NPT.** It goes through the IOMMU, which is a separate
translation mechanism with its own page tables. The xotext bit (bit 58) is a custom
CPU page table extension — it does not exist in IOMMU page table entries.

### Why This Matters

On FW 4.03, kernel `.data` is CPU-writable (the `.data` write protection was added at
FW 6.00). So GPU DMA isn't needed for `.data` writes on 4.03. However:

1. **The IOMMU might allow GPU writes to kernel `.text` physical pages** — since the IOMMU
   has no concept of xotext, the question is whether the HV configures IOMMU to block writes
   to those physical addresses at all.

2. **GART page table manipulation** — GPU page tables live in system RAM. With kernel R/W,
   you could modify GART entries to redirect GPU virtual addresses to kernel `.text` physical
   pages. If the IOMMU mapping covers those addresses, the GPU could read/write them.

3. **IOMMU reconfiguration via hypercalls** — The 6 IOMMU hypercalls (Section 5) are the
   guest kernel's interface for IOMMU management. If you can trick the HV into creating
   favorable IOMMU mappings, GPU DMA could target `.text` pages.

### Practical Approach

```
1. Locate GPU GART page tables in system RAM (using kernel R/W)
2. Find or create a GART entry pointing to a kernel .text physical page
3. Submit a GPU compute shader or DMA copy command that reads/writes via that GART entry
4. The GPU DMA goes through IOMMU (not NPT) — if IOMMU allows it, write succeeds
```

GPU command submission path:
- Allocate dmem via `sceKernelAllocateDirectMemory()`
- Map via `sceKernelMapDirectMemory()`
- Build command buffer with DMA copy packet (CP_DMA_CMD)
- Submit via `/dev/gc` ioctl or `sceGnmSubmitCommandBuffers()`

### Known Precedent

flat_z demonstrated GPU DMA writes to kernel `.data` on FW 6.00-7.61 (bypassing the
CPU-side `.data` write protection introduced at FW 6.00). Implemented in ps5-jar-loader
v4.0.0 using BD-J's `GnmUtils.copyPlanesBackgroundToPrimary()`.

---

## 7. Attack Surface 4: Side-Channels & Speculative Execution

### APPROACH B: DMAP Physical Memory Access — TRY THIS FIRST

**This is not a side channel — it's a direct read through an alternate mapping.**

The PS5 kernel's DMAP maps ALL physical memory into a contiguous kernel virtual address
range. The xotext bit in NPT applies to the *kernel .text virtual address mapping*.
The question: does the HV also set xotext on the DMAP NPT entries for those same
physical pages?

```c
// Already implemented in etaHEN (paging.cpp):
uint64_t text_pa = pmap_kextract(kernel_text_va);  // .text VA → PA
uint64_t dmap_va = get_dmap_addr(text_pa);          // PA → DMAP VA
kernel_copyout(dmap_va, &buf, size);                 // Read via DMAP
```

If the HV does NOT enforce xotext on DMAP mappings → **instant full kernel dump at MB/s**.

The "Meme Dumper" (cheburek3000, Feb 2023) accessed "PS5 memory via physical address,
which is mapped without any protection" — suggesting DMAP pages may not have xotext.

**Effort: Trivial. Test immediately.**

### APPROACH D: Zenbleed (CVE-2023-20593) — LIKELY UNPATCHED ON FW 4.03

Zen 2 hardware bug: speculative `vzeroupper` rollback leaves stale register contents
accessible from the register file. Leaks register data at 30 KB/core/second across
threads, processes, and VM boundaries.

**PS5 uses Zen 2. FW 4.03 is from 2021. Zenbleed was discovered July 2023. The microcode
fix (DE_CFG[9] chicken bit) was almost certainly not applied to FW 4.03.**

What it leaks: Register values from kernel code execution — function arguments, return
values, intermediate computations. String operations using AVX2 (`strlen`, `memcpy`,
`strcmp`) are especially vulnerable.

Not a direct code dump tool, but leaks kernel data (pointers, keys, structures) that
help reconstruct code behavior.

**PoC:** https://github.com/google/security-research/tree/master/pocs/cpus/zenbleed

### APPROACH A: BlindSide Speculative Probing — CONFIRMED ON ZEN 2

Uses speculative (not architectural) control-flow hijacking to probe kernel memory without
crashes. Key mechanism:

1. Corrupt a kernel code pointer (via kernel R/W to `.data`)
2. Trigger speculative execution via the corrupted pointer
3. Speculative execution follows a disclosure gadget in kernel code
4. The gadget speculatively reads a byte and encodes it in cache state
5. Observe cache via Flush+Reload → recover the byte value

**Critical insight:** Speculative *execution* of XOM code is permitted (that's what
execute-only means). The gadget executes kernel .text speculatively, reads data through
DMAP (where xotext may not apply), and leaks it via cache.

Confirmed working on AMD Ryzen 7 3700X (Zen 2) at ~2,645 bytes/second.
Full 8 MB kernel .text dump: ~55 minutes.

**Paper:** https://download.vusec.net/papers/blindside_ccs20.pdf

### APPROACH E: Retbleed / Branch Type Confusion (CVE-2022-29900)

On AMD Zen 2, return instructions can be mispredicted via BTB collisions (not just RSB
underflow). PhantomJMP allows non-branch instructions to be treated as JMP. Same
exploitation mechanism as BlindSide but using Retbleed as the speculative primitive.

AMD-specific: IBPB does NOT flush RSB entries on Zen < 4 (X86_BUG_IBPB_NO_RET).

### APPROACH C: Prefetch Timing (KASLR Break + Layout)

`prefetch` instruction timing on AMD leaks page table translation level and TLB state.
Reveals which kernel .text pages are mapped and actively used. Provides code layout at
page granularity but NOT byte contents.

Useful for mapping kernel structure before applying other techniques.

**PoC:** https://github.com/amdprefetch/amd-prefetch-attacks

### APPROACH G: Instruction Oracle via Controlled Execution

Execute XOM-protected code with controlled register inputs, observe outputs to infer
instructions. The CPU can *execute* .text (execute-only, not execute-denied). By
single-stepping (trap flag) and diffing register state, you can classify instructions.

Very slow (~100 instructions/sec) and x86 variable-length encoding makes this harder
than the ARM version (WOOT'19). But it works in theory.

---

## 8. Prioritized Research Roadmap

### Phase 1: Low-Hanging Fruit (Try Immediately)

| # | Action | Effort | Success Probability |
|---|--------|--------|-------------------|
| 1 | **Test DMAP read of kernel .text** | Trivial — 10 lines of C | Medium-High |
| 2 | **Test Zenbleed on FW 4.03** | Low — adapt Google PoC | High (unpatched) |

If DMAP read works, you have a full kernel dump in seconds. Game over for XOM.

### Phase 2: SBL Fuzzing (Medium Term)

| # | Action | Effort | Success Probability |
|---|--------|--------|-------------------|
| 3 | **Fuzz LOAD_SELF_BLOCK with crafted PAs and sizes** | Medium | Medium |
| 4 | **Test state machine abuse (out-of-order calls)** | Medium | Medium |
| 5 | **Fuzz VERIFY_HEADER with malformed SELF data** | Medium | Medium |
| 6 | **Test SPAWN with crafted sm_code values** | Low | Low-Medium |

### Phase 3: Speculative Execution (If DMAP Fails)

| # | Action | Effort | Success Probability |
|---|--------|--------|-------------------|
| 7 | **Implement BlindSide speculative probing** | High | Medium-High |
| 8 | **Implement Retbleed/BTC probing** | High | Medium |

### Phase 4: IOMMU / GPU DMA

| # | Action | Effort | Success Probability |
|---|--------|--------|-------------------|
| 9 | **Locate GPU GART page tables via kernel R/W** | Medium | High (for location) |
| 10 | **Test IOMMU hypercall argument validation** | High | Unknown |
| 11 | **Attempt GPU DMA write to .text physical pages** | High | Medium |

### Phase 5: HV Handler Fuzzing

| # | Action | Effort | Success Probability |
|---|--------|--------|-------------------|
| 12 | **Fuzz SELF-loading hypercalls (0x2, 0x3)** | High | Low-Medium |
| 13 | **Test IOMMU PASID bind/unbind state machine** | High | Low-Medium |
| 14 | **Test VMCB clean bits manipulation** | High | Low |

---

## 9. References

### PS5 Specific
- [PS5Dev/Byepervisor](https://github.com/PS5Dev/Byepervisor) — HV exploit for FW 1.xx-2.xx
- [PS5 Hypervisor Wiki](https://www.psdevwiki.com/ps5/Hypervisor) — Architecture documentation
- [PS5 Vulnerabilities Wiki](https://www.psdevwiki.com/ps5/Vulnerabilities) — Known vulns
- [PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak) — Kernel exploit
- [PS5-IPV6-Kernel-Exploit](https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit) — Kernel exploit
- [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader) — BD-J exploit with GPU DMA
- [Byepervisor Talk (hardwear.io 2024)](https://hardwear.io/netherlands-2024/speakers/specter.php)
- [Flatz HV exploit confirmation](https://wololo.net/2024/10/06/ps5-specterdev-to-present-byepervisor-exploit-in-october-flatz-confirms-he-has-another-hypervisor-exploit-up-to-fw-4-51/)

### AMD Architecture
- [AMD APM Vol 2 — SVM](https://www.0x04.net/doc/amd/33047.pdf) — VMCB, VMEXIT, NPT
- [AMD IOMMU Specification](https://docs.amd.com/api/khub/documents/GD6kOXjzWsek8QUbn_qMvg/content)
- [AMD GPU IOMMU Docs](https://instinct.docs.amd.com/projects/amdgpu-docs/en/latest/conceptual/iommu.html)

### Side-Channel Papers
- [BlindSide (CCS 2020)](https://download.vusec.net/papers/blindside_ccs20.pdf) — Speculative probing, confirmed Zen 2
- [AMD Prefetch Attacks (USENIX Sec 2022)](https://www.usenix.org/system/files/sec22summer_lipp.pdf)
- [Retbleed (USENIX Sec 2022)](https://www.usenix.org/system/files/sec22-wikner.pdf) — BTB-based return misprediction
- [Zenbleed (CVE-2023-20593)](https://lock.cmpxchg8b.com/zenbleed.html) — Zen 2 register file leak
- [Zenbleed PoC](https://github.com/google/security-research/tree/master/pocs/cpus/zenbleed)
- [Taking a Look into Execute-Only Memory (WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_schink.pdf)
- [Inception/SRSO (USENIX Sec 2023)](https://www.usenix.org/system/files/usenixsecurity23-trujillo.pdf)

### General
- [ret2dir (USENIX Sec 2014)](https://www.cs.columbia.edu/~vpk/papers/ret2dir.sec14.pdf) — Physical memory aliasing
- [IOMMU Protection Bypass](https://hal.science/hal-01419962/document) — IOMMU DMA attacks
- [Project Zero — EPYC Escape](https://projectzero.google/2021/06/an-epyc-escape-case-study-of-kvm.html) — KVM breakout case study
- [fail0verflow — PS4 Aux Hax](https://fail0verflow.com/blog/2022/ps4-psvr/) — PSVR DMA attacks
- [AMD Prefetch PoC](https://github.com/amdprefetch/amd-prefetch-attacks)
- [KASLD Collection](https://github.com/bcoles/kasld) — Kernel address space layout derandomization
