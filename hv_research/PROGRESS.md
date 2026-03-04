# PS5 Hypervisor Research Tool - Progress Documentation

**Target:** FW 4.03 | **Date:** March 2026

This documents what has been built, what works, and what has been confirmed through testing up to this commit. The most recent build (this commit) has NOT been tested yet.

---

## Architecture Overview

The tool is a two-part system:

1. **hv_research.elf** - Userland payload (runs after jailbreak via umtx2 + etaHEN)
2. **hv_kmod.ko** - Kernel module (embedded in .elf, loaded via kldload at runtime)

The .ko is compiled as an ET_REL (relocatable ELF), embedded into the .elf via `.incbin`, written to disk at runtime, then loaded via `kldload(2)`. The kernel linker handles relocation and memory allocation. Results are passed back via a DMAP-mapped shared buffer.

---

## What Works (Confirmed)

### 1. DMAP Base Discovery
- Walks kernel `pmap` structure to find the Direct Map base address
- Falls back to known common DMAP bases if walk fails
- Validates via MMIO register read at known physical address (0xE0500000)
- **Status:** Works reliably on FW 4.03

### 2. FW Version Detection + Offset Initialization
- Reads FW version from kernel
- Sets correct offsets for kernel structures (ktext, kdata, allproc, etc.)
- Supports FW 4.03 and 4.50 offsets
- **Status:** Confirmed working

### 3. Page Table Walking (VA to PA)
- Full AMD64 4-level page table walk (PML4 → PDP → PD → PT)
- Handles 4KB, 2MB, and 1GB page sizes
- Uses DMAP + CR3 to read page table entries
- **Status:** Core infrastructure, confirmed working

### 4. Kernel Module Loading (kldload)
- Writes embedded .ko to `/data/etaHEN/hv_kmod.ko`
- Patches `OUTPUT_KVA_SENTINEL` in the .ko's ELF symtab with DMAP-mapped output KVA
- Calls `kldload()` syscall to load into kernel
- Three execution paths for `hv_init()`:
  - **Path 1 (SYSINIT):** Kernel linker processes `set_sysinit_set` section, calls `hv_init` automatically
  - **Path 2 (MOD_LOAD):** Module metadata triggers `hv_modevent` → `hv_init`
  - **Path 3 (IDT Trampoline):** If SYSINIT/MOD_LOAD don't fire, userland hooks an IDT entry to point to `hv_idt_trampoline` in the .ko, then triggers `int N` from ring 3 → CPU transitions to ring 0 → trampoline calls `hv_init` → `iretq` back to ring 3
- **Status:** All three paths confirmed working. Path 3 (IDT) is the primary method on FW 4.03 since the kernel linker doesn't process SYSINIT for loaded modules.

### 5. Ring-0 Code Execution (MSR/CR Reading)
- From within the kernel module, reads:
  - MSR_EFER, MSR_LSTAR, MSR_STAR, MSR_SFMASK
  - MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE, MSR_TSC_AUX
  - CR0, CR3, CR4
- Results written to shared buffer via DMAP
- **Status:** Confirmed working, returns valid register values

### 6. VMMCALL Hypercall Enumeration
- Probes RAX = 0x00 through 0x1F with all other registers zeroed
- Records which hypercalls survive (HV doesn't kill guest) vs which cause #VMEXIT
- **Status:** Confirmed working. Some hypercalls return normally, others may kill the guest.

### 7. Ring-0 Code Execution via PTE NX-Clear + Sysent Hook
- Discovers sysent table in kernel .data via pattern matching (narg field validation)
- Clears NX bit on guest PTE for target kdata page
- Hooks sysent[253] to point to shellcode placed in kdata
- Calls `syscall(253)` → runs shellcode in ring 0 → restores everything
- **Status:** Confirmed working. This proves arbitrary ring-0 code execution via guest PTE manipulation + sysent hook.

### 8. apic_ops Discovery
- Scans kernel .data for the `apic_ops` function pointer vtable
- Validates by checking that entries point into ktext range
- Typically finds 28 entries (LAPIC operation function pointers)
- `apic_ops[2]` = `xapic_mode()` — called during LAPIC suspend/resume
- **Status:** Confirmed working on FW 4.03

### 9. apic_ops Hook Installation (KLD Trampoline)
- Computes `trampoline_xapic_mode()` KVA from machine code analysis of the loaded .ko
- Writes original `xapic_mode` address to `g_trampoline_target` via DMAP
- Patches `apic_ops[2]` to point to `trampoline_xapic_mode()` in KLD .text
- Trampoline transparently calls original via `g_trampoline_target`
- No PTE NX clearing needed — KLD .text is NPT-executable (GMET not enforced on FW < 6.50)
- **Status:** Confirmed working. Hook survives normal operation.

### 10. apic_ops Writeback Test
- Uses ring-0 shellcode (via PTE NX-clear + sysent hook) to verify that `apic_ops[2]` can be read AND written back from ring 0
- Reads current value, writes it back, verifies no change
- **Status:** Confirmed working. Proves ring-0 can manipulate apic_ops in both directions.

### 11. Persistence Marker System
- Writes "FLATZHOO" magic marker to kdata cave with original `xapic_mode` value and `ktext_base`
- Stores metadata in QA flags (bytes 0-1 = 0xFF, bytes 4-7 = Phase 7 marker, bytes 8-15 = original xapic)
- **Confirmed:** Cave marker persists across suspend/resume
- **Confirmed:** QA flags persist across suspend/resume
- **Confirmed:** `apic_ops[2]` retains its value across resume
- **Confirmed:** KASLR slide is stable across resume

### 12. ktext PTE Analysis (Phase 6a)
- Walks guest page tables to analyze ktext mapping structure
- Reports 2MB/4KB page counts, XOTEXT bit status, RW/NX flags
- Identifies that FW 4.03 enforces XOM purely via HV NPT (not guest PTEs)
- XOTEXT bit clearing in guest PTEs does NOT help — HV integrity monitor detects modified PTEs and prevents rest mode
- **Status:** Confirmed, diagnostic only

### 13. ktext Readability Test (Phase 6b)
- Reads first 16 bytes of ktext through DMAP
- Detects whether ktext is still XOM or has become readable (post-resume state)
- **Status:** Confirmed working as detection mechanism

### 14. IDT + kstuff Offset Verification (Phase 8)
- Uses known offsets from ps5-kstuff for FW 4.03:
  - IDT at kdata+0x64cdc80
  - TSS at kdata+0x64d0830
  - GDT at kdata+0x64cee30
  - PCPU at kdata+0x64d2280
  - doreti_iret, nop_ret, justreturn, Xinvtlb (ktext addresses)
- Validates IDT by reading all 256 entries and checking gate descriptors
- Cross-verifies Xinvtlb from IDT[244] against kstuff offset
- Dumps TSS RSP0 and IST1-IST7 values
- **Status:** Confirmed working, all offsets validated

### 15. Post-Resume Gadget Scan + apic_ops Hook (ktext readable path)
- When ktext IS readable (post-resume), scans for ROP gadgets
- Looks for: `ret`, `mov eax, 1; ret`, `xor eax, eax; ret`, `xchg rsp, rax; ret`, wrmsr, mov cr0/cr3
- Hooks `apic_ops[2]` with a safe target (`mov eax, 1; ret` or KLD trampoline)
- **Status:** Code is ready, untested (requires successful suspend/resume cycle with readable ktext)

---

## What Was Removed (This Commit)

The following speculative/fallback code was removed to keep only confirmed-working or going-to-work items:

1. **SBL Direct Communication** - `init_sbl_direct()`, `discover_sbl_offsets()`, `sbl_send_raw()` + all SBL structs/defines/globals
2. **SBL Campaigns** - `campaign_sbl_cmd_enum()`, `campaign_authmgr_func_enum()`, `campaign_verify_header_probe()`, `campaign_load_block_outpa()`
3. **IOMMU Reconnaissance** - `campaign_iommu_recon()` (speculative scanning)
4. **IOMMU VMMCALL Campaign** - `campaign_vmmcall_iommu()` in kmod (disabled, risky)
5. **Phase 9 (#GP Pointer Poisoning)** - `phase9_ring0_arm_trigger()`, inline #GP handler code, cave NX-clearing for handler execution, IST3 manipulation, IDT[13] arming
6. **gp_handler function** from kmod (Phase 9 only)
7. **hv_kmod.c** - Unused alternate kernel module with different calling convention
8. **linker.x** - Unused linker script in kmod directory
9. **hv_kmod.bin** - Unused binary dump

---

## Current State of the Flatz Method

The flatz suspend/resume method requires running code during early resume, before the HV sets up NPT protections. The key findings so far:

**Proven:**
- apic_ops[2] (xapic_mode) is called during LAPIC suspend/resume
- We can hook it (KLD trampoline or ktext gadget)
- Cave markers, QA flags, and apic_ops hooks survive suspend/resume
- KASLR slide is stable across resume
- Guest PTE NX-clear works for code execution in kdata

**Unknown (needs testing):**
- Whether ktext becomes readable after suspend/resume on FW 4.03
- Whether the #GP pointer poisoning approach actually fires during resume
- Whether the HV reinitializes NPT without XOM protection on resume

**Next Steps:**
1. Test current build (apic_ops hook + persistence markers)
2. Enter rest mode with markers set
3. Wake, re-exploit, re-run tool
4. Check if ktext is readable post-resume
5. If yes: gadget scan + apic_ops hook with ktext target works automatically
6. If no: need to investigate alternative approaches

---

## File Structure

```
hv_research/
  Makefile              - Build orchestrator (builds kmod first, then embeds in .elf)
  main.c                - Userland research driver (~5800 lines)
  hv_research.elf       - Compiled payload (deployed to PS5)
  kmod/
    Makefile            - Kernel module build rules (ET_REL via clang -c)
    hv_kld.c            - Kernel loadable module (~575 lines)
    hv_kmod.ko          - Compiled kernel module
    .gitignore          - Excludes *.o and *.elf
```
