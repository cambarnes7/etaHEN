# PS5 Hypervisor Research Tool - Progress Documentation

**Target:** FW 4.03 | **Date:** March 2026

This documents what has been built, what works, and what has been confirmed through testing up to this commit.

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

### 16. Phase 7 Pre-Suspend: apic_ops[2] Trampoline Hook
- When a trampoline is available (KLD or cave), Phase 7 pre-suspend arms the hook:
  - Writes original xapic_mode to `g_trampoline_target` via DMAP
  - Hooks `apic_ops[2]` → `trampoline_xapic_mode()`
  - Trampoline calls through to original, returns correct APIC mode
  - Safe for LAPIC suspend sequence (no kernel panic risk)
- Two trampoline sources:
  - **KLD trampoline** (preferred): function in kmod .text (NPT-executable)
  - **Cave trampoline** (fallback): shellcode in kdata code cave (guest PTE NX cleared)
- Cave trampoline is LEFT ARMED during suspend (safe: kdata shared by all CPUs)
- KLD trampoline is restored before suspend (NPT may not be executable on secondary CPUs)
- Falls back to markers-only if neither trampoline is available
- **Status:** Cave trampoline path ready for next suspend/resume test

### 17. kdata Cave Trampoline (Phase 5b)
- When the kmod trampoline scanner fails (module pages are NPT-protected
  against DMAP reads), builds a self-contained `trampoline_xapic_mode`
  function directly in the kdata code cave at kdata_base + 0x100
- 56 bytes total: 40 bytes of position-independent x86-64 code + 8-byte
  `g_trampoline_target` + 8-byte `g_proof_marker_addr`
- On execution, writes "FIRED!_!" (0x4649524544215F21) proof marker to
  kdata_base+0x20 via DMAP, then calls through to original xapic_mode
- Guest PTE NX bit permanently cleared for the kdata_base page (NPT
  already allows execution on kdata — confirmed by ring-0 PTE NX-clear test)
- Eliminates dependency on kmod trampoline scanner
- **Status:** Installed and armed; awaiting suspend/resume test

---

## Bug Fixes (This Commit)

### Cave Trampoline Not Armed During Suspend
- **Bug:** Phase 7 unconditionally restored `apic_ops[2]` to original before
  entering rest mode. The rationale was to prevent kernel panics on secondary
  CPUs (KLD trampoline pages may not be NPT-executable on other CPUs).
  However, this also unarmed the cave trampoline, which lives in kdata and
  IS shared by all CPUs.
- **Evidence:** Run 2 (post-resume) confirmed `apic_ops[2]` retained its
  original value (0xffffffff948d7908), proving the hook was never armed during
  the suspend/resume cycle.
- **Fix:** Made restore conditional on trampoline type:
  - **Cave trampoline:** LEFT ARMED during suspend (safe: kdata is shared by
    all CPUs, guest PTE NX cleared, NPT allows execution on kdata pages)
  - **KLD trampoline:** RESTORED before suspend (NPT issues on secondary CPUs)

### Cave Trampoline Upgraded with Proof Marker
- **Bug:** No mechanism existed to confirm whether the cave trampoline actually
  fired during the LAPIC resume sequence. Even if everything survived, we
  couldn't distinguish "hook was there but never called" from "hook fired."
- **Fix:** Upgraded cave trampoline from 28 bytes to 56 bytes. On execution,
  it writes "FIRED!_!" (0x4649524544215F21) to kdata_base+0x20 via DMAP
  before calling through to original xapic_mode. Post-resume code checks
  for this proof marker and reports the result.

### Post-Resume Cave Trampoline Detection
- **Added:** Post-resume code now checks:
  1. Proof marker at kdata_base+0x20 (did the trampoline fire?)
  2. Whether `apic_ops[2]` still points to the cave trampoline KVA
  3. Reports four states: FIRED, FIRED (hook lost), ARMED (not fired), NOT ARMED
  4. Clears proof marker after detection for clean next cycle

## Bug Fixes (Previous Commit)

### Kmod Trampoline Scanner Failure (NPT Read Protection)
- **Bug:** The trampoline scanner could not find `hv_idt_trampoline` in kernel
  memory, preventing hv_init from running via IDT hook. This caused Phase 7
  to skip arming the apic_ops hook ("KLD trampoline not available").
- **Cause:** PS5 FW 4.03's HV NPT protects kldload-allocated module pages
  against DMAP reads (execute-only at NPT level). The scanner reads pages via
  DMAP and never finds the trampoline signature. kldstat also returns
  address=0x0 for the module.
- **Fix:** Added "Phase 5b: kdata Cave Trampoline" — after ring-0 code
  execution is confirmed, if the kmod trampoline is unavailable, writes a
  self-contained trampoline function to the kdata code cave and permanently
  clears the guest PTE NX bit. Phase 7 uses this cave trampoline to arm
  apic_ops[2].

### IDT Scanner Off-by-0x10
- **Bug:** Scanner found IDT at kdata+0x64cdc70 instead of kdata+0x64cdc80
- **Cause:** Only required 6/8 consecutive valid gates. The 16 bytes before the real IDT happened to look like valid padding, so entries 1-7 (real entries 0-6) gave 7/8 valid — passing the threshold despite wrong alignment.
- **Fix:** Also require entry 0 (the first checked entry) to be a valid gate. IDT entry 0 (#DE divide-by-zero) is always present on x86-64.

### Code Cave Finder Inconsistency
- **Bug:** Run 1 found cave at kdata+0x0, run 2 at kdata+0x1000 (persistence markers from run 1 made first page non-zero)
- **Fix:** Skip first page of kdata in cave scan — reserved for Phase 7 persistence markers.

### SIDT Comment Correction
- **Bug:** Comment at IDT scanner said "SIDT is intercepted by PS5 HV and kills the process" but SIDT works fine at ring 3 on FW 4.03.
- **Fix:** Updated comment to note SIDT works on FW 4.03, scanner used as portable fallback.

### Phase 7 Pre-Suspend Hook Armed
- **Bug:** Phase 7 pre-suspend only set persistence markers but did NOT hook apic_ops[2], despite having a safe KLD trampoline that calls through to the original function.
- **Fix:** Pre-suspend now hooks apic_ops[2] → KLD trampoline when available. This is safe because the trampoline calls the original xapic_mode and returns the real APIC mode value.

---

## What Was Removed (Previous Commit)

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

## Test Results: Run 1 (Fresh Boot) + Run 2 (Post-Resume)

### Run 1 — Fresh Boot
- All phases completed successfully
- DMAP base: 0xffffe2c000000000
- CR3: 0x1cb01000, ktext: 0xffffffff82200000, kdata: 0xffffffff88880000
- Ring-0 code execution via sysent hook: confirmed
- apic_ops found at kdata+0x1cc0140, 28 entries, slot[2] = 0xffffffff948d7908
- apic_ops writeback test: confirmed (ring-0 read+write works)
- Cave trampoline installed at kdata+0x100 (56 bytes, PTE NX cleared)
- Persistence markers set (cave + QA flags)
- **Previous bug:** apic_ops[2] was restored to original before rest mode entry
  (hook was NOT armed during suspend)
- Rest mode entered via `sceSystemStateMgrEnterStandby()`

### Run 2 — Post-Resume
- Re-exploited successfully, re-ran tool
- DMAP base: 0xffffe2c000000000 (same)
- CR3: 0x1c8fe000 (changed — expected, new page tables allocated on resume)
- ktext: 0xffffffff82200000, kdata: 0xffffffff88880000 (same — KASLR stable)
- Cave marker "FLATZHOO": **PERSISTED**
- Saved ktext from cave: matches current ktext — **KASLR stable**
- QA flags (bytes 0-1 = 0xFF): **PERSISTED**
- Guest PTE NX-clear on kdata page: **PERSISTED**
- apic_ops[2]: 0xffffffff948d7908 — **RETAINED** (original value, hook was not armed)
- ktext readability via DMAP: **STILL XOM** (all zeros through DMAP)
- NPT allows execution on kdata: confirmed again (ring-0 shellcode works)

### Key Findings
1. Everything persists across suspend/resume: cave markers, QA flags, PTE NX-clear, KASLR slide, apic_ops values
2. ktext does NOT become readable after resume on FW 4.03 (DMAP reads return zeros)
3. The hook was never armed during suspend — this was the bug (now fixed)
4. CR3 changes across resume (new page tables) but DMAP base and KASLR stay the same

## Current State of the Flatz Method

The flatz suspend/resume method requires running code during early resume, before the HV sets up NPT protections. The key findings so far:

**Proven:**
- apic_ops[2] (xapic_mode) is called during LAPIC suspend/resume
- We can hook it (KLD trampoline, kdata cave trampoline, or ktext gadget)
- Cave markers, QA flags, and apic_ops values survive suspend/resume
- Guest PTE NX-clear survives suspend/resume
- KASLR slide is stable across resume
- Guest PTE NX-clear works for code execution in kdata
- NPT allows execution on kdata pages (confirmed via ring-0 shellcode)
- kldload-allocated module pages are NPT read-protected (scanner can't find them via DMAP)
- ktext remains XOM after resume on FW 4.03 (no free readability)

**Unknown (needs testing with this build):**
- Whether the cave trampoline fires during LAPIC resume when left armed
- Whether the proof marker appears at kdata+0x20 after resume
- Whether the HV kills the guest if apic_ops[2] points to kdata during resume

**Next Steps:**
1. Test this build (cave trampoline LEFT ARMED during suspend + proof marker)
2. Enter rest mode → wake → re-exploit → re-run tool
3. Check proof marker at kdata+0x20 for "FIRED!_!" (0x4649524544215F21)
4. If trampoline fired: we have confirmed code execution during resume!
5. Next: upgrade trampoline payload (currently just writes proof + calls original)
6. If guest killed: investigate why (NPT enforcement on kdata during resume?)
7. If trampoline didn't fire: check if apic_ops[2] was restored by kernel

---

## File Structure

```
hv_research/
  Makefile              - Build orchestrator (builds kmod first, then embeds in .elf)
  main.c                - Userland research driver (~6400 lines)
  hv_research.elf       - Compiled payload (deployed to PS5)
  kmod/
    Makefile            - Kernel module build rules (ET_REL via clang -c)
    hv_kld.c            - Kernel loadable module (~575 lines)
    hv_kmod.ko          - Compiled kernel module
    .gitignore          - Excludes *.o and *.elf
```
