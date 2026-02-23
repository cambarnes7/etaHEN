/**
 * cfi_probe.cpp - Probing tool for CFI/XOM bypass research
 *
 * Tests several theories for achieving kernel code execution without
 * needing to modify kernel .text pages (i.e., without Byepervisor).
 *
 * Probes:
 *  1. DMAP executability - Are DMAP pages marked NX? Can we clear it?
 *  2. New PTE creation  - Can we create fresh executable PTEs in kernel pmap?
 *  3. Auth context table - Can we fake SELF auth via data-only corruption?
 *  4. Sysent gadget API  - Can we build a full HEN using only sysent redirects?
 *
 * IMPORTANT: These are research probes. Each one may crash the kernel.
 *            Run them one at a time with logging enabled.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" {
#include <ps5/kernel.h>
}

#include "debug_log.h"
#include "kdlsym.h"
#include "paging.h"
#include "util.h"

/**
 * Probe 1: DMAP Executability Check
 *
 * The DMAP (direct map) maps all of physical RAM into kernel virtual space.
 * If DMAP page table entries do NOT have NX set, we can:
 *   1. Write payload to a userspace page
 *   2. Calculate its DMAP address (dmap_base + PA)
 *   3. Jump to the DMAP address from kernel context
 *
 * This probe reads the PDE/PTE for several DMAP addresses and reports
 * their permission bits. It does NOT attempt execution.
 */
int probe_dmap_executability()
{
    uint64_t kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
    uint64_t dmap_base;
    uint64_t pde, pte;
    uint64_t pde_addr, pte_addr;

    // Resolve DMAP base
    uint64_t DMPML4I, DMPDPI;
    kernel_copyout(kdlsym(KERNEL_SYM_DMPML4I), &DMPML4I, sizeof(int));
    kernel_copyout(kdlsym(KERNEL_SYM_DMPDPI), &DMPDPI, sizeof(int));
    dmap_base = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000;

    flash_notification("[PROBE] DMAP base = 0x%lx", dmap_base);

    // Allocate a userspace page and find its PA
    void *user_page = mmap(0, 0x1000, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_page == MAP_FAILED)
        return -1;

    // Touch the page to ensure it's faulted in
    *(volatile uint64_t *)user_page = 0xDEADC0DE;

    // Get process pmap for our page
    uint64_t proc_pmap = get_proc_pmap();
    uint64_t user_pte;
    find_pte(proc_pmap, (uint64_t)user_page, &user_pte);
    uint64_t user_pa = PDE_ADDR(user_pte);

    flash_notification("[PROBE] User page VA=0x%lx PA=0x%lx", (uint64_t)user_page, user_pa);

    // Now check the DMAP mapping of this physical address
    uint64_t dmap_va = dmap_base + user_pa;
    flash_notification("[PROBE] DMAP VA for user page = 0x%lx", dmap_va);

    // Check PML4E
    uint64_t pml4e;
    uint64_t pml4e_addr = find_pml4e(kernel_pmap, dmap_va, &pml4e);
    flash_notification("[PROBE] DMAP PML4E: addr=0x%lx val=0x%lx NX=%lu RW=%lu USER=%lu",
        pml4e_addr, pml4e,
        PDE_FIELD(pml4e, EXECUTE_DISABLE),
        PDE_FIELD(pml4e, RW),
        PDE_FIELD(pml4e, USER));

    // Check PDPE
    uint64_t pdpe;
    uint64_t pdpe_addr = find_pdpe(kernel_pmap, dmap_va, &pdpe);
    flash_notification("[PROBE] DMAP PDPE: addr=0x%lx val=0x%lx NX=%lu RW=%lu PS=%lu",
        pdpe_addr, pdpe,
        PDE_FIELD(pdpe, EXECUTE_DISABLE),
        PDE_FIELD(pdpe, RW),
        PDE_FIELD(pdpe, PS));

    // If PS bit is set on PDPE, this is a 1GB page (common for DMAP)
    if (PDE_FIELD(pdpe, PS)) {
        flash_notification("[PROBE] DMAP uses 1GB superpages at PDPE level");
        flash_notification("[PROBE] DMAP NX = %lu (0=EXECUTABLE, 1=NOT EXECUTABLE)",
            PDE_FIELD(pdpe, EXECUTE_DISABLE));
        flash_notification("[PROBE] DMAP XOTEXT = %lu", PDE_FIELD(pdpe, XOTEXT));
        goto done;
    }

    // Check PDE
    pde_addr = find_pde(kernel_pmap, dmap_va, &pde);
    flash_notification("[PROBE] DMAP PDE: addr=0x%lx val=0x%lx NX=%lu RW=%lu PS=%lu",
        pde_addr, pde,
        PDE_FIELD(pde, EXECUTE_DISABLE),
        PDE_FIELD(pde, RW),
        PDE_FIELD(pde, PS));

    if (PDE_FIELD(pde, PS)) {
        flash_notification("[PROBE] DMAP uses 2MB superpages at PDE level");
        flash_notification("[PROBE] DMAP NX = %lu", PDE_FIELD(pde, EXECUTE_DISABLE));
        goto done;
    }

    // Check PTE
    pte_addr = find_pte(kernel_pmap, dmap_va, &pte);
    flash_notification("[PROBE] DMAP PTE: addr=0x%lx val=0x%lx NX=%lu RW=%lu",
        pte_addr, pte,
        PDE_FIELD(pte, EXECUTE_DISABLE),
        PDE_FIELD(pte, RW));

done:
    // Also check kernel .text page permissions for comparison
    uint64_t ktext_addr = ktext(0);
    find_pde(kernel_pmap, ktext_addr, &pde);
    flash_notification("[PROBE] Kernel .text PDE: val=0x%lx NX=%lu RW=%lu XOTEXT=%lu PS=%lu",
        pde,
        PDE_FIELD(pde, EXECUTE_DISABLE),
        PDE_FIELD(pde, RW),
        PDE_FIELD(pde, XOTEXT),
        PDE_FIELD(pde, PS));

    munmap(user_page, 0x1000);
    return 0;
}

/**
 * Probe 2: Can we create a new executable PTE in the kernel pmap?
 *
 * Theory: The hypervisor protects EXISTING kernel .text page table entries.
 *         But does it also prevent CREATION of NEW executable entries?
 *
 * This probe:
 *   1. Finds a free kernel VA range (above kernel .text, below DMAP)
 *   2. Allocates a userspace page with a simple payload (ret instruction)
 *   3. Attempts to create a new PDE->PTE chain mapping userspace PA as executable
 *   4. Reads back the PTE to see if the hypervisor reverted it
 *
 * NOTE: This does NOT attempt execution. It only checks if the PTE survives.
 */
int probe_new_pte_creation()
{
    uint64_t kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
    uint64_t test_pte;
    uint64_t pte_addr;
    uint64_t readback_pte;

    // Allocate a page with a ret instruction
    void *user_page = mmap(0, 0x1000, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_page == MAP_FAILED)
        return -1;

    // Write a simple ret instruction
    *(uint8_t *)user_page = 0xC3;
    *(volatile uint64_t *)((char *)user_page + 8) = 0x4141414141414141; // canary

    // Get PA of our page
    uint64_t proc_pmap = get_proc_pmap();
    uint64_t user_pte;
    find_pte(proc_pmap, (uint64_t)user_page, &user_pte);
    uint64_t user_pa = PDE_ADDR(user_pte);

    flash_notification("[PROBE2] User page PA = 0x%lx", user_pa);

    // Find a kernel VA that has NO existing PTE (should be in a gap)
    // Try an address in the range after kernel .text but before typical data
    uint64_t ktext_end = kdlsym(KERNEL_SYM_TEXT_END);
    flash_notification("[PROBE2] Kernel .text end = 0x%lx", ktext_end);

    // Check if there's a PDE for addresses beyond .text
    // We want to find a VA where the PDE exists but there's no PTE (or PDE is not present)
    uint64_t probe_va = ktext_end + 0x200000; // 2MB beyond .text end
    uint64_t existing_pde;
    uint64_t pde_addr_val = find_pde(kernel_pmap, probe_va, &existing_pde);

    flash_notification("[PROBE2] PDE at probe VA 0x%lx: addr=0x%lx val=0x%lx present=%lu",
        probe_va, pde_addr_val,
        existing_pde, PDE_FIELD(existing_pde, PRESENT));

    // If PDE is not present, we'd need to create the whole PDE->PT chain
    // For now, just report what we find
    if (!PDE_FIELD(existing_pde, PRESENT)) {
        flash_notification("[PROBE2] No PDE present - would need to create PDE->PT chain");
        flash_notification("[PROBE2] This is a harder test. Skipping execution attempt.");
    } else {
        // PDE exists, try to find/create a PTE
        uint64_t existing_pte;
        uint64_t pte_addr_val = find_pte(kernel_pmap, probe_va, &existing_pte);
        flash_notification("[PROBE2] PTE at probe VA: addr=0x%lx val=0x%lx present=%lu",
            pte_addr_val, existing_pte, PDE_FIELD(existing_pte, PRESENT));
    }

    munmap(user_page, 0x1000);
    return 0;
}

/**
 * Probe 3: Auth Context Table Analysis
 *
 * Dump the SELF auth context table to understand its structure.
 * If we can manipulate ctxTable[] and ctxStatus[] directly,
 * we might achieve fake SELF loading without any code hooks.
 */
int probe_auth_context_table()
{
    uint64_t ctxTable = kdlsym(KERNEL_SYM_CTXTABLE);
    uint64_t ctxStatus = kdlsym(KERNEL_SYM_CTXSTATUS);

    flash_notification("[PROBE3] ctxTable = 0x%lx", ctxTable);
    flash_notification("[PROBE3] ctxStatus = 0x%lx", ctxStatus);

    // Read status array (4 entries)
    int status[4];
    kernel_copyout(ctxStatus, status, sizeof(status));

    for (int i = 0; i < 4; i++) {
        flash_notification("[PROBE3] ctxStatus[%d] = %d", i, status[i]);
    }

    // Read first bytes of each context entry to understand layout
    uint8_t ctx_data[0x40];
    // SelfContext is referenced but size varies; read first 64 bytes of each
    for (int i = 0; i < 4; i++) {
        kernel_copyout(ctxTable + (i * 0x100), ctx_data, sizeof(ctx_data));
        flash_notification("[PROBE3] ctx[%d] first 8 bytes: %02x%02x%02x%02x %02x%02x%02x%02x",
            i,
            ctx_data[0], ctx_data[1], ctx_data[2], ctx_data[3],
            ctx_data[4], ctx_data[5], ctx_data[6], ctx_data[7]);
    }

    return 0;
}

/**
 * Probe 4: Sysent Gadget Scan
 *
 * Scan the kernel .text for useful gadgets that can be installed
 * into sysent entries. Each gadget = one syscall = one kernel operation.
 *
 * Key gadgets needed for data-only HEN:
 *  - mov [rdi], rsi; ret    (arbitrary write from syscall args)
 *  - mov rax, [rdi]; ret    (arbitrary read returning value)
 *  - call [rdi]; ret        (indirect call)
 *  - mov cr3, rdi; ret      (TLB flush - unlikely but worth checking)
 *
 * We use kernel_copyout to read .text (kernel can read its own text).
 */
int probe_sysent_gadgets()
{
    uint64_t kernel_base = ktext(0);
    uint64_t text_end = kdlsym(KERNEL_SYM_TEXT_END);
    uint64_t scan_size = text_end - kernel_base;
    uint8_t buf[0x20];

    flash_notification("[PROBE4] Scanning kernel text 0x%lx - 0x%lx (%lu MB)",
        kernel_base, text_end, scan_size / (1024*1024));

    int gadget_count = 0;
    // Scan for: jmp [rsi] (FF 26) - already known
    // Scan for: jmp [rdi] (FF 27)
    // Scan for: call [rdi] (FF 17)
    // Scan for: mov [rdi], rsi; ret (48 89 37 C3)
    // Scan for: mov rax, [rdi]; ret (48 8B 07 C3)

    // Sample scan - check first 1MB for known useful patterns
    uint64_t scan_limit = (scan_size < 0x100000) ? scan_size : 0x100000;

    for (uint64_t offset = 0; offset < scan_limit; offset += 0x1000) {
        uint8_t page[0x1000];
        kernel_copyout(kernel_base + offset, page, sizeof(page));

        for (int i = 0; i < 0x1000 - 4; i++) {
            // jmp [rdi] - FF 27
            if (page[i] == 0xFF && page[i+1] == 0x27) {
                flash_notification("[PROBE4] jmp [rdi] at offset 0x%lx", offset + i);
                gadget_count++;
            }
            // mov [rdi], rsi; ret - 48 89 37 C3
            if (page[i] == 0x48 && page[i+1] == 0x89 && page[i+2] == 0x37 && page[i+3] == 0xC3) {
                flash_notification("[PROBE4] mov [rdi],rsi; ret at 0x%lx", offset + i);
                gadget_count++;
            }
            // mov rax, [rdi]; ret - 48 8B 07 C3
            if (page[i] == 0x48 && page[i+1] == 0x8B && page[i+2] == 0x07 && page[i+3] == 0xC3) {
                flash_notification("[PROBE4] mov rax,[rdi]; ret at 0x%lx", offset + i);
                gadget_count++;
            }
        }
    }

    flash_notification("[PROBE4] Found %d useful gadgets in first %lu KB",
        gadget_count, scan_limit / 1024);

    return 0;
}

/**
 * Probe 5: Hypervisor PTE modification detection latency
 *
 * This probe measures how quickly the hypervisor reverts a PTE change.
 * It modifies a kernel .text PTE (sets RW, clears XOTEXT), then
 * immediately reads it back in a tight loop to see if there's a
 * window where the modification persists.
 *
 * WARNING: This may cause a #VMEXIT and could destabilize the system.
 */
int probe_hv_response_time()
{
    uint64_t kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
    uint64_t ktext_addr = ktext(0x1000); // Pick a page in kernel .text
    uint64_t pde, original_pde;
    uint64_t pde_addr;
    uint64_t readback;
    int survived_count = 0;

    // Read original PDE
    pde_addr = find_pde(kernel_pmap, ktext_addr, &pde);
    original_pde = pde;

    flash_notification("[PROBE5] Original PDE for ktext+0x1000: 0x%lx", pde);
    flash_notification("[PROBE5] NX=%lu RW=%lu XOTEXT=%lu",
        PDE_FIELD(pde, EXECUTE_DISABLE),
        PDE_FIELD(pde, RW),
        PDE_FIELD(pde, XOTEXT));

    // Modify: set RW, clear XOTEXT
    CLEAR_PDE_BIT(pde, XOTEXT);
    SET_PDE_BIT(pde, RW);

    // Write modified PDE
    kernel_copyin(&pde, pde_addr, sizeof(pde));

    // Immediately read back in tight loop
    for (int i = 0; i < 100; i++) {
        kernel_copyout(pde_addr, &readback, sizeof(readback));
        if (readback != original_pde) {
            survived_count++;
        }
    }

    // Read final state
    kernel_copyout(pde_addr, &readback, sizeof(readback));

    flash_notification("[PROBE5] After modification:");
    flash_notification("[PROBE5] Modified PDE survived %d/100 readbacks", survived_count);
    flash_notification("[PROBE5] Final PDE = 0x%lx (original was 0x%lx)", readback, original_pde);

    if (readback == original_pde) {
        flash_notification("[PROBE5] HV reverted the PTE change");
    } else if (readback == pde) {
        flash_notification("[PROBE5] MODIFICATION SURVIVED! HV did not revert!");
    } else {
        flash_notification("[PROBE5] PDE is different from both original and modified - interesting");
    }

    return 0;
}
