/**
 * cfi_probe.cpp - CFI/XOM bypass research for FW 4.03+
 *
 * CONTEXT: On FW 4.03, Byepervisor does NOT run. There is no HV bypass.
 *
 * What we HAVE:
 *   - kernel_copyout: read ANY kernel memory (including .text, since it runs
 *     in kernel context -- the kernel can read its own text, XOM only blocks
 *     userspace reads)
 *   - kernel_copyin: write to kernel DATA pages only (.data/.bss, sysent,
 *     page tables, ucred, etc.)
 *   - Process privilege escalation (ucred, caps, authid, rootvnode)
 *   - ptrace (attach, set registers, single-step, call functions in target)
 *   - JIT shared memory (syscall 0x215/0x216) for W^X userspace code
 *   - ELF loading into new processes
 *
 * What we CANNOT do:
 *   - Write to kernel .text (hypervisor NPT marks those GPA ranges as RO)
 *   - Patch cfi_check_fail (it's in .text)
 *   - Install code caves or hooks in kernel code
 *   - Make arbitrary memory RWX (sceKernelMprotect to 0x7 fails)
 *   - Write through DMAP to kernel text physical pages (NPT also covers DMAP)
 *
 * GOAL: Find a path to kernel code execution or achieve HEN goals (fself,
 *       fpkg) purely through data manipulation and/or non-CPU write paths.
 *
 * ==========================================================================
 *
 * RESEARCH DIRECTIONS:
 *
 * 1. SYSENT DISPATCH CFI TEST
 *    The sysent table (sy_call function pointers) lives in kernel .data.
 *    We can overwrite any entry. BUT does the kernel's syscall dispatch
 *    path use a CFI-checked indirect call? In FreeBSD, the dispatch is:
 *      error = (*callp->sy_call)(td, &args);
 *    If this call site has CFI, replacing sy_call with a non-matching type
 *    triggers cfi_check_fail -> panic. If it DOESN'T have CFI (because it's
 *    in assembly or excluded), we can redirect syscalls freely.
 *
 *    TEST: Redirect an unused sysent to a known kernel function with a
 *    MATCHING sy_call_t signature. If it works, CFI doesn't block sysent.
 *    If it panics, CFI is checked on that path.
 *
 * 2. DATA-ONLY HEN
 *    Skip code execution entirely. Achieve FSELF/FPKG by corrupting the
 *    kernel's authentication data structures (ctxTable, ctxStatus, sceSbl*
 *    internal state) so the kernel THINKS everything is legitimate.
 *
 * 3. CALLBACK FUNCTION POINTERS IN DATA
 *    Find kernel data structures containing function pointers that get
 *    called through non-CFI-checked paths:
 *      - struct fileops (fo_read, fo_write, etc.)
 *      - struct filterops (f_attach, f_detach, f_event)
 *      - struct protosw (pr_input, pr_output, etc.)
 *      - struct vnodeops / vop_vector
 *      - struct cdevsw (d_open, d_read, d_ioctl, etc.)
 *      - taskqueue callbacks
 *    All of these live in DATA. If even one call site lacks CFI, we have
 *    kernel code execution by redirecting it to a useful existing function.
 *
 * 4. GPU DMA
 *    The GPU is a separate bus master with its own address translation
 *    (GART/GPU IOMMU). GPU DMA does NOT go through the CPU's NPT. If the
 *    GPU IOMMU allows writes to the physical pages backing kernel .text,
 *    we can patch kernel code via GPU compute shader or DMA engine,
 *    completely bypassing the hypervisor.
 *
 * 5. SAMU PHYSICAL WRITE
 *    The SAMU at MMIO 0xE0500000 has unrestricted physical memory access.
 *    If a SAMU command takes a destination physical address and writes
 *    caller-controlled data, it bypasses NPT entirely.
 *
 * ==========================================================================
 *
 * These probes are designed to run as a userspace ELF spawned by the
 * etaHEN bootstrapper. They use kernel_copyout/kernel_copyin from
 * ps5/kernel.h.
 */

extern "C" {
#include <ps5/kernel.h>
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

/* You need to set these for FW 4.03 -- placeholder values */
/* These would come from the payload_args or a kdlsym table for 4.03 */
extern unsigned long KERNEL_ADDRESS_DATA_BASE;

/*
 * ============================================================
 * Probe 1: Read kernel .text via kernel_copyout
 *
 * Confirms that kernel_copyout CAN read kernel code pages.
 * (The kernel reading its own text is not blocked by XOM --
 *  XOM only prevents userspace direct reads.)
 *
 * If this works, we can:
 *  - Dump the entire kernel .text to find gadgets
 *  - Identify natural occurrences of useful byte sequences
 *  - Map out CFI check locations
 * ============================================================
 */
int probe_ktext_readable(uint64_t ktext_base)
{
    uint8_t buf[32];
    int ret;

    printf("[PROBE1] Attempting to read kernel .text at 0x%lx via kernel_copyout\n", ktext_base);

    ret = kernel_copyout(ktext_base, buf, sizeof(buf));
    if (ret != 0) {
        printf("[PROBE1] FAILED: kernel_copyout returned %d\n", ret);
        printf("[PROBE1] kernel text is NOT readable even from kernel context\n");
        return -1;
    }

    printf("[PROBE1] SUCCESS: kernel .text is readable via kernel_copyout\n");
    printf("[PROBE1] First 16 bytes: ");
    for (int i = 0; i < 16; i++)
        printf("%02x ", buf[i]);
    printf("\n");

    return 0;
}

/*
 * ============================================================
 * Probe 2: Scan kernel .text for natural gadgets
 *
 * Since we can read kernel text, search for byte sequences
 * that naturally occur and could serve as sysent targets:
 *
 *   FF 26         : jmp [rsi]        (the kexec gadget)
 *   FF 27         : jmp [rdi]
 *   FF 17         : call [rdi]
 *   48 89 F8 C3   : mov rax, rdi; ret
 *   48 89 37 C3   : mov [rdi], rsi; ret (arbitrary write)
 *   48 8B 07 C3   : mov rax, [rdi]; ret (arbitrary read)
 *   C3            : ret (useful for NOP-ing a sysent entry)
 *
 * These exist naturally in any large binary. The question is
 * whether they're at addresses the CFI machinery will accept.
 * ============================================================
 */
typedef struct {
    const char *name;
    uint8_t bytes[8];
    int len;
    uint64_t found_offset;
} gadget_pattern_t;

int probe_gadget_scan(uint64_t ktext_base, uint64_t scan_size)
{
    gadget_pattern_t patterns[] = {
        {"jmp [rsi]",          {0xFF, 0x26},                   2, 0},
        {"jmp [rdi]",          {0xFF, 0x27},                   2, 0},
        {"call [rdi]",         {0xFF, 0x17},                   2, 0},
        {"mov rax,rdi; ret",   {0x48, 0x89, 0xF8, 0xC3},      4, 0},
        {"mov [rdi],rsi; ret", {0x48, 0x89, 0x37, 0xC3},      4, 0},
        {"mov rax,[rdi]; ret", {0x48, 0x8B, 0x07, 0xC3},      4, 0},
        {"ret",                {0xC3},                         1, 0},
    };
    int num_patterns = sizeof(patterns) / sizeof(patterns[0]);

    printf("[PROBE2] Scanning 0x%lx bytes of kernel .text for gadgets\n", scan_size);

    /* Scan in 4KB pages to avoid huge allocations */
    uint8_t page[0x1000];
    uint64_t limit = (scan_size < 0x200000) ? scan_size : 0x200000; /* Cap at 2MB */

    for (uint64_t off = 0; off < limit; off += 0x1000) {
        if (kernel_copyout(ktext_base + off, page, sizeof(page)) != 0) {
            printf("[PROBE2] Read failed at offset 0x%lx, stopping scan\n", off);
            break;
        }

        for (int i = 0; i < 0x1000 - 8; i++) {
            for (int p = 0; p < num_patterns; p++) {
                if (patterns[p].found_offset != 0)
                    continue; /* Already found one, skip */

                if (memcmp(&page[i], patterns[p].bytes, patterns[p].len) == 0) {
                    patterns[p].found_offset = off + i;
                    printf("[PROBE2] Found '%s' at ktext+0x%lx (VA=0x%lx)\n",
                           patterns[p].name,
                           patterns[p].found_offset,
                           ktext_base + patterns[p].found_offset);
                }
            }
        }
    }

    printf("[PROBE2] === Gadget scan results ===\n");
    for (int p = 0; p < num_patterns; p++) {
        if (patterns[p].found_offset)
            printf("[PROBE2]   %-25s at ktext+0x%lx\n",
                   patterns[p].name, patterns[p].found_offset);
        else
            printf("[PROBE2]   %-25s NOT FOUND in first 0x%lx bytes\n",
                   patterns[p].name, limit);
    }

    return 0;
}

/*
 * ============================================================
 * Probe 3: Sysent structure analysis
 *
 * Read the sysent table from kernel memory. Each entry is:
 *   struct sysent {
 *       int sv_narg;        // number of arguments
 *       sy_call_t *sy_call; // function pointer
 *       // ... possibly more fields
 *   };
 *
 * We want to:
 *  1. Find the sysent table address for FW 4.03
 *  2. Read several entries to understand the layout
 *  3. Identify unused/reserved syscall numbers
 *  4. Note what sy_call points to (for CFI type analysis)
 *
 * If we find an unused syscall, we can test sysent redirection
 * without destroying a real syscall.
 * ============================================================
 */
int probe_sysent_layout(uint64_t sysent_addr)
{
    if (sysent_addr == 0) {
        printf("[PROBE3] sysent address not provided, skipping\n");
        return -1;
    }

    /* FreeBSD sysent entry is typically 48 bytes on PS5 (may vary) */
    /* Read a few entries to figure out the actual layout */
    uint8_t entry[0x40];

    printf("[PROBE3] Reading sysent table at 0x%lx\n", sysent_addr);

    for (int i = 0; i < 5; i++) {
        kernel_copyout(sysent_addr + (i * sizeof(entry)), entry, sizeof(entry));
        printf("[PROBE3] sysent[%d]: ", i);
        for (int j = 0; j < 32; j++)
            printf("%02x ", entry[j]);
        printf("\n");
    }

    /* Also read some high-numbered entries that are likely unused */
    for (int i = 600; i < 605; i++) {
        kernel_copyout(sysent_addr + (i * sizeof(entry)), entry, sizeof(entry));

        /* Check if sy_call points to nosys (the default for unused syscalls) */
        uint64_t sy_call;
        memcpy(&sy_call, &entry[8], sizeof(sy_call)); /* Offset may vary */

        printf("[PROBE3] sysent[%d]: sy_call=0x%lx ", i, sy_call);

        /* Read the first few bytes at sy_call to check if it's nosys */
        uint8_t code[4];
        if (kernel_copyout(sy_call, code, sizeof(code)) == 0) {
            printf("(code: %02x %02x %02x %02x)\n",
                   code[0], code[1], code[2], code[3]);
        } else {
            printf("(can't read target)\n");
        }
    }

    return 0;
}

/*
 * ============================================================
 * Probe 4: Page table permission survey
 *
 * Walk the kernel's page tables to understand what's protected.
 * Read page table entries for:
 *   - Kernel .text pages (should be RX or XO)
 *   - Kernel .data pages (should be RW, NX)
 *   - DMAP pages (what permissions?)
 *   - Sysent table page (should be RW, NX)
 *
 * This tells us exactly what the guest page tables say.
 * The NPT (hypervisor) adds another layer on top, but
 * understanding guest-level permissions helps.
 *
 * x86-64 page table entry format:
 *   Bit  0: Present
 *   Bit  1: Read/Write (1=writable)
 *   Bit  2: User/Supervisor
 *   Bit  7: Page Size (1=huge page)
 *   Bit 58: XOTEXT (PS5 custom - execute only)
 *   Bit 63: NX (No Execute)
 * ============================================================
 */
#define PTE_PRESENT     (1UL << 0)
#define PTE_RW          (1UL << 1)
#define PTE_USER        (1UL << 2)
#define PTE_PS          (1UL << 7)
#define PTE_XOTEXT      (1UL << 58)
#define PTE_NX          (1UL << 63)
#define PTE_ADDR_MASK   0x000FFFFFFFFFF000UL

int probe_page_permissions(uint64_t kdata_base,
                           uint64_t ktext_base,
                           uint64_t dmpml4i_offset,
                           uint64_t dmpdpi_offset,
                           uint64_t pml4pml4i_offset)
{
    uint64_t DMPML4I = 0, DMPDPI = 0, PML4PML4I = 0;

    kernel_copyout(kdata_base + dmpml4i_offset, &DMPML4I, sizeof(int));
    kernel_copyout(kdata_base + dmpdpi_offset, &DMPDPI, sizeof(int));
    kernel_copyout(kdata_base + pml4pml4i_offset, &PML4PML4I, sizeof(int));

    uint64_t dmap_base = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000UL;
    uint64_t pde_base = (PML4PML4I << 39) | (PML4PML4I << 30) | 0xFFFF800000000000UL;

    printf("[PROBE4] DMPML4I=%lu DMPDPI=%lu PML4PML4I=%lu\n", DMPML4I, DMPDPI, PML4PML4I);
    printf("[PROBE4] DMAP base = 0x%lx\n", dmap_base);

    /* Check PDE for kernel .text */
    uint64_t pde_addr = pde_base + 8 * ((ktext_base >> 21) & 0x7FFFFFFUL);
    uint64_t pde;
    kernel_copyout(pde_addr, &pde, sizeof(pde));
    printf("[PROBE4] Kernel .text PDE (VA=0x%lx):\n", ktext_base);
    printf("[PROBE4]   PDE addr  = 0x%lx\n", pde_addr);
    printf("[PROBE4]   PDE value = 0x%lx\n", pde);
    printf("[PROBE4]   Present=%lu RW=%lu PS=%lu NX=%lu XOTEXT=%lu\n",
           (pde >> 0) & 1, (pde >> 1) & 1, (pde >> 7) & 1,
           (pde >> 63) & 1, (pde >> 58) & 1);

    /* Check PDE for kernel .data */
    pde_addr = pde_base + 8 * ((kdata_base >> 21) & 0x7FFFFFFUL);
    kernel_copyout(pde_addr, &pde, sizeof(pde));
    printf("[PROBE4] Kernel .data PDE (VA=0x%lx):\n", kdata_base);
    printf("[PROBE4]   PDE value = 0x%lx\n", pde);
    printf("[PROBE4]   Present=%lu RW=%lu PS=%lu NX=%lu XOTEXT=%lu\n",
           (pde >> 0) & 1, (pde >> 1) & 1, (pde >> 7) & 1,
           (pde >> 63) & 1, (pde >> 58) & 1);

    /* Check PDE for DMAP region */
    uint64_t dmap_test = dmap_base + 0x200000;
    pde_addr = pde_base + 8 * ((dmap_test >> 21) & 0x7FFFFFFUL);
    kernel_copyout(pde_addr, &pde, sizeof(pde));
    printf("[PROBE4] DMAP PDE (VA=0x%lx):\n", dmap_test);
    printf("[PROBE4]   PDE value = 0x%lx\n", pde);
    printf("[PROBE4]   Present=%lu RW=%lu PS=%lu NX=%lu XOTEXT=%lu\n",
           (pde >> 0) & 1, (pde >> 1) & 1, (pde >> 7) & 1,
           (pde >> 63) & 1, (pde >> 58) & 1);

    if (!(pde & PTE_NX)) {
        printf("[PROBE4] *** DMAP NX=0 -- DMAP is EXECUTABLE in guest page tables ***\n");
    }

    return 0;
}

/*
 * ============================================================
 * Probe 5: fileops/cdevsw function pointer survey
 *
 * Read kernel data structures that contain function pointers
 * called through potentially non-CFI-checked paths.
 *
 * If we can find ONE function pointer call site without CFI,
 * we can redirect it to achieve kernel code execution.
 * ============================================================
 */
int probe_fileops(uint64_t proc_addr)
{
    if (proc_addr == 0) {
        printf("[PROBE5] Need process kernel address, skipping\n");
        return -1;
    }

    /* Read the fd table from our own process */
    /* proc->p_fd->fd_files->fdt_ofiles[fd]->f_ops */
    uint64_t p_fd;
    kernel_copyout(proc_addr + 0x48, &p_fd, sizeof(p_fd)); /* offset may vary */

    printf("[PROBE5] proc->p_fd = 0x%lx\n", p_fd);

    if (p_fd == 0) {
        printf("[PROBE5] p_fd is NULL, skipping\n");
        return -1;
    }

    /* Read fd_files pointer */
    uint64_t fd_files;
    kernel_copyout(p_fd + 0x0, &fd_files, sizeof(fd_files));
    printf("[PROBE5] fd_files = 0x%lx\n", fd_files);

    /* Read file structure for fd 0 (stdin) */
    uint64_t file_ptr;
    kernel_copyout(fd_files + 0x0, &file_ptr, sizeof(file_ptr));
    printf("[PROBE5] file[0] = 0x%lx\n", file_ptr);

    if (file_ptr == 0) {
        printf("[PROBE5] file[0] is NULL\n");
        return -1;
    }

    /* Read f_ops from file structure */
    uint64_t f_ops;
    kernel_copyout(file_ptr + 0x28, &f_ops, sizeof(f_ops)); /* offset varies */
    printf("[PROBE5] file[0]->f_ops = 0x%lx\n", f_ops);

    /* Read the fileops function pointers */
    uint64_t ops[8];
    kernel_copyout(f_ops, ops, sizeof(ops));
    printf("[PROBE5] fileops:\n");
    printf("[PROBE5]   fo_read    = 0x%lx\n", ops[0]);
    printf("[PROBE5]   fo_write   = 0x%lx\n", ops[1]);
    printf("[PROBE5]   fo_truncate= 0x%lx\n", ops[2]);
    printf("[PROBE5]   fo_ioctl   = 0x%lx\n", ops[3]);
    printf("[PROBE5]   fo_poll    = 0x%lx\n", ops[4]);
    printf("[PROBE5]   fo_kqfilter= 0x%lx\n", ops[5]);
    printf("[PROBE5]   fo_stat    = 0x%lx\n", ops[6]);
    printf("[PROBE5]   fo_close   = 0x%lx\n", ops[7]);

    /* KEY QUESTION: Is this fileops table in .data or .rodata?
     * If .data -> writable -> can redirect function pointers
     * If .rodata -> mapped read-only -> need to find writable ones
     *
     * Check if f_ops address is in kernel .data range */
    printf("[PROBE5] f_ops at 0x%lx -- is this in writable kernel data?\n", f_ops);

    return 0;
}

/*
 * ============================================================
 * Probe 6: CFI check detection in kernel .text
 *
 * Scan kernel code for calls/jumps to cfi_check_fail(). By
 * finding which call sites have CFI enforcement, we can
 * determine if the sysent dispatch path is CFI-checked.
 *
 * If the sysent dispatch (amd64_syscall or equivalent) does
 * NOT have a CFI check, then sysent manipulation works even
 * with CFI active on everything else.
 * ============================================================
 */
int probe_cfi_callsites(uint64_t ktext_base, uint64_t cfi_check_fail_addr,
                         uint64_t scan_size)
{
    if (cfi_check_fail_addr == 0) {
        printf("[PROBE6] cfi_check_fail address not provided\n");
        return -1;
    }

    printf("[PROBE6] Scanning for call/jmp to cfi_check_fail at 0x%lx\n",
           cfi_check_fail_addr);

    uint8_t page[0x1000];
    uint64_t limit = (scan_size < 0x400000) ? scan_size : 0x400000;
    int count = 0;

    for (uint64_t off = 0; off < limit; off += 0x1000) {
        if (kernel_copyout(ktext_base + off, page, sizeof(page)) != 0)
            break;

        for (int i = 0; i < 0x1000 - 5; i++) {
            /* Check for E8 xx xx xx xx (call rel32) */
            if (page[i] == 0xE8) {
                int32_t rel;
                memcpy(&rel, &page[i+1], 4);
                uint64_t target = ktext_base + off + i + 5 + rel;

                if (target == cfi_check_fail_addr) {
                    printf("[PROBE6] CFI check at ktext+0x%lx\n", off + i);
                    count++;
                    if (count > 100) {
                        printf("[PROBE6] (too many, truncating...)\n");
                        goto done;
                    }
                }
            }
            /* Check for E9 xx xx xx xx (jmp rel32) */
            if (page[i] == 0xE9) {
                int32_t rel;
                memcpy(&rel, &page[i+1], 4);
                uint64_t target = ktext_base + off + i + 5 + rel;

                if (target == cfi_check_fail_addr) {
                    printf("[PROBE6] CFI jmp at ktext+0x%lx\n", off + i);
                    count++;
                }
            }
        }
    }

done:
    printf("[PROBE6] Found %d references to cfi_check_fail\n", count);
    printf("[PROBE6] Next step: find amd64_syscall in this dump and check\n");
    printf("[PROBE6] whether the sy_call dispatch has a CFI reference nearby\n");
    return 0;
}

/*
 * ============================================================
 * Probe 7: Sysent redirection safety test
 *
 * THE critical test. Redirect an unused sysent entry to point
 * to an EXISTING syscall handler (same sy_call_t type). Then
 * invoke it. If the kernel doesn't panic, the sysent dispatch
 * path is NOT CFI-checked, and sysent manipulation is viable.
 *
 * Safe test: redirect sysent[unused] to point to the handler
 * for sys_getpid (which returns the PID). If we call the
 * unused syscall and get back our PID, it worked.
 *
 * We redirect to a REAL syscall handler, so the function type
 * matches sy_call_t perfectly. This makes the test safe even
 * if CFI IS checked -- a type-matching function won't trigger
 * CFI regardless.
 *
 * For the REAL test of whether non-matching types are checked,
 * we'd need to redirect to a gadget (different type). But that
 * risks a panic. Start with the safe version first to confirm
 * sysent writes work at all.
 * ============================================================
 */
int probe_sysent_redirect(uint64_t sysent_addr, uint64_t sys_getpid_addr)
{
    if (sysent_addr == 0 || sys_getpid_addr == 0) {
        printf("[PROBE7] Need sysent and sys_getpid addresses\n");
        return -1;
    }

    /* Pick an unused syscall number (high numbers are usually free) */
    int test_syscall = 601;

    /* Read the current entry */
    uint8_t entry[0x40];
    uint64_t entry_addr = sysent_addr + (test_syscall * sizeof(entry));
    kernel_copyout(entry_addr, entry, sizeof(entry));

    printf("[PROBE7] Original sysent[%d]: ", test_syscall);
    for (int i = 0; i < 16; i++) printf("%02x ", entry[i]);
    printf("\n");

    /* Save the original sy_call for restoration */
    uint64_t original_sy_call;
    memcpy(&original_sy_call, &entry[8], sizeof(original_sy_call));

    /* Overwrite sy_call with sys_getpid's address */
    printf("[PROBE7] Redirecting sysent[%d].sy_call to sys_getpid (0x%lx)\n",
           test_syscall, sys_getpid_addr);

    kernel_copyin(&sys_getpid_addr, entry_addr + 8, sizeof(sys_getpid_addr));

    /* Try to invoke it */
    printf("[PROBE7] Invoking syscall(%d)...\n", test_syscall);
    printf("[PROBE7] If the kernel panics here, the sysent dispatch HAS CFI\n");
    printf("[PROBE7] (but since we used a matching type, it SHOULD be safe)\n");

    long result = syscall(test_syscall);
    printf("[PROBE7] syscall(%d) returned: %ld (our pid=%d)\n",
           test_syscall, result, getpid());

    if (result == getpid()) {
        printf("[PROBE7] *** SUCCESS! Sysent redirection works! ***\n");
        printf("[PROBE7] The sysent dispatch path accepted our redirect.\n");
        printf("[PROBE7] Next: test with a non-matching gadget type to see\n");
        printf("[PROBE7] if the dispatch truly lacks CFI or just matched types.\n");
    }

    /* Restore original */
    kernel_copyin(&original_sy_call, entry_addr + 8, sizeof(original_sy_call));
    printf("[PROBE7] Restored original sysent[%d]\n", test_syscall);

    return 0;
}
