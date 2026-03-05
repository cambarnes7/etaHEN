/*
 * PS5 Hypervisor Research Tool 2 - FW 4.03
 *
 * SAFE reconnaissance payload for APIC suspend/resume research.
 * Builds on findings from hv_research (see ../hv_research/PROGRESS.md).
 *
 * CONFIRMED SAFE operations (from 8+ sessions of testing):
 *   - DMAP base discovery via pmap walk
 *   - VA-to-PA page table walking
 *   - kernel_copyout/copyin for DMAP reads/writes to kdata
 *   - kldload of ET_REL .ko modules
 *   - Sysent hook for ring-0 code execution (syscall 253)
 *   - apic_ops discovery via kdata pointer scan
 *   - Guest PTE NX-bit clearing on kdata pages
 *   - QA flags read/write
 *   - Persistence markers in kdata cave
 *   - sceSystemStateMgrEnterStandby() with apic_ops[2] = ORIGINAL value
 *
 * CONFIRMED DANGEROUS (will kernel panic):
 *   - apic_ops[2] -> kdata code during suspend (NPT NX enforced)
 *   - apic_ops[2] -> kmod .text during suspend (NPT NX enforced)
 *   - DMAP writes during cpususpend_handler
 *   - Clearing XOTEXT in guest PTEs (HV integrity monitor blocks rest mode)
 *   - Calling arbitrary apic_ops functions via sysent (MMIO panic)
 *   - Probing arbitrary ktext byte offsets (mid-instruction decode)
 *
 * NEW in hv_research2:
 *   Phase A: APIC ops slot mapping - which slots are called when
 *   Phase B: NPT deep scan for VMCB discovery
 *   Phase C: ktext gadget catalog from known kstuff offsets
 *   Phase D: LAPIC MMIO register dump (safe read via DMAP)
 *   Phase E: apic_ops function signature analysis
 *   Phase F: Suspend with ktext hook + marker verification
 *
 * Log output: /data/etaHEN/hv_research2.log
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ps5/kernel.h>

/* Notification helper */
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

/* Direct memory allocation */
int sceKernelAllocateDirectMemory(off_t searchStart, off_t searchEnd,
                                  size_t len, size_t alignment,
                                  int memoryType, off_t *physAddrOut);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot,
                             int flags, off_t directMemoryStart,
                             size_t alignment);

#define SCE_KERNEL_WB_ONION    0
#define SCE_KERNEL_PROT_CPU_READ   0x01
#define SCE_KERNEL_PROT_CPU_WRITE  0x02
#define SCE_KERNEL_PROT_CPU_RW     0x03

/* Kernel struct offsets */
#define OFFSET_PROC_P_VMSPACE    0x200
#define OFFSET_PMAP_PM_PML4      0x020

/* Embedded kernel module (.ko) */
__asm__ (
    ".section .rodata\n"
    ".global KMOD_KO\n"
    ".type KMOD_KO, @object\n"
    ".align 16\n"
    "KMOD_KO:\n"
    ".incbin \"kmod/hv_kmod2.ko\"\n"
    "KMOD_KO_END:\n"
    ".global KMOD_KO_SZ\n"
    ".type KMOD_KO_SZ, @object\n"
    ".align 16\n"
    "KMOD_KO_SZ:\n"
    ".quad KMOD_KO_END - KMOD_KO\n"
);

extern const unsigned char KMOD_KO[];
extern const uint64_t KMOD_KO_SZ;

/* Kmod shared data structures (must match kmod/hv_kld2.c) */
#define KMOD2_MAGIC          0xCAFEBABEDEAD2337ULL
#define KMOD2_STATUS_INIT    0
#define KMOD2_STATUS_RUNNING 1
#define KMOD2_STATUS_DONE    2

#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL

struct kmod2_result_buf {
    volatile uint64_t magic;
    volatile uint32_t status;
    volatile uint32_t pad0;
    volatile uint64_t trampoline_func_kva;
    volatile uint64_t trampoline_target_kva;
    volatile uint32_t num_msr_results;
    volatile uint32_t pad1;
    struct {
        uint32_t msr_id;
        uint32_t valid;
        uint64_t value;
    } msr_results[32];
    volatile uint64_t apic_base_msr;
    volatile uint64_t apic_base_pa;
    volatile uint32_t apic_is_x2apic;
    volatile uint32_t pad2;
};

/* kldsym lookup structure */
struct kld_sym_lookup {
    int         version;
    char       *symname;
    uint64_t    symvalue;
    uint64_t    symsize;
};

#define SYS_kldload     304
#define SYS_kldunload   305
#define SYS_kldfind     306
#define SYS_kldnext     307
#define SYS_kldstat     308
#define SYS_kldsym      337
#define KLDSYM_LOOKUP   1

struct kld_file_stat {
    int         version;
    char        name[1024];
    int         refs;
    int         id;
    uint64_t    address;
    uint64_t    size;
    char        pathname[1024];
};

/* Global state */
static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_cr3_phys = 0;

/* apic_ops discovery */
static uint64_t g_apic_ops_addr = 0;
static int      g_apic_ops_count = 0;

/* Kmod state */
static int      g_kmod_kid = -1;

/* Page table constants */
#define PTE_PRESENT   (1ULL << 0)
#define PTE_PS        (1ULL << 7)
#define PTE_PA_MASK   0x000FFFFFFFFFF000ULL
#define MAX_SAFE_PA   0x800000000ULL
#define PTE_BIT_RW    (1ULL << 1)
#define PTE_BIT_NX    (1ULL << 63)
#define PTE_BIT_XOTEXT (1ULL << 58)

/* Sysent constants */
#define SYSENT_STRIDE 0x30

/* ps5-kstuff offsets for FW 4.03 (relative to kdata_base) */
#define KSTUFF_IDT_OFF         0x64cdc80ULL
#define KSTUFF_GDT_OFF         0x64cee30ULL
#define KSTUFF_TSS_OFF         0x64d0830ULL
#define KSTUFF_PCPU_OFF        0x64d2280ULL
#define KSTUFF_DORETI_IRET_OFF (-0x9cf84cLL)
#define KSTUFF_NOP_RET_OFF     (-0x9d20caLL)
#define KSTUFF_JUSTRETURN_OFF  (-0x9cf990LL)
#define KSTUFF_XINVTLB_OFF    (-0x96be70LL)
#define KSTUFF_QA_FLAGS_OFF    0x6506498ULL
#define KSTUFF_SYSENTS_OFF     0x1709c0ULL

/* Persistence markers */
#define P7_CAVE_MAGIC    0x464C41545A484F4FULL  /* "FLATZHOO" */
#define PHASE7_MARKER    0x42EFCDABUL
#define P9_ARMED_MAGIC   0x5039484F4F4B4544ULL  /* "P9HOOKED" */


/* ─── DMAP base discovery ─── */
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

    kernel_copyout(vmspace + 0x1D0, &pmap_addr, sizeof(pmap_addr));
    if (!pmap_addr) {
        printf("[-] Failed to get pmap\n");
        return -1;
    }

    kernel_copyout(pmap_addr + OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
    printf("[*] pm_pml4 = 0x%lx\n", pm_pml4);

    static const int cr3_offsets[] = {0x28, 0x30, 0x38, 0x40, 0x48};
    for (int i = 0; i < 5; i++) {
        kernel_copyout(pmap_addr + cr3_offsets[i], &candidate_cr3, sizeof(candidate_cr3));
        if (candidate_cr3 == 0 || candidate_cr3 > 0x800000000ULL)
            continue;
        if (candidate_cr3 & 0xFFF)
            continue;

        uint64_t candidate_dmap = pm_pml4 - candidate_cr3;
        if ((candidate_dmap >> 47) != 0 && candidate_dmap > 0xFFFF800000000000ULL) {
            uint64_t verify;
            if (kernel_copyout(candidate_dmap + candidate_cr3 + OFFSET_PMAP_PM_PML4,
                              &verify, sizeof(verify)) == 0) {
                g_dmap_base = candidate_dmap;
                g_cr3_phys = candidate_cr3;
                printf("[+] DMAP base discovered: 0x%lx (cr3=0x%lx)\n",
                       g_dmap_base, candidate_cr3);
                return 0;
            }
        }
    }

    printf("[!] Could not discover DMAP via pmap, trying common bases...\n");
    static const uint64_t common_dmap[] = {
        0xFFFFFF0000000000ULL, 0xFFFFFE8000000000ULL,
        0xFFFF808000000000ULL, 0xFFFF800000000000ULL,
    };
    for (int i = 0; i < 4; i++) {
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

/* ─── FW version detection ─── */
static int init_fw_offsets(void) {
    g_fw_version = kernel_get_fw_version() & 0xFFFF0000;
    g_kdata_base = KERNEL_ADDRESS_DATA_BASE;
    g_ktext_base = KERNEL_ADDRESS_TEXT_BASE;

    printf("[*] FW version: 0x%lx\n", g_fw_version);
    printf("[*] Kernel data base: 0x%lx\n", g_kdata_base);
    printf("[*] Kernel text base: 0x%lx\n", g_ktext_base);

    switch (g_fw_version) {
    case 0x4000000: case 0x4020000: case 0x4030000:
    case 0x4500000: case 0x4510000:
        printf("[+] FW 4.xx detected\n");
        break;
    default:
        printf("[!] Warning: FW 0x%lx may not be fully supported\n", g_fw_version);
        break;
    }
    return 0;
}

/* ─── Page table walking ─── */
static uint64_t va_to_cpu_pa(uint64_t va) {
    if (!g_cr3_phys || !g_dmap_base) {
        printf("[!] va_to_cpu_pa: no CR3 or DMAP base\n");
        return 0;
    }

    uint64_t pml4e, pdpte, pde, pte;

    kernel_copyout(g_dmap_base + g_cr3_phys + ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
    if (!(pml4e & PTE_PRESENT)) return 0;

    kernel_copyout(g_dmap_base + (pml4e & PTE_PA_MASK) + ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
    if (!(pdpte & PTE_PRESENT)) return 0;
    if (pdpte & PTE_PS) return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    kernel_copyout(g_dmap_base + (pdpte & PTE_PA_MASK) + ((va >> 21) & 0x1FF) * 8, &pde, 8);
    if (!(pde & PTE_PRESENT)) return 0;
    if (pde & PTE_PS) return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

    kernel_copyout(g_dmap_base + (pde & PTE_PA_MASK) + ((va >> 12) & 0x1FF) * 8, &pte, 8);
    if (!(pte & PTE_PRESENT)) return 0;
    return (pte & PTE_PA_MASK) | (va & 0xFFF);
}

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

/* Read a guest PTE for a given VA (returns the full PTE value, not the PA) */
static uint64_t read_guest_pte(uint64_t va, int *level_out) {
    if (!g_cr3_phys || !g_dmap_base) return 0;
    uint64_t e;

    kernel_copyout(g_dmap_base + g_cr3_phys + ((va >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { if (level_out) *level_out = 4; return 0; }

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { if (level_out) *level_out = 3; return 0; }
    if (e & PTE_PS) { if (level_out) *level_out = 3; return e; }

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 21) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { if (level_out) *level_out = 2; return 0; }
    if (e & PTE_PS) { if (level_out) *level_out = 2; return e; }

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 12) & 0x1FF) * 8, &e, 8);
    if (level_out) *level_out = 1;
    return e;
}


/* ─── Phase 1: Kernel Reconnaissance ─── */
static void phase1_kernel_recon(void) {
    printf("\n=============================================\n");
    printf("  Phase 1: Kernel Reconnaissance\n");
    printf("=============================================\n\n");

    printf("[*] KERNEL_ADDRESS_TEXT_BASE  = 0x%lx\n", KERNEL_ADDRESS_TEXT_BASE);
    printf("[*] KERNEL_ADDRESS_DATA_BASE = 0x%lx\n", KERNEL_ADDRESS_DATA_BASE);
    printf("[*] KERNEL_ADDRESS_ALLPROC   = 0x%lx\n", KERNEL_ADDRESS_ALLPROC);
    printf("[*] DMAP base                = 0x%lx\n", g_dmap_base);
    printf("[*] CR3 (physical)           = 0x%lx\n", g_cr3_phys);

    /* Security flags */
    if (KERNEL_ADDRESS_SECURITY_FLAGS) {
        uint8_t secflags[16];
        kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, secflags, sizeof(secflags));
        printf("\n[*] Security flags: ");
        for (int i = 0; i < 16; i++) printf("%02x", secflags[i]);
        printf("\n");
    }

    /* QA flags */
    uint8_t qaflags[16];
    if (kernel_get_qaflags(qaflags) == 0) {
        printf("[*] QA flags: ");
        for (int i = 0; i < 16; i++) printf("%02x", qaflags[i]);
        printf("\n");
    }

    /* Guest PTE analysis for ktext and kdata */
    printf("\n[*] Guest PTE analysis:\n");
    int level;

    uint64_t ktext_pte = read_guest_pte(g_ktext_base, &level);
    printf("    ktext PTE: 0x%016lx (level=%d) P=%d RW=%d NX=%d bit58=%d\n",
           (unsigned long)ktext_pte, level,
           (int)(ktext_pte & 1), (int)((ktext_pte >> 1) & 1),
           (int)(ktext_pte >> 63), (int)((ktext_pte >> 58) & 1));

    uint64_t kdata_pte = read_guest_pte(g_kdata_base, &level);
    printf("    kdata PTE: 0x%016lx (level=%d) P=%d RW=%d NX=%d bit58=%d\n",
           (unsigned long)kdata_pte, level,
           (int)(kdata_pte & 1), (int)((kdata_pte >> 1) & 1),
           (int)(kdata_pte >> 63), (int)((kdata_pte >> 58) & 1));

    fflush(stdout);
}

/* ─── Phase 2: kldload + kmod execution ─── */
static void phase2_kmod_load(void) {
    printf("\n=============================================\n");
    printf("  Phase 2: Kernel Module Load\n");
    printf("=============================================\n\n");

    /* Allocate physically-contiguous output buffer */
    off_t dmem_phys = 0;
    void *out_buf = NULL;
    size_t buf_sz = 0x4000;  /* 16KB */

    int ret = sceKernelAllocateDirectMemory(0, 0x300000000ULL,
                                            buf_sz, 0x4000,
                                            SCE_KERNEL_WB_ONION, &dmem_phys);
    if (ret != 0) {
        printf("[-] sceKernelAllocateDirectMemory failed: %d\n", ret);
        return;
    }

    ret = sceKernelMapDirectMemory(&out_buf, buf_sz,
                                   SCE_KERNEL_PROT_CPU_RW, 0,
                                   dmem_phys, 0);
    if (ret != 0) {
        printf("[-] sceKernelMapDirectMemory failed: %d\n", ret);
        return;
    }

    memset(out_buf, 0, buf_sz);
    printf("[*] Output buffer: VA=0x%lx, dmem_phys=0x%lx\n",
           (unsigned long)out_buf, (unsigned long)dmem_phys);

    /* Resolve CPU physical address via page table walk */
    uint64_t buf_cpu_pa = va_to_cpu_pa((uint64_t)out_buf);
    if (!buf_cpu_pa) {
        printf("[-] Failed to resolve output buffer PA\n");
        return;
    }
    printf("[*] Output buffer CPU PA: 0x%lx\n", (unsigned long)buf_cpu_pa);

    uint64_t output_kva = g_dmap_base + buf_cpu_pa;
    printf("[*] Output KVA (DMAP): 0x%lx\n", (unsigned long)output_kva);

    /* Write .ko to disk */
    printf("[*] Writing kmod to /data/etaHEN/hv_kmod2.ko (%lu bytes)...\n",
           (unsigned long)KMOD_KO_SZ);

    /* Ensure directory exists */
    mkdir("/data/etaHEN", 0777);

    /* Create a mutable copy with sentinel patched */
    uint8_t *ko_copy = malloc(KMOD_KO_SZ);
    if (!ko_copy) {
        printf("[-] malloc failed for ko_copy\n");
        return;
    }
    memcpy(ko_copy, KMOD_KO, KMOD_KO_SZ);

    /* Patch OUTPUT_KVA_SENTINEL -> output_kva in the .ko's .data/.bss */
    int patched = 0;
    for (size_t i = 0; i + 8 <= KMOD_KO_SZ; i++) {
        uint64_t val;
        memcpy(&val, &ko_copy[i], 8);
        if (val == OUTPUT_KVA_SENTINEL) {
            memcpy(&ko_copy[i], &output_kva, 8);
            patched++;
            printf("[+] Patched sentinel at .ko offset 0x%lx\n", (unsigned long)i);
        }
    }
    if (!patched) {
        printf("[!] WARNING: No sentinel found in .ko — kmod may not write results\n");
    }

    FILE *f = fopen("/data/etaHEN/hv_kmod2.ko", "wb");
    if (!f) {
        printf("[-] fopen failed: %s\n", strerror(errno));
        free(ko_copy);
        return;
    }
    fwrite(ko_copy, 1, KMOD_KO_SZ, f);
    fclose(f);
    free(ko_copy);
    printf("[+] .ko written to disk\n");

    /* Load the module */
    printf("[*] Calling kldload...\n");
    fflush(stdout);

    int kid = syscall(SYS_kldload, "/data/etaHEN/hv_kmod2.ko");
    printf("[*] kldload returned kid=%d (errno=%d)\n", kid, errno);

    if (kid < 0) {
        printf("[-] kldload failed\n");
        return;
    }
    g_kmod_kid = kid;

    /* kldstat for module info */
    struct kld_file_stat kstat;
    memset(&kstat, 0, sizeof(kstat));
    kstat.version = sizeof(kstat);
    int ks_ret = syscall(SYS_kldstat, kid, &kstat);
    printf("[*] kldstat: ret=%d, name='%s', addr=0x%lx, size=%lu\n",
           ks_ret, kstat.name, (unsigned long)kstat.address,
           (unsigned long)kstat.size);

    /* Wait for SYSINIT/MOD_LOAD to fire */
    printf("[*] Waiting for kmod init (up to 20s)...\n");
    fflush(stdout);

    struct kmod2_result_buf *results = (struct kmod2_result_buf *)out_buf;
    int init_ok = 0;

    for (int wait = 0; wait < 40; wait++) {
        usleep(500000);  /* 500ms */
        if (results->magic == KMOD2_MAGIC && results->status == KMOD2_STATUS_DONE) {
            printf("[+] Kmod init completed after %d.%ds\n", (wait + 1) / 2, ((wait + 1) % 2) * 5);
            init_ok = 1;
            break;
        }
        if (results->magic == KMOD2_MAGIC && results->status == KMOD2_STATUS_RUNNING) {
            printf("[*] Kmod running... (wait %d.%ds)\n", (wait + 1) / 2, ((wait + 1) % 2) * 5);
        }
        if (wait == 3) {
            printf("[*] Still waiting (canary=0x%lx)...\n", (unsigned long)results->magic);
        }
    }

    if (!init_ok) {
        printf("[!] Kmod init didn't complete via SYSINIT/MOD_LOAD.\n");
        printf("    magic=0x%lx, status=%u\n",
               (unsigned long)results->magic, results->status);

        /* Try IDT trampoline invocation (same as hv_research) */
        printf("[*] Attempting IDT trampoline invocation...\n");
        /* For now, just report status - IDT invocation is complex */
        printf("    (IDT trampoline not implemented in hv_research2 yet)\n");
    }

    if (init_ok) {
        /* Dump MSR results */
        printf("\n[*] MSR/CR results from ring-0 (%u entries):\n",
               results->num_msr_results);
        for (uint32_t i = 0; i < results->num_msr_results && i < 32; i++) {
            if (!results->msr_results[i].valid) continue;
            uint32_t id = results->msr_results[i].msr_id;
            uint64_t val = results->msr_results[i].value;
            const char *name = "unknown";
            switch (id) {
            case 0xC0000080: name = "MSR_EFER"; break;
            case 0xC0000081: name = "MSR_STAR"; break;
            case 0xC0000082: name = "MSR_LSTAR"; break;
            case 0xC0000084: name = "MSR_SFMASK"; break;
            case 0xC0000100: name = "MSR_FS_BASE"; break;
            case 0xC0000101: name = "MSR_GS_BASE"; break;
            case 0xC0000102: name = "MSR_KERNEL_GS_BASE"; break;
            case 0xC0000103: name = "MSR_TSC_AUX"; break;
            case 0x0000001B: name = "MSR_APIC_BASE"; break;
            case 0xFFFF0000: name = "CR0"; break;
            case 0xFFFF0003: name = "CR3"; break;
            case 0xFFFF0004: name = "CR4"; break;
            }
            printf("    %-20s (0x%08x) = 0x%016lx\n",
                   name, id, (unsigned long)val);
        }

        /* APIC info */
        printf("\n[*] APIC info from ring-0:\n");
        printf("    APIC_BASE MSR:   0x%016lx\n", (unsigned long)results->apic_base_msr);
        printf("    APIC MMIO PA:    0x%016lx\n", (unsigned long)results->apic_base_pa);
        printf("    x2APIC mode:     %s\n", results->apic_is_x2apic ? "YES" : "NO");

        /* Trampoline addresses */
        printf("\n[*] Kmod trampoline addresses:\n");
        printf("    trampoline_xapic_mode() = 0x%016lx\n",
               (unsigned long)results->trampoline_func_kva);
        printf("    g_trampoline_target     = 0x%016lx\n",
               (unsigned long)results->trampoline_target_kva);
    }

    fflush(stdout);
}


/* ─── Phase A: APIC ops discovery + slot mapping ─── */
static void phaseA_apic_ops_mapping(void) {
    printf("\n=============================================\n");
    printf("  Phase A: APIC ops Discovery + Slot Mapping\n");
    printf("=============================================\n\n");

    if (!g_dmap_base || !g_ktext_base || !g_kdata_base) {
        printf("[-] Missing prerequisites\n");
        return;
    }

    /*
     * Scan kdata for apic_ops vtable:
     * Look for 26-30 consecutive ktext pointers (4-byte aligned).
     * CONFIRMED: On FW 4.03, apic_ops has 28 entries at kdata+0x1656b0.
     */
    uint64_t ktext_scan_size = 0x2000000;  /* 32MB */
    #define SCAN_SIZE   0x800000  /* 8MB of kdata */
    #define SCAN_CHUNK  0x1000    /* 4KB at a time */

    int run_len = 0;
    uint64_t run_start = 0;
    uint64_t best_addr = 0;
    int best_len = 0;
    int best_score = 0;

    uint8_t chunk[SCAN_CHUNK];

    printf("[*] Scanning kdata for apic_ops vtable...\n");
    fflush(stdout);

    for (uint64_t off = 0; off < SCAN_SIZE; off += SCAN_CHUNK) {
        uint64_t scan_kva = g_kdata_base + off;
        uint64_t scan_pa = va_to_pa_quiet(scan_kva);
        if (scan_pa == 0 || scan_pa >= MAX_SAFE_PA) {
            if (run_len >= 26 && run_len <= 30) {
                /* Score candidate */
                uint64_t tbl_pa = va_to_pa_quiet(run_start);
                if (tbl_pa && tbl_pa < MAX_SAFE_PA) {
                    uint64_t tbl[40];
                    int cnt = run_len > 40 ? 40 : run_len;
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
                    if (score > best_score) {
                        best_addr = run_start;
                        best_len = cnt;
                        best_score = score;
                    }
                }
            }
            run_len = 0;
            continue;
        }

        kernel_copyout(g_dmap_base + scan_pa, chunk, SCAN_CHUNK);

        for (int qi = 0; qi < SCAN_CHUNK; qi += 8) {
            uint64_t qval;
            memcpy(&qval, &chunk[qi], 8);
            int is_ktext = (qval >= g_ktext_base &&
                            qval < g_ktext_base + ktext_scan_size &&
                            (qval & 0x3) == 0);
            if (is_ktext) {
                if (run_len == 0)
                    run_start = scan_kva + qi;
                run_len++;
            } else {
                if (run_len >= 26 && run_len <= 30) {
                    uint64_t tbl_pa = va_to_pa_quiet(run_start);
                    if (tbl_pa && tbl_pa < MAX_SAFE_PA) {
                        uint64_t tbl[40];
                        int cnt = run_len > 40 ? 40 : run_len;
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
                        if (score > best_score) {
                            best_addr = run_start;
                            best_len = cnt;
                            best_score = score;
                        }
                    }
                }
                run_len = 0;
            }
        }
    }

    if (!best_addr) {
        printf("[-] apic_ops vtable not found in kdata scan.\n");
        fflush(stdout);
        return;
    }

    g_apic_ops_addr = best_addr;
    g_apic_ops_count = best_len;

    printf("[+] apic_ops found at kdata+0x%lx (%d entries, score=%d)\n",
           (unsigned long)(best_addr - g_kdata_base), best_len, best_score);

    /* Dump all entries with analysis */
    uint64_t ops_pa = va_to_pa_quiet(best_addr);
    if (!ops_pa) {
        printf("[-] apic_ops VA->PA failed\n");
        return;
    }

    int n_ops = best_len > 32 ? 32 : best_len;
    uint64_t ops[32];
    kernel_copyout(g_dmap_base + ops_pa, ops, n_ops * 8);

    /*
     * FreeBSD LAPIC ops structure (from sys/x86/include/apicvar.h):
     *
     * struct apic_ops {
     *    [0]  lapic_init           - LAPIC initialization
     *    [1]  lapic_disable        - Disable LAPIC
     *    [2]  lapic_mode           - Return APIC mode (xAPIC/x2APIC) *** SAFE TO CALL ***
     *    [3]  lapic_read           - Read LAPIC register (MMIO)
     *    [4]  lapic_write          - Write LAPIC register (MMIO) *** DANGEROUS ***
     *    [5]  lapic_ipi_raw        - Send raw IPI
     *    [6]  lapic_ipi_vectored   - Send vectored IPI
     *    [7]  lapic_ipi_wait       - Wait for IPI delivery
     *    [8]  lapic_ipi_alloc      - Allocate IPI vector
     *    [9]  lapic_ipi_free       - Free IPI vector
     *    [10] lapic_set_logical_id - Set logical APIC ID
     *    [11] lapic_create         - Create per-CPU LAPIC state
     *    [12] lapic_setup          - Set up LAPIC for current CPU
     *    [13] lapic_dump           - Dump LAPIC state
     *    [14] lapic_enable_pmc     - Enable PMC NMI
     *    [15] lapic_disable_pmc    - Disable PMC NMI
     *    [16] lapic_reenable_pmc   - Re-enable PMC NMI
     *    [17] lapic_enable_cmc     - Enable CMC
     *    [18] lapic_enable_error   - Enable error interrupt
     *    [19] lapic_set_timer      - Set APIC timer
     *    [20] lapic_handle_intr    - Handle LAPIC interrupt
     *    [21] lapic_timer_enable   - Enable APIC timer
     *    [22] lapic_timer_disable  - Disable APIC timer
     *    [23] lapic_timer_oneshot  - Set one-shot timer
     *    [24] lapic_timer_periodic - Set periodic timer
     *    [25] lapic_timer_deadline - Set TSC deadline timer
     *    [26] lapic_timer_stop     - Stop APIC timer
     *    [27] lapic_calibrate_timer - Calibrate timer
     * };
     *
     * SUSPEND PATH ANALYSIS:
     *   During suspend (cpususpend_handler), the kernel calls:
     *     - lapic_mode [2] to determine APIC type
     *     - POSSIBLY lapic_read [3] / lapic_write [4] for register save
     *     - POSSIBLY lapic_disable [1] to shut down LAPIC
     *
     *   During resume (cpuresume), the kernel calls:
     *     - lapic_mode [2] to determine APIC type
     *     - lapic_setup [12] to reinitialize LAPIC
     *     - lapic_timer_enable [21] to restart timer
     *     - POSSIBLY other init functions
     *
     *   SAFE TO HOOK: Only ops[2] (lapic_mode) - confirmed returns constant.
     *   ALL OTHERS: Access MMIO registers, unsafe to call with wrong args.
     */

    static const char *slot_names[] = {
        "lapic_init",           /* 0 */
        "lapic_disable",        /* 1 */
        "lapic_mode",           /* 2 - SAFE, returns constant */
        "lapic_read",           /* 3 */
        "lapic_write",          /* 4 */
        "lapic_ipi_raw",        /* 5 */
        "lapic_ipi_vectored",   /* 6 */
        "lapic_ipi_wait",       /* 7 */
        "lapic_ipi_alloc",      /* 8 */
        "lapic_ipi_free",       /* 9 */
        "lapic_set_logical_id", /* 10 */
        "lapic_create",         /* 11 */
        "lapic_setup",          /* 12 */
        "lapic_dump",           /* 13 */
        "lapic_enable_pmc",     /* 14 */
        "lapic_disable_pmc",    /* 15 */
        "lapic_reenable_pmc",   /* 16 */
        "lapic_enable_cmc",     /* 17 */
        "lapic_enable_error",   /* 18 */
        "lapic_set_timer",      /* 19 */
        "lapic_handle_intr",    /* 20 */
        "lapic_timer_enable",   /* 21 */
        "lapic_timer_disable",  /* 22 */
        "lapic_timer_oneshot",  /* 23 */
        "lapic_timer_periodic", /* 24 */
        "lapic_timer_deadline", /* 25 */
        "lapic_timer_stop",     /* 26 */
        "lapic_calibrate_timer",/* 27 */
    };

    printf("\n[*] apic_ops vtable dump (%d entries):\n", n_ops);
    printf("    %-4s  %-22s  %-18s  %s\n",
           "Slot", "Name", "Address", "ktext+offset");
    printf("    ─────────────────────────────────────────────────────────────\n");

    /* Find duplicate addresses (shared implementations) */
    for (int i = 0; i < n_ops; i++) {
        const char *name = (i < 28) ? slot_names[i] : "?";
        int is_dup = 0;
        for (int j = 0; j < i; j++) {
            if (ops[j] == ops[i]) { is_dup = 1; break; }
        }
        printf("    [%2d]  %-22s  0x%016lx  ktext+0x%06lx%s\n",
               i, name,
               (unsigned long)ops[i],
               (unsigned long)(ops[i] - g_ktext_base),
               is_dup ? "  (DUP)" : "");
    }

    /* Group by unique address to find function boundaries */
    printf("\n[*] Unique function addresses (sorted):\n");
    uint64_t sorted[32];
    int n_sorted = 0;
    for (int i = 0; i < n_ops; i++) {
        int dup = 0;
        for (int j = 0; j < n_sorted; j++) {
            if (sorted[j] == ops[i]) { dup = 1; break; }
        }
        if (!dup) sorted[n_sorted++] = ops[i];
    }
    /* Sort */
    for (int i = 0; i < n_sorted - 1; i++) {
        for (int j = i + 1; j < n_sorted; j++) {
            if (sorted[j] < sorted[i]) {
                uint64_t t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t;
            }
        }
    }
    for (int i = 0; i < n_sorted; i++) {
        printf("    0x%016lx  (ktext+0x%06lx)",
               (unsigned long)sorted[i],
               (unsigned long)(sorted[i] - g_ktext_base));
        /* Which slots reference this */
        printf("  slots:");
        for (int j = 0; j < n_ops; j++) {
            if (ops[j] == sorted[i]) printf(" %d", j);
        }
        if (i + 1 < n_sorted)
            printf("  gap=%lu", (unsigned long)(sorted[i+1] - sorted[i]));
        printf("\n");
    }

    printf("\n[*] KEY FINDING: ops[2] (lapic_mode) = 0x%016lx\n",
           (unsigned long)ops[2]);
    printf("    This is the ONLY safe function to hook for suspend/resume.\n");
    printf("    All other slots access APIC MMIO and will panic if called\n");
    printf("    with wrong arguments.\n");

    fflush(stdout);
}


/* ─── Phase B: NPT Deep Scan for VMCB Discovery ─── */
static void phaseB_npt_vmcb_scan(void) {
    printf("\n=============================================\n");
    printf("  Phase B: NPT Deep Scan + VMCB Discovery\n");
    printf("=============================================\n\n");

    if (!g_dmap_base) {
        printf("[-] No DMAP base\n");
        return;
    }

    /*
     * The VMCB (Virtual Machine Control Block) is a 4KB-aligned structure
     * used by AMD SVM to control guest execution.  Key signatures:
     *
     * Offset 0x000-0x3FF: Control area
     *   - Offset 0x000 (16 bytes): CR intercept bits
     *   - Offset 0x010 (16 bytes): DR intercept bits
     *   - Offset 0x040 (4 bytes): Exception intercept bitmap
     *   - Offset 0x058 (8 bytes): IOPM_BASE_PA (physical addr of IOPM)
     *   - Offset 0x060 (8 bytes): MSRPM_BASE_PA (physical addr of MSRPM)
     *   - Offset 0x068 (8 bytes): TSC_OFFSET
     *   - Offset 0x090 (4 bytes): VMCB clean bits
     *
     * Offset 0x400-0xFFF: State save area
     *   - Offset 0x400 (16 bytes): ES segment
     *   - Offset 0x410 (16 bytes): CS segment
     *   - Offset 0x420 (16 bytes): SS segment
     *   - Offset 0x430 (16 bytes): DS segment
     *   - Offset 0x5F8 (8 bytes): RAX
     *   - Offset 0x600 (8 bytes): STAR
     *   - Offset 0x608 (8 bytes): LSTAR
     *   - Offset 0x628 (8 bytes): SFMASK
     *   - Offset 0x630 (8 bytes): KernelGsBase
     *   - Offset 0x648 (8 bytes): CR4
     *   - Offset 0x650 (8 bytes): CR3
     *   - Offset 0x658 (8 bytes): CR0
     *
     * We look for pages where:
     *   1. Control area has plausible intercept bits (non-zero, not all-ones)
     *   2. State save area has recognizable kernel addresses (LSTAR, CR3, etc.)
     *   3. CR3 matches our known kernel CR3
     *   4. LSTAR matches our known LSTAR value
     *
     * SAFETY: This is READ-ONLY scanning via DMAP. No writes, no modifications.
     */

    /* Get LSTAR from kstuff */
    uint64_t expected_lstar = g_ktext_base + 0x294218ULL; /* Known LSTAR offset for 4.03 */
    printf("[*] Expected LSTAR: 0x%lx\n", (unsigned long)expected_lstar);
    printf("[*] Known CR3:      0x%lx\n", (unsigned long)g_cr3_phys);

    int vmcb_candidates = 0;
    int pages_scanned = 0;
    int pages_blocked = 0;

    /*
     * Scan strategy: The VMCB must be in physical memory accessible to the HV.
     * The HV itself runs at a higher privilege level but the VMCB is in RAM.
     * Scan the first 2GB of physical memory (0x00000000 - 0x80000000).
     *
     * We read via DMAP in 4KB pages and check for VMCB signatures.
     */
    printf("[*] Scanning PA 0x0 - 0x80000000 for VMCB candidates...\n");
    fflush(stdout);

    /* Also track NPT page table pages with useful info */
    int npt_with_ktext = 0;
    int npt_with_kdata = 0;

    uint64_t ktext_pa_base = va_to_pa_quiet(g_ktext_base);
    uint64_t kdata_pa_base = va_to_pa_quiet(g_kdata_base);

    printf("[*] ktext PA base: 0x%lx\n", (unsigned long)ktext_pa_base);
    printf("[*] kdata PA base: 0x%lx\n", (unsigned long)kdata_pa_base);

    for (uint64_t pa = 0; pa < 0x80000000ULL; pa += 0x1000) {
        /* Progress every 256MB */
        if ((pa & 0x0FFFFFFF) == 0 && pa > 0) {
            printf("[*] Scanning PA 0x%lx... (%d scanned, %d blocked, %d VMCB candidates)\n",
                   (unsigned long)pa, pages_scanned, pages_blocked, vmcb_candidates);
            fflush(stdout);
        }

        /* Read 64 bytes from the page start (enough for initial VMCB check) */
        uint8_t probe[128];
        int ret = kernel_copyout(g_dmap_base + pa, probe, 128);
        if (ret != 0) {
            pages_blocked++;
            continue;
        }
        pages_scanned++;

        /* Check for VMCB state save area at offset 0x400 */
        uint8_t state_probe[128];
        ret = kernel_copyout(g_dmap_base + pa + 0x600, state_probe, 128);
        if (ret != 0) continue;

        uint64_t maybe_star, maybe_lstar, maybe_sfmask, maybe_cr3, maybe_cr0, maybe_cr4;
        memcpy(&maybe_star,   &state_probe[0x00], 8);  /* offset 0x600 = STAR */
        memcpy(&maybe_lstar,  &state_probe[0x08], 8);  /* offset 0x608 = LSTAR */
        memcpy(&maybe_sfmask, &state_probe[0x28], 8);  /* offset 0x628 = SFMASK */
        memcpy(&maybe_cr4,    &state_probe[0x48], 8);  /* offset 0x648 = CR4 */
        memcpy(&maybe_cr3,    &state_probe[0x50], 8);  /* offset 0x650 = CR3 */
        memcpy(&maybe_cr0,    &state_probe[0x58], 8);  /* offset 0x658 = CR0 */

        /* Check LSTAR match (strongest signal) */
        int lstar_match = (maybe_lstar >= g_ktext_base &&
                          maybe_lstar < g_ktext_base + 0x2000000);

        /* Check CR3 match */
        int cr3_match = (maybe_cr3 == g_cr3_phys);

        /* Check CR0 sanity (PE=1, PG=1 at minimum) */
        int cr0_sane = ((maybe_cr0 & 0x80000001ULL) == 0x80000001ULL);

        /* Check STAR sanity (should have valid segment selectors) */
        int star_sane = (maybe_star != 0 && (maybe_star >> 32) != 0);

        /* Score this page */
        int score = 0;
        if (lstar_match) score += 50;
        if (cr3_match) score += 30;
        if (cr0_sane && maybe_cr0 != 0) score += 10;
        if (star_sane) score += 10;
        if (maybe_sfmask != 0) score += 5;

        if (score >= 50) {
            vmcb_candidates++;
            printf("\n[!] VMCB candidate at PA 0x%lx (score=%d):\n",
                   (unsigned long)pa, score);
            printf("    STAR:   0x%016lx %s\n", (unsigned long)maybe_star,
                   star_sane ? "(valid segments)" : "");
            printf("    LSTAR:  0x%016lx %s\n", (unsigned long)maybe_lstar,
                   lstar_match ? "(KTEXT MATCH!)" : "");
            printf("    SFMASK: 0x%016lx\n", (unsigned long)maybe_sfmask);
            printf("    CR4:    0x%016lx\n", (unsigned long)maybe_cr4);
            printf("    CR3:    0x%016lx %s\n", (unsigned long)maybe_cr3,
                   cr3_match ? "(CR3 MATCH!)" : "");
            printf("    CR0:    0x%016lx %s\n", (unsigned long)maybe_cr0,
                   cr0_sane ? "(sane)" : "");

            /* Also read intercept bits from control area */
            uint64_t cr_intercept, dr_intercept;
            uint32_t exc_intercept;
            uint64_t iopm_base, msrpm_base;
            memcpy(&cr_intercept, &probe[0x00], 8);
            memcpy(&dr_intercept, &probe[0x10], 8);
            memcpy(&exc_intercept, &probe[0x40], 4);
            /* Re-read from correct offsets */
            kernel_copyout(g_dmap_base + pa + 0x058, &iopm_base, 8);
            kernel_copyout(g_dmap_base + pa + 0x060, &msrpm_base, 8);

            printf("    CR intercept:  0x%016lx\n", (unsigned long)cr_intercept);
            printf("    DR intercept:  0x%016lx\n", (unsigned long)dr_intercept);
            printf("    Exc intercept: 0x%08x\n", exc_intercept);
            printf("    IOPM_BASE_PA:  0x%016lx\n", (unsigned long)iopm_base);
            printf("    MSRPM_BASE_PA: 0x%016lx\n", (unsigned long)msrpm_base);

            /* Read segment info from state save */
            uint8_t seg_buf[64];
            kernel_copyout(g_dmap_base + pa + 0x400, seg_buf, 64);
            printf("    ES: ");
            for (int si = 0; si < 16; si++) printf("%02x", seg_buf[si]);
            printf("\n    CS: ");
            for (int si = 16; si < 32; si++) printf("%02x", seg_buf[si]);
            printf("\n    SS: ");
            for (int si = 32; si < 48; si++) printf("%02x", seg_buf[si]);
            printf("\n    DS: ");
            for (int si = 48; si < 64; si++) printf("%02x", seg_buf[si]);
            printf("\n");

            /* Dump nCR3 (Nested CR3, offset 0xB0) - this is the NPT root */
            uint64_t ncr3 = 0;
            kernel_copyout(g_dmap_base + pa + 0x0B0, &ncr3, 8);
            printf("    nCR3 (NPT root): 0x%016lx\n", (unsigned long)ncr3);

            fflush(stdout);
        }

        /* Also check for NPT page table pages */
        if (pages_scanned % 4096 == 0) {
            /* Sample check: look for pages containing valid PTE entries
             * that reference ktext or kdata physical addresses */
            uint64_t first_entry;
            memcpy(&first_entry, probe, 8);
            if ((first_entry & PTE_PRESENT) &&
                (first_entry & PTE_PA_MASK) < MAX_SAFE_PA) {
                /* Check if any entries in this page point to ktext/kdata PAs */
                uint64_t entries[64];
                kernel_copyout(g_dmap_base + pa, entries, 512);
                for (int ei = 0; ei < 64; ei++) {
                    uint64_t entry_pa = entries[ei] & PTE_PA_MASK;
                    if (ktext_pa_base && entry_pa >= ktext_pa_base &&
                        entry_pa < ktext_pa_base + 0x2000000) {
                        npt_with_ktext++;
                        break;
                    }
                    if (kdata_pa_base && entry_pa >= kdata_pa_base &&
                        entry_pa < kdata_pa_base + 0x2000000) {
                        npt_with_kdata++;
                        break;
                    }
                }
            }
        }
    }

    printf("\n[*] NPT scan complete:\n");
    printf("    Pages scanned:  %d\n", pages_scanned);
    printf("    Pages blocked:  %d\n", pages_blocked);
    printf("    VMCB candidates: %d\n", vmcb_candidates);
    printf("    NPT pages w/ktext refs: %d\n", npt_with_ktext);
    printf("    NPT pages w/kdata refs: %d\n", npt_with_kdata);

    if (vmcb_candidates == 0) {
        printf("\n[!] No VMCB candidates found in first 2GB.\n");
        printf("    The VMCB may be in HV-private memory not accessible via DMAP.\n");
        printf("    Alternative: The HV may use a different VMCB layout or\n");
        printf("    store it in memory above the DMAP-accessible range.\n");
    }

    fflush(stdout);
}


/* ─── Phase C: ktext Gadget Catalog ─── */
static void phaseC_ktext_gadgets(void) {
    printf("\n=============================================\n");
    printf("  Phase C: ktext Gadget Catalog\n");
    printf("=============================================\n\n");

    if (!g_ktext_base || !g_kdata_base) {
        printf("[-] Missing prerequisites\n");
        return;
    }

    /*
     * Using known kstuff offsets for FW 4.03, catalog useful ktext
     * addresses and their properties.
     *
     * IMPORTANT: We do NOT call these functions (that would be unsafe).
     * We only record their addresses for potential use in hooks.
     *
     * For the flatz method, we need a ktext address that:
     *   1. Is a valid instruction-aligned entry point
     *   2. Returns the correct xapic_mode value (14 or whatever it is)
     *   3. Has no destructive side effects when called from cpususpend_handler
     *
     * Since ktext is XOM, we CANNOT read the actual instructions.
     * We must rely on known offsets from ps5-kstuff or IDT entries.
     */

    uint64_t ks_doreti    = g_kdata_base + (int64_t)KSTUFF_DORETI_IRET_OFF;
    uint64_t ks_nop_ret   = g_kdata_base + (int64_t)KSTUFF_NOP_RET_OFF;
    uint64_t ks_justret   = g_kdata_base + (int64_t)KSTUFF_JUSTRETURN_OFF;
    uint64_t ks_xinvtlb   = g_kdata_base + (int64_t)KSTUFF_XINVTLB_OFF;

    printf("[*] Known ktext entry points (from ps5-kstuff FW 4.03):\n\n");

    struct {
        const char *name;
        uint64_t addr;
        const char *description;
        const char *safety;
    } gadgets[] = {
        {"doreti_iret", ks_doreti,
         "iret instruction in doreti path",
         "UNSAFE via sysent (needs trap frame)"},

        {"nop_ret", ks_nop_ret,
         "nop; ret (wrmsr_ret+2)",
         "SAFE via sysent (returns whatever RAX is)"},

        {"justreturn", ks_justret,
         "Xjustreturn handler (syscall return)",
         "UNSAFE via sysent (hangs/deadlocks)"},

        {"Xinvtlb", ks_xinvtlb,
         "int244 handler (push_pop_all_iret)",
         "UNSAFE via sysent (needs IDT state)"},
    };
    int n_gadgets = sizeof(gadgets) / sizeof(gadgets[0]);

    for (int i = 0; i < n_gadgets; i++) {
        printf("    %-16s 0x%016lx  ktext+0x%06lx\n",
               gadgets[i].name,
               (unsigned long)gadgets[i].addr,
               (unsigned long)(gadgets[i].addr - g_ktext_base));
        printf("                     %s\n", gadgets[i].description);
        printf("                     Safety: %s\n\n", gadgets[i].safety);
    }

    /* Also catalog apic_ops[2] (original xapic_mode) */
    if (g_apic_ops_addr && g_apic_ops_count >= 3) {
        uint64_t ops_pa = va_to_pa_quiet(g_apic_ops_addr);
        if (ops_pa) {
            uint64_t ops[3];
            kernel_copyout(g_dmap_base + ops_pa, ops, 24);
            printf("    %-16s 0x%016lx  ktext+0x%06lx\n",
                   "xapic_mode", (unsigned long)ops[2],
                   (unsigned long)(ops[2] - g_ktext_base));
            printf("                     Original apic_ops[2] function\n");
            printf("                     Safety: SAFE (returns APIC mode constant)\n\n");
        }
    }

    /* IDT handler catalog */
    printf("\n[*] IDT handler addresses (from known kstuff IDT offset):\n");

    uint64_t idt_kva = g_kdata_base + KSTUFF_IDT_OFF;
    uint64_t idt_pa = va_to_pa_quiet(idt_kva);
    if (!idt_pa) {
        printf("[-] IDT VA->PA failed\n");
        fflush(stdout);
        return;
    }

    /* Read all 256 IDT entries (16 bytes each) */
    uint8_t idt_buf[256 * 16];
    kernel_copyout(g_dmap_base + idt_pa, idt_buf, sizeof(idt_buf));

    struct { int vec; const char *name; } interesting_vecs[] = {
        {  0, "#DE divide-by-zero"},
        {  1, "#DB debug"},
        {  2, "NMI"},
        {  3, "#BP breakpoint"},
        {  6, "#UD invalid-opcode"},
        {  8, "#DF double-fault"},
        { 13, "#GP general-protection"},
        { 14, "#PF page-fault"},
        { 18, "#MC machine-check"},
        { 32, "IRQ0 timer"},
        {128, "int80 syscall"},
        {244, "Xinvtlb"},
    };
    int n_vecs = sizeof(interesting_vecs) / sizeof(interesting_vecs[0]);

    printf("    %-4s  %-22s  %-18s  IST  Type  DPL\n",
           "Vec", "Name", "Handler");
    printf("    ──────────────────────────────────────────────────────────\n");

    for (int i = 0; i < n_vecs; i++) {
        int vec = interesting_vecs[i].vec;
        uint8_t *e = &idt_buf[vec * 16];

        uint64_t handler = ((uint64_t)e[11] << 56) | ((uint64_t)e[10] << 48) |
                           ((uint64_t)e[9] << 40)  | ((uint64_t)e[8] << 32)  |
                           ((uint64_t)e[7] << 24)  | ((uint64_t)e[6] << 16)  |
                           ((uint64_t)e[1] << 8)   | (uint64_t)e[0];

        uint8_t ist = e[4] & 0x07;
        uint8_t type = (e[5] >> 0) & 0x0F;
        uint8_t dpl = (e[5] >> 5) & 0x03;
        uint8_t present = (e[5] >> 7) & 0x01;

        if (present) {
            printf("    %3d   %-22s  0x%016lx  %d    %x     %d",
                   vec, interesting_vecs[i].name,
                   (unsigned long)handler, ist, type, dpl);
            if (handler >= g_ktext_base && handler < g_ktext_base + 0x2000000)
                printf("  ktext+0x%lx", (unsigned long)(handler - g_ktext_base));
            printf("\n");
        }
    }

    /* Cross-verify Xinvtlb from IDT[244] vs kstuff offset */
    {
        uint8_t *e244 = &idt_buf[244 * 16];
        uint64_t idt244_handler = ((uint64_t)e244[11] << 56) | ((uint64_t)e244[10] << 48) |
                                  ((uint64_t)e244[9] << 40)  | ((uint64_t)e244[8] << 32)  |
                                  ((uint64_t)e244[7] << 24)  | ((uint64_t)e244[6] << 16)  |
                                  ((uint64_t)e244[1] << 8)   | (uint64_t)e244[0];

        printf("\n[*] Xinvtlb cross-check:\n");
        printf("    IDT[244]: 0x%016lx\n", (unsigned long)idt244_handler);
        printf("    kstuff:   0x%016lx\n", (unsigned long)ks_xinvtlb);
        printf("    Match:    %s\n",
               idt244_handler == ks_xinvtlb ? "YES" : "NO");
    }

    fflush(stdout);
}


/* ─── Phase D: LAPIC MMIO Register Dump ─── */
static void phaseD_lapic_mmio_dump(void) {
    printf("\n=============================================\n");
    printf("  Phase D: LAPIC MMIO Register Dump (via DMAP)\n");
    printf("=============================================\n\n");

    /*
     * The LAPIC is typically mapped at physical address 0xFEE00000
     * (unless relocated via IA32_APIC_BASE MSR).
     *
     * We read LAPIC registers through DMAP to understand the
     * APIC configuration WITHOUT calling any apic_ops functions.
     *
     * SAFETY: Read-only DMAP access to MMIO registers.
     * Some registers may return 0 if the HV intercepts MMIO reads.
     */

    /* Default LAPIC base */
    uint64_t lapic_pa = 0xFEE00000ULL;

    printf("[*] LAPIC physical address: 0x%lx\n", (unsigned long)lapic_pa);
    printf("[*] Reading via DMAP at 0x%lx...\n\n",
           (unsigned long)(g_dmap_base + lapic_pa));

    struct {
        uint32_t offset;
        const char *name;
    } lapic_regs[] = {
        {0x020, "LAPIC_ID"},
        {0x030, "LAPIC_VERSION"},
        {0x080, "TPR (Task Priority)"},
        {0x090, "APR (Arbitration Priority)"},
        {0x0A0, "PPR (Processor Priority)"},
        {0x0D0, "LDR (Logical Destination)"},
        {0x0E0, "DFR (Destination Format)"},
        {0x0F0, "SVR (Spurious Vector)"},
        {0x100, "ISR[0] (In-Service)"},
        {0x170, "ISR[7]"},
        {0x200, "IRR[0] (Interrupt Request)"},
        {0x280, "ESR (Error Status)"},
        {0x300, "ICR_LOW (Interrupt Command)"},
        {0x310, "ICR_HIGH"},
        {0x320, "LVT_TIMER"},
        {0x330, "LVT_THERMAL"},
        {0x340, "LVT_PERFMON"},
        {0x350, "LVT_LINT0"},
        {0x360, "LVT_LINT1"},
        {0x370, "LVT_ERROR"},
        {0x380, "TIMER_ICR (Initial Count)"},
        {0x390, "TIMER_CCR (Current Count)"},
        {0x3E0, "TIMER_DCR (Divide Config)"},
    };
    int n_regs = sizeof(lapic_regs) / sizeof(lapic_regs[0]);

    printf("    %-6s  %-28s  %s\n", "Offset", "Register", "Value");
    printf("    ─────────────────────────────────────────────────\n");

    int regs_read = 0;
    for (int i = 0; i < n_regs; i++) {
        uint32_t val = 0;
        int ret = kernel_copyout(g_dmap_base + lapic_pa + lapic_regs[i].offset,
                                 &val, 4);
        if (ret == 0) {
            printf("    0x%03x   %-28s  0x%08x\n",
                   lapic_regs[i].offset,
                   lapic_regs[i].name, val);
            regs_read++;
        } else {
            printf("    0x%03x   %-28s  (read failed)\n",
                   lapic_regs[i].offset,
                   lapic_regs[i].name);
        }
    }

    printf("\n[*] LAPIC registers read: %d/%d\n", regs_read, n_regs);
    if (regs_read == 0) {
        printf("[!] No LAPIC registers readable via DMAP.\n");
        printf("    The HV may intercept LAPIC MMIO reads.\n");
    }

    fflush(stdout);
}

/* ─── Phase E: apic_ops Function Signature Analysis ─── */
static void phaseE_apic_func_analysis(void) {
    printf("\n=============================================\n");
    printf("  Phase E: apic_ops Function Signature Analysis\n");
    printf("=============================================\n\n");

    if (!g_apic_ops_addr || g_apic_ops_count < 3 || !g_dmap_base) {
        printf("[-] apic_ops not available\n");
        return;
    }

    uint64_t ops_pa = va_to_pa_quiet(g_apic_ops_addr);
    if (!ops_pa) { printf("[-] ops VA->PA failed\n"); return; }

    int n_ops = g_apic_ops_count > 28 ? 28 : g_apic_ops_count;
    uint64_t ops[28];
    kernel_copyout(g_dmap_base + ops_pa, ops, n_ops * 8);

    /*
     * Since ktext is XOM, we can't read the function code directly.
     * However, we CAN determine:
     *   1. Function size estimates from address gaps
     *   2. Whether functions share the same implementation (same address)
     *   3. Relative positions (which are adjacent in ktext)
     *
     * This helps us understand the LAPIC driver structure and
     * identify functions that might be small/simple enough to
     * serve as safe hook targets (like xapic_mode which just
     * returns a constant).
     */

    printf("[*] Function size estimates (from address gaps):\n\n");

    /* Build sorted unique list with slot mapping */
    struct {
        uint64_t addr;
        int slots[28];
        int n_slots;
        uint64_t est_size;
    } funcs[28];
    int n_funcs = 0;

    for (int i = 0; i < n_ops; i++) {
        int found = -1;
        for (int j = 0; j < n_funcs; j++) {
            if (funcs[j].addr == ops[i]) { found = j; break; }
        }
        if (found >= 0) {
            funcs[found].slots[funcs[found].n_slots++] = i;
        } else {
            funcs[n_funcs].addr = ops[i];
            funcs[n_funcs].slots[0] = i;
            funcs[n_funcs].n_slots = 1;
            funcs[n_funcs].est_size = 0;
            n_funcs++;
        }
    }

    /* Sort by address */
    for (int i = 0; i < n_funcs - 1; i++) {
        for (int j = i + 1; j < n_funcs; j++) {
            if (funcs[j].addr < funcs[i].addr) {
                typeof(funcs[0]) tmp = funcs[i];
                funcs[i] = funcs[j];
                funcs[j] = tmp;
            }
        }
    }

    /* Estimate sizes from gaps */
    for (int i = 0; i < n_funcs - 1; i++) {
        funcs[i].est_size = funcs[i+1].addr - funcs[i].addr;
    }

    static const char *slot_names[] = {
        "init", "disable", "mode", "read", "write",
        "ipi_raw", "ipi_vec", "ipi_wait", "ipi_alloc", "ipi_free",
        "set_logid", "create", "setup", "dump",
        "en_pmc", "dis_pmc", "reen_pmc", "en_cmc", "en_error",
        "set_timer", "handle_intr", "timer_en", "timer_dis",
        "timer_1shot", "timer_periodic", "timer_deadline",
        "timer_stop", "calibrate",
    };

    printf("    %-18s  %-10s  %s\n", "Address", "Est.Size", "Slots");
    printf("    ────────────────────────────────────────────────────\n");

    for (int i = 0; i < n_funcs; i++) {
        printf("    0x%016lx  ", (unsigned long)funcs[i].addr);
        if (funcs[i].est_size > 0)
            printf("%-10lu  ", (unsigned long)funcs[i].est_size);
        else
            printf("(last)      ");

        for (int s = 0; s < funcs[i].n_slots; s++) {
            int slot = funcs[i].slots[s];
            if (slot < 28)
                printf("%s(%d) ", slot_names[slot], slot);
            else
                printf("?(%d) ", slot);
        }
        printf("\n");

        /* Flag small functions as potential simple gadgets */
        if (funcs[i].est_size > 0 && funcs[i].est_size <= 16) {
            printf("                      ^^^ VERY SMALL — likely returns constant\n");
        }
    }

    printf("\n[*] Analysis:\n");
    printf("    - Functions <= 16 bytes are likely simple (return constant)\n");
    printf("    - These could potentially serve as safe hook targets\n");
    printf("    - BUT: hooking non-mode functions still risky (caller expectations)\n");
    printf("    - SAFEST approach: use original xapic_mode (ops[2]) with markers\n");

    fflush(stdout);
}


/* ─── Phase F: Suspend with ktext hook + marker verification ─── */
static void phaseF_suspend_test(void) {
    printf("\n=============================================\n");
    printf("  Phase F: Suspend/Resume Test\n");
    printf("=============================================\n\n");

    if (!g_apic_ops_addr || g_apic_ops_count < 3 || !g_dmap_base) {
        printf("[-] Prerequisites not met (apic_ops=%lx, count=%d, dmap=%lx)\n",
               (unsigned long)g_apic_ops_addr, g_apic_ops_count,
               (unsigned long)g_dmap_base);
        return;
    }

    uint64_t ops_pa = va_to_pa_quiet(g_apic_ops_addr);
    if (!ops_pa) { printf("[-] ops VA->PA failed\n"); return; }

    int n_ops = g_apic_ops_count > 28 ? 28 : g_apic_ops_count;
    uint64_t ops[28];
    kernel_copyout(g_dmap_base + ops_pa, ops, n_ops * 8);

    uint64_t original_xapic = ops[2];
    printf("[*] apic_ops[2] (xapic_mode): 0x%016lx\n",
           (unsigned long)original_xapic);

    /* Check for post-resume state */
    int is_post_resume = 0;

    /* Detection 1: QA flags marker */
    uint8_t qa[16] = {0};
    kernel_get_qaflags(qa);
    uint32_t qa_marker = 0;
    memcpy(&qa_marker, &qa[4], 4);
    if (qa_marker == PHASE7_MARKER)
        is_post_resume = 1;

    /* Detection 2: Cave persistence marker */
    uint64_t cave_pa = va_to_pa_quiet(g_kdata_base);
    uint64_t cave_magic = 0;
    if (cave_pa) {
        kernel_copyout(g_dmap_base + cave_pa, &cave_magic, 8);
        if (cave_magic == P7_CAVE_MAGIC)
            is_post_resume = 1;
    }

    if (is_post_resume) {
        /* ─── POST-RESUME PATH ─── */
        printf("\n[+] *** POST-RESUME DETECTED ***\n\n");

        /* Read full cave marker */
        uint64_t saved_xapic = 0, saved_ktext = 0;
        if (cave_pa) {
            uint8_t cave_data[64];
            kernel_copyout(g_dmap_base + cave_pa, cave_data, 64);
            memcpy(&saved_xapic, &cave_data[0x08], 8);
            memcpy(&saved_ktext, &cave_data[0x10], 8);
        }

        /* Display persistence results */
        printf("[*] Persistence check:\n");
        printf("    Cave magic:    0x%016lx %s\n",
               (unsigned long)cave_magic,
               cave_magic == P7_CAVE_MAGIC ? "PERSISTED" : "LOST");
        printf("    Saved ktext:   0x%016lx %s\n",
               (unsigned long)saved_ktext,
               saved_ktext == g_ktext_base ? "(KASLR stable)" : "(KASLR CHANGED!)");
        printf("    Saved xapic:   0x%016lx\n", (unsigned long)saved_xapic);
        printf("    Current xapic: 0x%016lx %s\n",
               (unsigned long)original_xapic,
               (saved_xapic && original_xapic == saved_xapic) ?
               "RETAINED" : "CHANGED");

        printf("    QA flags:      ");
        for (int i = 0; i < 16; i++) printf("%02x ", qa[i]);
        printf("\n");
        printf("    QA bytes 0-1:  %s\n",
               (qa[0] == 0xFF && qa[1] == 0xFF) ? "PERSISTED" : "reinit");

        /* Check P9 armed marker */
        uint64_t p9_marker = 0;
        if (cave_pa) {
            kernel_copyout(g_dmap_base + cave_pa + 0x20, &p9_marker, 8);
        }
        printf("    P9 marker:     0x%016lx %s\n",
               (unsigned long)p9_marker,
               p9_marker == P9_ARMED_MAGIC ? "PERSISTED (hook survived!)" : "not set");

        /* Check ktext readability */
        uint64_t ktext_pa = va_to_pa_quiet(g_ktext_base);
        if (ktext_pa) {
            uint8_t ktext_probe[16];
            memset(ktext_probe, 0xCC, 16);
            kernel_copyout(g_dmap_base + ktext_pa, ktext_probe, 16);
            int all_zero = 1, all_cc = 1;
            for (int i = 0; i < 16; i++) {
                if (ktext_probe[i] != 0x00) all_zero = 0;
                if (ktext_probe[i] != 0xCC) all_cc = 0;
            }
            int readable = (!all_zero && !all_cc);
            printf("    ktext readable: %s\n",
                   readable ? "YES (XOM disabled!)" : "NO (still XOM)");
            if (readable) {
                printf("    ktext bytes: ");
                for (int i = 0; i < 16; i++) printf("%02x ", ktext_probe[i]);
                printf("\n");
            }
        }

        /* Check guest PTE on kdata */
        int pte_level;
        uint64_t kdata_pte = read_guest_pte(g_kdata_base, &pte_level);
        printf("    kdata PTE:     0x%016lx (NX=%d)\n",
               (unsigned long)kdata_pte, (int)(kdata_pte >> 63));

        printf("\n[+] ============================================\n");
        printf("[+]  POST-RESUME ANALYSIS COMPLETE\n");
        printf("[+] ============================================\n");

        /* Clear markers for clean next run */
        memset(&qa[4], 0, 12);
        kernel_set_qaflags(qa);
        printf("[*] QA marker cleared for next run.\n");

        notify("[HV Research 2] Post-resume check complete!");

    } else {
        /* ─── PRE-SUSPEND PATH ─── */
        printf("\n[*] Pre-suspend setup...\n\n");

        /* Step 1: Write persistence markers */
        printf("[*] Step 1: Writing persistence markers...\n");

        if (!cave_pa) {
            printf("[-] kdata VA->PA failed\n");
            fflush(stdout);
            return;
        }

        uint8_t marker[64];
        memset(marker, 0, sizeof(marker));
        uint64_t magic = P7_CAVE_MAGIC;
        memcpy(&marker[0x00], &magic, 8);
        memcpy(&marker[0x08], &original_xapic, 8);
        memcpy(&marker[0x10], &g_ktext_base, 8);

        kernel_copyin(marker, g_dmap_base + cave_pa, 64);

        /* Verify */
        uint8_t verify[64];
        kernel_copyout(g_dmap_base + cave_pa, verify, 64);
        int marker_ok = (memcmp(marker, verify, 64) == 0);
        printf("    Cave marker: %s\n", marker_ok ? "OK" : "MISMATCH");

        /* Step 2: QA flags */
        printf("[*] Step 2: Setting QA flags...\n");
        uint8_t qa_set[16];
        kernel_get_qaflags(qa_set);
        qa_set[0] = 0xFF;
        qa_set[1] = 0xFF;
        uint32_t marker_val = PHASE7_MARKER;
        memcpy(&qa_set[4], &marker_val, 4);
        memcpy(&qa_set[8], &original_xapic, 8);
        kernel_set_qaflags(qa_set);

        uint8_t qa_v[16];
        kernel_get_qaflags(qa_v);
        uint32_t mv = 0;
        memcpy(&mv, &qa_v[4], 4);
        printf("    QA marker: 0x%08x [%s]\n", mv,
               mv == PHASE7_MARKER ? "OK" : "FAIL");

        /* Step 3: Determine suspend hook strategy */
        printf("\n[*] Step 3: Suspend hook strategy...\n");

        /*
         * CONFIRMED from hv_research sessions 1-8:
         *   - kdata code PANICS during suspend (NPT NX enforced)
         *   - kmod .text PANICS during suspend (NPT NX enforced)
         *   - ktext code is the ONLY executable region during suspend
         *   - Original xapic_mode is in ktext and is safe
         *
         * STRATEGY: Hook apic_ops[2] with the ORIGINAL xapic_mode
         * address (a no-op). Use P9_ARMED_MAGIC marker to verify
         * our kdata writes persisted through suspend/resume.
         *
         * This is the SAFEST possible approach:
         *   - apic_ops[2] points to its original ktext function
         *   - No code execution from kdata or kmod during suspend
         *   - Marker-only proof of persistence
         *
         * We DO NOT arm any non-ktext code during suspend.
         */

        /* Write P9_ARMED_MAGIC at cave+0x20 as proof marker */
        {
            uint64_t p9_magic = P9_ARMED_MAGIC;
            kernel_copyin(&p9_magic, g_dmap_base + cave_pa + 0x20, 8);
            uint64_t p9_verify = 0;
            kernel_copyout(g_dmap_base + cave_pa + 0x20, &p9_verify, 8);
            printf("    P9 marker at cave+0x20: 0x%016lx [%s]\n",
                   (unsigned long)p9_verify,
                   p9_verify == P9_ARMED_MAGIC ? "SET" : "FAIL");
        }

        printf("\n    apic_ops[2] left at ORIGINAL value (ktext resident).\n");
        printf("    This is SAFE — confirmed across 8+ suspend/resume cycles.\n");
        printf("    P9 marker will verify kdata persistence after resume.\n");

        /* Step 4: Enter rest mode */
        printf("\n[*] Step 4: Entering rest mode...\n");
        printf("    apic_ops[2] = 0x%016lx (ORIGINAL, safe)\n",
               (unsigned long)original_xapic);
        fflush(stdout);
        fflush(stderr);

        notify("[HV Research 2] Entering REST MODE (safe - original xapic)");
        sleep(3);

        int standby_ret = sceSystemStateMgrEnterStandby();
        printf("[*] sceSystemStateMgrEnterStandby() returned %d\n", standby_ret);
        if (standby_ret != 0) {
            printf("[!] Standby failed (ret=%d, errno=%d)\n", standby_ret, errno);
            notify("[HV Research 2] Standby failed!");
        }
    }

    fflush(stdout);
}


/* ─── Main entry point ─── */
int main(void) {
    notify("[HV Research 2] main() entered");

    FILE *f = fopen("/data/etaHEN/hv_research2.log", "w");
    if (f) {
        fclose(f);
        freopen("/data/etaHEN/hv_research2.log", "w", stdout);
        freopen("/data/etaHEN/hv_research2.log", "a", stderr);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    } else {
        notify("[HV Research 2] ERROR: fopen log failed!");
    }

    printf("\n");
    printf("==============================================\n");
    printf("  PS5 Hypervisor Research Tool 2\n");
    printf("  Target: FW 4.03 (educational/personal use)\n");
    printf("  Log: /data/etaHEN/hv_research2.log\n");
    printf("==============================================\n\n");
    fflush(stdout);

    notify("[HV Research 2] Starting...");

    /* Step 1: FW offsets */
    if (init_fw_offsets() != 0) {
        printf("[-] Failed to initialize FW offsets\n");
        return 1;
    }

    /* Step 2: DMAP base */
    if (discover_dmap_base() != 0) {
        printf("[-] Failed to discover DMAP base\n");
        printf("[!] Continuing without DMAP (limited)\n");
    }

    /* Phase 1: Kernel recon */
    phase1_kernel_recon();

    /* Phase 2: kmod load */
    phase2_kmod_load();

    /* Phase A: APIC ops mapping */
    phaseA_apic_ops_mapping();

    /* Phase B: NPT/VMCB scan */
    if (g_dmap_base) {
        phaseB_npt_vmcb_scan();
    }

    /* Phase C: ktext gadgets */
    phaseC_ktext_gadgets();

    /* Phase D: LAPIC MMIO dump */
    if (g_dmap_base) {
        phaseD_lapic_mmio_dump();
    }

    /* Phase E: apic_ops function analysis */
    phaseE_apic_func_analysis();

    /* Phase F: Suspend test */
    if (g_dmap_base) {
        phaseF_suspend_test();
    }

    printf("\n==============================================\n");
    printf("  All phases complete.\n");
    printf("==============================================\n");

    fflush(stdout);
    fflush(stderr);

    notify("[HV Research 2] Done! Check /data/etaHEN/hv_research2.log");

    return 0;
}
