/*
 * PS5 Offset Discovery Tool (hv_research2)
 *
 * Standalone ELF payload for discovering ps5-kstuff offsets on unknown
 * firmware versions using TF (Trap Flag) single-stepping.
 *
 * Developed on FW 4.03 where offsets are known (for verification),
 * designed to be deployed on 4.50/4.51 where offsets are unknown.
 *
 * Usage: python3 send_elf.py <ps5_ip> --name hv_research2 hv_research2.elf
 *
 * Output: /data/etaHEN/hv_research2.log
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

static void notify(const char *msg) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, msg, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* ─── Direct memory allocation ─── */

int sceKernelAllocateDirectMemory(off_t searchStart, off_t searchEnd,
                                  size_t len, size_t alignment,
                                  int memoryType, off_t *physAddrOut);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot,
                             int flags, off_t directMemoryStart,
                             size_t alignment);

#define SCE_KERNEL_WB_ONION    0
#define SCE_KERNEL_PROT_CPU_RW 0x03

/* ─── Kernel struct offsets ─── */

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

/* ─── Embedded flat binary kernel payload ─── */

__asm__ (
    ".section .rodata\n"
    ".global KMOD_FLAT\n"
    ".type KMOD_FLAT, @object\n"
    ".align 16\n"
    "KMOD_FLAT:\n"
    ".incbin \"kmod/hv_flat.bin\"\n"
    "KMOD_FLAT_END:\n"
    ".global KMOD_FLAT_SZ\n"
    ".type KMOD_FLAT_SZ, @object\n"
    ".align 16\n"
    "KMOD_FLAT_SZ:\n"
    ".quad KMOD_FLAT_END - KMOD_FLAT\n"
);

extern const unsigned char KMOD_FLAT[];
extern const uint64_t KMOD_FLAT_SZ;

/* ─── kstuff kekcall interface (PS5_kldload approach) ─── */

/* kstuff multiplexes kernel operations through syscall 0x27 (getpid)
 * with magic upper-32-bit prefixes in rax. */

static uint64_t kekcall_kmem_alloc(uint64_t size) {
    uint64_t ret;
    __asm__ volatile(
        "mov $0x600000027, %%rax\n"
        "syscall\n"
        : "=a"(ret)
        : "D"(size)
        : "rcx", "r11", "memory"
    );
    /* kmem_alloc returns lower bits; OR with kernel VA mask */
    return ret | 0xffffff8000000000ULL;
}

static uint64_t kekcall_kproc_create(uint64_t func, uint64_t args, uint64_t name) {
    uint64_t ret;
    __asm__ volatile(
        "mov $0x700000027, %%rax\n"
        "syscall\n"
        : "=a"(ret)
        : "D"(func), "S"(args), "d"(name)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static int kekcall_kstuff_check(void) {
    uint64_t ret;
    __asm__ volatile(
        "mov $0xffffffff00000027, %%rax\n"
        "syscall\n"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    /* kstuff_check returns 0 if kstuff is active */
    return (int)ret;
}

/* Args struct passed to flat binary module_start (must match hv_flat.c) */
struct kmod_flat_args {
    uint64_t output_kva;
    uint64_t kdata_base;
    uint32_t fw_ver;
    uint32_t pad;
};

/* ─── Kmod shared data structures (must match kmod/hv_kld.c) ─── */

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_STATUS_DONE    2
#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL

struct kmod_result_buf {
    volatile uint64_t magic;
    volatile uint32_t status;
    volatile uint32_t pad0;
    volatile uint64_t idt_trampoline_kva;
    volatile uint32_t num_msr_results;
    volatile uint32_t pad1;
    struct {
        uint32_t msr_id;
        uint32_t valid;
        uint64_t value;
    } msr_results[16];
};

/* kld syscall numbers */
#define SYS_kldload     304
#define SYS_kldunload   305
#define SYS_kldstat     308

struct kld_file_stat {
    int         version;
    char        name[1024];
    int         refs;
    int         id;
    uint64_t    address;
    uint64_t    size;
    char        pathname[1024];
};

/* ─── Known ps5-kstuff offsets for FW 4.03 (verification targets) ─── */

#define KSTUFF_IDT_OFF         0x64cdc80ULL
#define KSTUFF_GDT_OFF         0x64cee30ULL
#define KSTUFF_TSS_OFF         0x64d0830ULL
#define KSTUFF_PCPU_OFF        0x64d2280ULL
#define KSTUFF_SYSENTS_OFF     0x1709c0ULL
#define KSTUFF_QA_FLAGS_OFF    0x6506498ULL
#define KSTUFF_DORETI_IRET_OFF (-0x9cf84cLL)
#define KSTUFF_NOP_RET_OFF     (-0x9d20caLL)
#define KSTUFF_JUSTRETURN_OFF  (-0x9cf990LL)
#define KSTUFF_XINVTLB_OFF     (-0x96be70LL)
#define KSTUFF_COPYIN_OFF      (-0x9908e0LL)
#define KSTUFF_COPYOUT_OFF     (-0x990990LL)

/* ─── Global state ─── */

static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_cr3_phys = 0;

/* Sysent discovery */
static uint64_t g_sysent_kva = 0;
#define SYSENT_STRIDE 0x30  /* 48 bytes per sysent entry on PS5 */

/* apic_ops discovery */
static uint64_t g_apic_ops_addr = 0;
static int      g_apic_ops_count = 0;

/* Kmod info */
static int g_kmod_kid = -1;

/* ─── Page table walking ─── */

#define PTE_PRESENT   (1ULL << 0)
#define PTE_PS        (1ULL << 7)
#define PTE_PA_MASK   0x000FFFFFFFFFF000ULL
#define MAX_SAFE_PA   0x800000000ULL  /* 32GB */

/* ─── DMAP base discovery ─── */

static int discover_dmap_base(void) {
    uint64_t proc, vmspace, pmap_addr, pm_pml4, candidate_cr3;

    proc = kernel_get_proc(getpid());
    if (!proc) { printf("[-] Failed to get proc\n"); return -1; }

    kernel_copyout(proc + OFFSET_PROC_P_VMSPACE, &vmspace, sizeof(vmspace));
    if (!vmspace) { printf("[-] Failed to get vmspace\n"); return -1; }

    kernel_copyout(vmspace + 0x1D0, &pmap_addr, sizeof(pmap_addr));
    if (!pmap_addr) { printf("[-] Failed to get pmap\n"); return -1; }

    kernel_copyout(pmap_addr + OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
    printf("[*] pm_pml4 = 0x%lx\n", pm_pml4);

    static const int cr3_offsets[] = {0x28, 0x30, 0x38, 0x40, 0x48};
    for (int i = 0; i < 5; i++) {
        kernel_copyout(pmap_addr + cr3_offsets[i], &candidate_cr3, sizeof(candidate_cr3));
        if (candidate_cr3 == 0 || candidate_cr3 > 0x800000000ULL) continue;
        if (candidate_cr3 & 0xFFF) continue;

        uint64_t candidate_dmap = pm_pml4 - candidate_cr3;
        if ((candidate_dmap >> 47) != 0 && candidate_dmap > 0xFFFF800000000000ULL) {
            uint64_t verify;
            if (kernel_copyout(candidate_dmap + candidate_cr3 + OFFSET_PMAP_PM_PML4,
                              &verify, sizeof(verify)) == 0) {
                g_dmap_base = candidate_dmap;
                g_cr3_phys = candidate_cr3;
                printf("[+] DMAP base: 0x%lx (cr3=0x%lx)\n", g_dmap_base, candidate_cr3);
                return 0;
            }
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

    printf("[*] FW: 0x%lx  kdata: 0x%lx  ktext: 0x%lx\n",
           g_fw_version, g_kdata_base, g_ktext_base);

    switch (g_fw_version) {
    case 0x4000000: case 0x4020000: case 0x4030000:
    case 0x4500000: case 0x4510000:
        printf("[+] FW 4.xx detected\n");
        break;
    default:
        printf("[!] FW 0x%lx may not be fully supported\n", g_fw_version);
        break;
    }
    return 0;
}

/* ─── Physical address resolution ─── */

static uint64_t va_to_cpu_pa(uint64_t va) {
    if (!g_cr3_phys || !g_dmap_base) return 0;

    uint64_t e;
    kernel_copyout(g_dmap_base + g_cr3_phys + ((va >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PML4E not present for 0x%lx\n", va); return 0; }

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PDPTE not present for 0x%lx\n", va); return 0; }
    if (e & PTE_PS) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 21) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PDE not present for 0x%lx\n", va); return 0; }
    if (e & PTE_PS) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 12) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PTE not present for 0x%lx\n", va); return 0; }
    return (e & PTE_PA_MASK) | (va & 0xFFF);
}

/* Silent page table walk */
static uint64_t va_to_pa(uint64_t va) {
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

/* ─── Sysent table discovery ─── */

static void discover_sysent(void) {
    printf("\n[*] Discovering sysent table...\n");

    /* Try known offset first */
    uint64_t ks_sysent = g_kdata_base + KSTUFF_SYSENTS_OFF;
    uint64_t pa = va_to_pa(ks_sysent);
    if (!pa) {
        printf("[-] sysent VA->PA failed\n");
        return;
    }

    /* Verify: sysent[20] = getpid, narg should be 0 */
    int32_t narg = -1;
    uint64_t getpid_pa = va_to_pa(ks_sysent + 20ULL * SYSENT_STRIDE);
    if (getpid_pa) {
        kernel_copyout(g_dmap_base + getpid_pa, &narg, 4);
    }

    if (narg == 0) {
        g_sysent_kva = ks_sysent;
        printf("[+] sysent at kdata+0x%lx (getpid narg=%d) [VERIFIED]\n",
               (unsigned long)KSTUFF_SYSENTS_OFF, narg);
    } else {
        printf("[-] sysent verification failed (getpid narg=%d)\n", narg);
        printf("    Will need to scan for sysent on this FW.\n");
    }
}

/* ─── apic_ops discovery ─── */

#define APIC_OPS_KNOWN_OFFSET  0x170650  /* Known offset on FW 4.03 */
#define APIC_OPS_KNOWN_COUNT   28

/* Check if value looks like a ktext function pointer */
static int is_ktext_ptr(uint64_t val) {
    return (val >= g_ktext_base &&
            val < g_ktext_base + 0x2000000 &&
            (val & 0x3) == 0);
}

static void discover_apic_ops(void) {
    printf("\n[*] Discovering apic_ops table...\n");

    /* ── Direct check at known FW 4.03 offset ── */
    {
        uint64_t known_kva = g_kdata_base + APIC_OPS_KNOWN_OFFSET;
        uint64_t known_pa = va_to_pa(known_kva);
        printf("[*] Direct check at known offset kdata+0x%x...\n",
               APIC_OPS_KNOWN_OFFSET);
        if (known_pa && known_pa < MAX_SAFE_PA) {
            uint64_t ptrs[40];
            kernel_copyout(g_dmap_base + known_pa, ptrs, sizeof(ptrs));
            int run = 0;
            for (int i = 0; i < 40; i++) {
                if (is_ktext_ptr(ptrs[i])) run++;
                else break;
            }
            if (run >= 20) {
                g_apic_ops_addr = known_kva;
                g_apic_ops_count = run;
                printf("[+] CONFIRMED: apic_ops at kdata+0x%x (%d entries)\n",
                       APIC_OPS_KNOWN_OFFSET, run);
                printf("    slot[2] (xapic_mode) = 0x%016lx (ktext+0x%lx)\n",
                       (unsigned long)ptrs[2],
                       (unsigned long)(ptrs[2] - g_ktext_base));
                return;
            }
            printf("    Only %d consecutive ktext ptrs at known offset\n", run);
        } else {
            printf("    Page not mapped at known offset\n");
        }
    }

    /* ── Full scan: read kdata in 4KB chunks via DMAP ──
     *
     * Read page-sized chunks to avoid cross-page reads.
     * Track runs of consecutive ktext pointers across chunk boundaries.
     * Score candidates by entry count, uniqueness, and spread. */
    printf("[*] Full scan: kdata 8MB for apic_ops...\n");

    #define APIC_SCAN_SIZE   0x800000  /* 8MB */
    #define APIC_SCAN_CHUNK  0x1000    /* 4KB per read */

    int best_len = 0, best_score = 0;
    uint64_t best_addr = 0;
    int run_len = 0;
    uint64_t run_start = 0;
    uint8_t chunk[APIC_SCAN_CHUNK];

    for (uint64_t off = 0; off < APIC_SCAN_SIZE; off += APIC_SCAN_CHUNK) {
        uint64_t scan_kva = g_kdata_base + off;
        uint64_t scan_pa = va_to_pa(scan_kva);
        if (!scan_pa || scan_pa >= MAX_SAFE_PA) {
            /* Page not mapped — end any current run */
            if (run_len >= 4) goto score_run;
            run_len = 0;
            continue;
        }

        kernel_copyout(g_dmap_base + scan_pa, chunk, APIC_SCAN_CHUNK);
        uint64_t *qwords = (uint64_t *)chunk;
        int nqwords = APIC_SCAN_CHUNK / 8;

        for (int qi = 0; qi < nqwords; qi++) {
            if (is_ktext_ptr(qwords[qi])) {
                if (run_len == 0)
                    run_start = scan_kva + qi * 8;
                run_len++;
            } else {
                if (run_len >= 4) goto score_run;
                run_len = 0;
                continue;
            score_run: ;
                /* Score this candidate */
                if (run_len >= 26 && run_len <= 32) {
                    /* Re-read the full table from run_start */
                    uint64_t rs_pa = va_to_pa(run_start);
                    if (rs_pa && rs_pa < MAX_SAFE_PA) {
                        uint64_t tbl[40];
                        int cnt = run_len;
                        if (cnt > 40) cnt = 40;
                        kernel_copyout(g_dmap_base + rs_pa, tbl, cnt * 8);

                        /* Compute uniqueness and spread */
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

                        int score = 0;
                        if (cnt == 28) score += 15;
                        else if (cnt >= 26 && cnt <= 30) score += 10;
                        /* Real apic_ops: spread 4KB-64KB */
                        if (spread >= 0x1000 && spread <= 0x10000) score += 20;
                        score += uniq;
                        /* Require slot[2] to be a valid ktext ptr */
                        if (cnt > 2 && is_ktext_ptr(tbl[2])) score += 10;

                        printf("    [TABLE] kdata+0x%lx: %d entries, %d unique, "
                               "spread=%luKB, score=%d\n",
                               (unsigned long)(run_start - g_kdata_base),
                               cnt, uniq,
                               (unsigned long)(spread >> 10), score);

                        if (score > best_score) {
                            best_score = score;
                            best_len = cnt;
                            best_addr = run_start;
                        }
                    }
                }
                run_len = 0;
            }
        }
    }
    /* Handle final run */
    if (run_len >= 26 && run_len <= 32) {
        uint64_t rs_pa = va_to_pa(run_start);
        if (rs_pa && rs_pa < MAX_SAFE_PA) {
            uint64_t tbl[40];
            int cnt = run_len;
            if (cnt > 40) cnt = 40;
            kernel_copyout(g_dmap_base + rs_pa, tbl, cnt * 8);
            int uniq = 0;
            for (int u = 0; u < cnt; u++) {
                int dup = 0;
                for (int v = 0; v < u; v++)
                    if (tbl[v] == tbl[u]) { dup = 1; break; }
                if (!dup) uniq++;
            }
            int score = (cnt == 28 ? 15 : 10) + uniq;
            if (cnt > 2 && is_ktext_ptr(tbl[2])) score += 10;
            if (score > best_score) {
                best_score = score;
                best_len = cnt;
                best_addr = run_start;
            }
        }
    }

    if (best_addr) {
        g_apic_ops_addr = best_addr;
        g_apic_ops_count = best_len;

        /* Read and display the winning table */
        uint64_t pa = va_to_pa(best_addr);
        uint64_t tbl[40];
        kernel_copyout(g_dmap_base + pa, tbl, best_len * 8);
        printf("[+] apic_ops at 0x%lx (kdata+0x%lx), %d entries, score=%d\n",
               (unsigned long)best_addr,
               (unsigned long)(best_addr - g_kdata_base),
               best_len, best_score);
        printf("    slot[2] (xapic_mode) = 0x%016lx (ktext+0x%lx)\n",
               (unsigned long)tbl[2],
               (unsigned long)(tbl[2] - g_ktext_base));
        for (int i = 0; i < best_len; i++) {
            printf("    [%2d] 0x%016lx  (ktext+0x%lx)\n",
                   i, (unsigned long)tbl[i],
                   (unsigned long)(tbl[i] - g_ktext_base));
        }
    } else {
        printf("[-] apic_ops not found in 8MB scan\n");
    }
}

/* ─── Kmod loading infrastructure ─── */

/* Minimal ELF64 types for symbol lookup */
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

/* ─── kstuff-based flat binary loading (PS5_kldload approach) ─── */

static int g_kstuff_available = 0;

static int load_kmod_kstuff(void *result_vaddr, uint64_t result_kva) {
    printf("\n[*] Trying kstuff kekcall approach...\n");

    /* Check if kstuff is active */
    int kcheck = kekcall_kstuff_check();
    printf("[*] kstuff_check() returned %d\n", kcheck);
    if (kcheck != 0) {
        printf("[-] kstuff not available (ret=%d)\n", kcheck);
        return -1;
    }
    g_kstuff_available = 1;
    printf("[+] kstuff is active!\n");

    /* Test kmem_alloc: call with 0x100 and check result.
     * If kstuff doesn't handle 0x600000027, the syscall falls through
     * to getpid (syscall 0x27), returning our PID instead of a KVA.
     * A real kmem_alloc result should be page-aligned (low bits = 0). */
    uint64_t raw_ret;
    __asm__ volatile(
        "mov $0x600000027, %%rax\n"
        "mov %1, %%rdi\n"
        "syscall\n"
        : "=a"(raw_ret)
        : "r"((uint64_t)0x100)
        : "rcx", "r11", "rdi", "memory"
    );
    uint64_t test_alloc = raw_ret | 0xffffff8000000000ULL;
    pid_t my_pid = getpid();
    pid_t my_ppid = getppid();
    printf("[*] kmem_alloc(0x100) raw=0x%lx full=0x%lx\n",
           (unsigned long)raw_ret, (unsigned long)test_alloc);
    printf("    pid=%d ppid=%d\n", my_pid, my_ppid);

    /* If raw return matches our PID, kstuff didn't intercept */
    if ((int)raw_ret == my_pid || (int)raw_ret == my_ppid) {
        printf("[-] kmem_alloc returned PID — kstuff kekcall not supported\n");
        printf("    This kstuff build doesn't multiplex syscall 0x27\n");
        return -1;
    }
    /* Sanity: result should be page-aligned or at least > 0x1000 */
    if (raw_ret < 0x1000) {
        printf("[-] kmem_alloc returned suspicious value 0x%lx\n",
               (unsigned long)raw_ret);
        return -1;
    }
    printf("[+] kmem_alloc test OK: 0x%016lx\n", (unsigned long)test_alloc);

    /* Allocate RWX kernel memory for:
     * 1. Code (flat binary payload)
     * 2. Args struct
     * 3. Thread name */
    size_t code_size = (size_t)KMOD_FLAT_SZ;
    /* Round up to page boundary */
    size_t alloc_size = (code_size + 0x3FFF) & ~0x3FFFULL;

    uint64_t code_kva = kekcall_kmem_alloc(alloc_size);
    uint64_t args_kva = kekcall_kmem_alloc(sizeof(struct kmod_flat_args));
    uint64_t name_kva = kekcall_kmem_alloc(0x100);

    printf("[+] Allocated kernel memory:\n");
    printf("    code: 0x%016lx (%zu bytes, rounded to %zu)\n",
           (unsigned long)code_kva, code_size, alloc_size);
    printf("    args: 0x%016lx\n", (unsigned long)args_kva);
    printf("    name: 0x%016lx\n", (unsigned long)name_kva);

    /* Copy flat binary payload into kernel RWX memory */
    kernel_copyin((void *)KMOD_FLAT, code_kva, code_size);
    printf("[+] Copied %zu bytes of flat binary to kernel\n", code_size);

    /* Set up args */
    struct kmod_flat_args args;
    args.output_kva = result_kva;
    args.kdata_base = g_kdata_base;
    args.fw_ver = (uint32_t)(g_fw_version >> 16);
    args.pad = 0;
    kernel_copyin(&args, args_kva, sizeof(args));

    /* Copy thread name */
    const char *tname = "hv_kmod\0";
    kernel_copyin((void *)tname, name_kva, 8);

    /* Launch kernel thread */
    printf("[*] Creating kernel thread at 0x%lx...\n", (unsigned long)code_kva);
    fflush(stdout);

    kekcall_kproc_create(code_kva, args_kva, name_kva);
    printf("[+] kproc_create returned\n");

    /* Wait for results */
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;
    printf("[*] Waiting for kmod results...\n");
    for (int poll = 0; poll < 100; poll++) {
        usleep(10000);  /* 10ms */
        if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
            printf("[+] Kmod completed after %dms!\n", (poll + 1) * 10);
            return 0;
        }
        if (results->magic == KMOD_MAGIC) {
            printf("[*] Kmod running (status=%u)...\n", results->status);
        }
    }

    printf("[!] Kmod did not complete within 1s (magic=0x%lx status=%u)\n",
           (unsigned long)results->magic, results->status);
    return -1;
}

static void load_kmod(void) {
    printf("\n=============================================\n");
    printf("  Loading Kernel Module\n");
    printf("=============================================\n\n");

    printf("[*] .ko size: %lu bytes\n", KMOD_KO_SZ);

    /* Step 1: Allocate shared result buffer */
    #define KMOD_RESULT_ALLOC_SIZE 0x4000
    off_t result_phys = 0;
    void *result_vaddr = NULL;

    int ret = sceKernelAllocateDirectMemory(0, 0x180000000ULL,
        KMOD_RESULT_ALLOC_SIZE, 0x4000, SCE_KERNEL_WB_ONION, &result_phys);
    if (ret != 0) { printf("[-] AllocateDirectMemory failed: 0x%x\n", ret); return; }

    ret = sceKernelMapDirectMemory(&result_vaddr, KMOD_RESULT_ALLOC_SIZE,
        SCE_KERNEL_PROT_CPU_RW, 0, result_phys, 0x4000);
    if (ret != 0) { printf("[-] MapDirectMemory failed: 0x%x\n", ret); return; }

    memset(result_vaddr, 0, KMOD_RESULT_ALLOC_SIZE);

    uint64_t cpu_pa = va_to_cpu_pa((uint64_t)result_vaddr);
    if (cpu_pa == 0) { printf("[-] Page table walk failed for result buffer\n"); return; }

    uint64_t result_kva = g_dmap_base + cpu_pa;
    printf("[+] Result buffer: VA=0x%lx PA=0x%lx DMAP=0x%lx\n",
           (unsigned long)result_vaddr, (unsigned long)cpu_pa, (unsigned long)result_kva);

    /* DMAP verify */
    volatile uint64_t *test_ptr = (volatile uint64_t *)result_vaddr;
    *test_ptr = 0xBEEFCAFE12345678ULL;
    uint64_t verify;
    kernel_copyout(result_kva, &verify, sizeof(verify));
    if (verify != 0xBEEFCAFE12345678ULL) {
        printf("[-] DMAP verification failed!\n");
        return;
    }
    *test_ptr = 0;
    printf("[+] DMAP verified OK\n");

    /* Step 2: Patch g_output_kva in .ko */
    void *ko_buf = malloc((size_t)KMOD_KO_SZ);
    if (!ko_buf) { printf("[-] malloc failed\n"); return; }
    memcpy(ko_buf, KMOD_KO, (size_t)KMOD_KO_SZ);

    uint8_t *ko_bytes = (uint8_t *)ko_buf;
    int patched = 0;

    Elf64_Ehdr_t *ehdr = (Elf64_Ehdr_t *)ko_bytes;
    if (ehdr->e_shoff && ehdr->e_shnum > 0) {
        Elf64_Shdr_t *shdrs = (Elf64_Shdr_t *)(ko_bytes + ehdr->e_shoff);
        Elf64_Shdr_t *symtab_sh = NULL;
        for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_SYMTAB) { symtab_sh = &shdrs[i]; break; }
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
                            memcpy(ko_bytes + file_off, &result_kva, 8);
                            printf("[+] Patched g_output_kva at .ko+0x%lx -> 0x%lx\n",
                                   (unsigned long)file_off, (unsigned long)result_kva);
                            patched = 1;
                        }
                    }
                    break;
                }
            }
        }
    }

    if (!patched) {
        /* Fallback: patch LAST sentinel occurrence */
        size_t last = (size_t)-1;
        for (size_t i = 0; i + 8 <= (size_t)KMOD_KO_SZ; i++) {
            uint64_t val;
            memcpy(&val, &ko_bytes[i], 8);
            if (val == OUTPUT_KVA_SENTINEL) last = i;
        }
        if (last != (size_t)-1) {
            memcpy(&ko_bytes[last], &result_kva, 8);
            printf("[+] Patched last sentinel at .ko+0x%zx\n", last);
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
    if (!ko) { printf("[-] fopen hv_kmod.ko failed\n"); free(ko_buf); return; }
    fwrite(ko_buf, 1, (size_t)KMOD_KO_SZ, ko);
    fclose(ko);
    free(ko_buf);
    printf("[+] Wrote /data/etaHEN/hv_kmod.ko\n");

    /* Step 3: kldload */
    int kid = syscall(SYS_kldload, "/data/etaHEN/hv_kmod.ko");
    if (kid < 0) {
        printf("[-] kldload failed: errno=%d (%s)\n", errno, strerror(errno));
        kid = 0;
    } else {
        printf("[+] kldload kid=%d\n", kid);
    }
    g_kmod_kid = kid;

    /* Get kldstat info */
    struct kld_file_stat kfs;
    memset(&kfs, 0, sizeof(kfs));
    if (kid > 0) {
        kfs.version = sizeof(kfs);
        int ks_ret = syscall(SYS_kldstat, kid, &kfs);
        if (ks_ret == 0 && kfs.address != 0) {
            printf("[+] kldstat: base=0x%lx size=0x%lx\n",
                   (unsigned long)kfs.address, (unsigned long)kfs.size);
        } else {
            printf("[*] kldstat: address=0x%lx (may need scanner)\n",
                   (unsigned long)(uintptr_t)kfs.address);
        }
    }

    /* Poll for SYSINIT */
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;
    uint64_t first_qword;
    memcpy(&first_qword, (void *)result_vaddr, 8);
    if (first_qword == 0) {
        printf("[*] Polling for deferred SYSINIT...\n");
        for (int poll = 0; poll < 40; poll++) {
            usleep(50000);
            memcpy(&first_qword, (void *)result_vaddr, 8);
            if (first_qword != 0) {
                printf("[+] SYSINIT fired after %dms\n", (poll + 1) * 50);
                break;
            }
        }
    }

    /* ── If SYSINIT didn't fire, scan for trampoline + IDT invoke ──
     *
     * PS5 FW 4.03 does NOT process SYSINIT or MOD_LOAD for kldload'd
     * modules. We locate hv_idt_trampoline in kernel memory by scanning
     * for its machine code signature, then hook an IDT entry to invoke it. */
    if (first_qword == 0) {
        printf("\n[*] SYSINIT did not fire — scanning for trampoline...\n");

        /* hv_idt_trampoline signature */
        static const uint8_t tramp_prefix[] = {
            0x50, 0x51, 0x52, 0x56, 0x57,                         /* push rax..rdi */
            0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,       /* push r8..r11 */
            0x31, 0xff                                              /* xor edi,edi */
        };
        static const uint8_t tramp_suffix[] = {
            0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,       /* pop r11..r8 */
            0x5f, 0x5e, 0x5a, 0x59, 0x58,                         /* pop rdi..rax */
            0x48, 0xcf                                              /* iretq */
        };
        const int suffix_off = 0x14;

        uint64_t trampoline_kva = 0;
        uint8_t hdr[256];

        /* Try kldstat-reported base first */
        if (kfs.address != 0) {
            uint64_t mod_pa = va_to_pa(kfs.address);
            if (mod_pa && mod_pa < MAX_SAFE_PA) {
                if (kernel_copyout(g_dmap_base + mod_pa, hdr, sizeof(hdr)) == 0) {
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = kfs.address;
                        printf("[+] Trampoline at kldstat base 0x%lx\n",
                               (unsigned long)trampoline_kva);
                    }
                }
            }
        }

        /* Hierarchical page-table scan of ktext→top
         * Start from ktext (not kdata) because kmod may be loaded
         * anywhere in the kernel VA range, including between ktext
         * and kdata. */
        if (!trampoline_kva) {
            printf("[*] Hierarchical scan: ktext → top...\n");
            fflush(stdout);

            uint64_t rs = g_ktext_base, re = 0xFFFFFFFFFFE00000ULL;
            uint64_t va = rs & ~0x1FFFFFULL;
            uint64_t pages_checked = 0;

            #define VA_NEXT_2MB(va, re) do { \
                uint64_t _old = (va); (va) += (1ULL << 21); \
                if ((va) <= _old) (va) = (re); \
            } while (0)

            for (; va < re && !trampoline_kva; ) {
                uint64_t pml4e;
                kernel_copyout(g_dmap_base + g_cr3_phys +
                               ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
                if (!(pml4e & PTE_PRESENT)) {
                    uint64_t n = (va + (1ULL << 39)) & ~((1ULL << 39) - 1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pdpt_pa = pml4e & PTE_PA_MASK;
                if (pdpt_pa >= MAX_SAFE_PA) {
                    uint64_t n = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pdpte;
                kernel_copyout(g_dmap_base + pdpt_pa +
                               ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
                if (!(pdpte & PTE_PRESENT) || (pdpte & PTE_PS)) {
                    uint64_t n = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pd_pa = pdpte & PTE_PA_MASK;
                if (pd_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                uint64_t pde;
                kernel_copyout(g_dmap_base + pd_pa +
                               ((va >> 21) & 0x1FF) * 8, &pde, 8);
                if (!(pde & PTE_PRESENT)) { VA_NEXT_2MB(va, re); continue; }

                if (pde & PTE_PS) {
                    /* 2MB huge page — check each 4KB */
                    uint64_t base_pa = pde & 0x000FFFFFFFE00000ULL;
                    if (base_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                    uint64_t cs = va & ~0x1FFFFFULL;
                    for (int pi = 0; pi < 512 && !trampoline_kva; pi++) {
                        uint64_t pva = cs + (uint64_t)pi * 0x1000;
                        if (pva < rs) continue;
                        uint64_t pa = base_pa + (uint64_t)pi * 0x1000;
                        if (pa >= MAX_SAFE_PA) continue;
                        uint8_t pg[4096];
                        if (kernel_copyout(g_dmap_base + pa, pg, 4096) != 0) continue;
                        pages_checked++;
                        for (int off = 0; off <= 4096 - suffix_off - (int)sizeof(tramp_suffix); off++) {
                            if (memcmp(pg + off, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                                memcmp(pg + off + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                                trampoline_kva = pva + off;
                                memcpy(hdr, pg + off, (4096 - off > 256) ? 256 : 4096 - off);
                            }
                        }
                    }
                    VA_NEXT_2MB(va, re); continue;
                }

                /* 4KB pages: bulk-read PT */
                uint64_t pt_pa = pde & PTE_PA_MASK;
                if (pt_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                uint64_t pt_entries[512];
                kernel_copyout(g_dmap_base + pt_pa, pt_entries, sizeof(pt_entries));
                uint64_t cs = va & ~0x1FFFFFULL;
                for (int pi = 0; pi < 512 && !trampoline_kva; pi++) {
                    uint64_t pva = cs + (uint64_t)pi * 0x1000;
                    if (pva < rs) continue;
                    if (!(pt_entries[pi] & PTE_PRESENT)) continue;
                    uint64_t pa = pt_entries[pi] & PTE_PA_MASK;
                    if (pa >= MAX_SAFE_PA) continue;
                    uint8_t pg[4096];
                    if (kernel_copyout(g_dmap_base + pa, pg, 4096) != 0) continue;
                    pages_checked++;
                    for (int off = 0; off <= 4096 - suffix_off - (int)sizeof(tramp_suffix); off++) {
                        if (memcmp(pg + off, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                            memcmp(pg + off + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                            trampoline_kva = pva + off;
                            memcpy(hdr, pg + off, (4096 - off > 256) ? 256 : 4096 - off);
                        }
                    }
                }
                VA_NEXT_2MB(va, re);
            }
            printf("    Scanned %lu pages\n", (unsigned long)pages_checked);
        }

        /* Diagnostics: dump raw kldstat buffer to understand PS5 layout */
        if (!trampoline_kva && kid > 0) {
            printf("[*] kldstat diagnostics (raw buffer):\n");
            uint8_t raw_kfs[2080];
            memset(raw_kfs, 0, sizeof(raw_kfs));
            *(int *)raw_kfs = (int)sizeof(raw_kfs);
            int ks2 = syscall(SYS_kldstat, kid, raw_kfs);
            printf("    kldstat ret=%d\n", ks2);
            /* Dump bytes around the address field (offset ~1040) */
            printf("    raw[1028..1063]: ");
            for (int i = 1028; i < 1064 && i < (int)sizeof(raw_kfs); i++)
                printf("%02x ", raw_kfs[i]);
            printf("\n");
            /* Also check if address is at a different offset */
            printf("    Scanning for non-zero uint64 after name[1024]:\n");
            for (int off = 1028; off <= 1060; off += 4) {
                uint64_t v;
                memcpy(&v, raw_kfs + off, 8);
                if (v != 0)
                    printf("      offset %d: 0x%016lx\n", off, (unsigned long)v);
            }
        }

        if (trampoline_kva) {
            printf("[+] FOUND trampoline at 0x%lx\n", (unsigned long)trampoline_kva);

            /* ── Invoke hv_init via sysent hook (no IDT manipulation) ──
             *
             * Extract hv_init address from the trampoline's CALL instruction,
             * hook sysent[253] to point to hv_init, call syscall(253).
             * This avoids IDT hooking which causes panics on PS5. */

            /* The call instruction is at offset 15 (after the push/xor prefix).
             * Format: E8 <rel32>  →  target = call_addr + 5 + rel32 */
            uint64_t hv_init_kva = 0;
            if (hdr[15] == 0xE8) {
                int32_t rel32;
                memcpy(&rel32, &hdr[16], 4);
                hv_init_kva = trampoline_kva + 15 + 5 + (int64_t)rel32;
                printf("[+] hv_init extracted from CALL: 0x%016lx\n",
                       (unsigned long)hv_init_kva);
            } else {
                printf("[-] Expected E8 (CALL) at trampoline+15, got 0x%02x\n",
                       hdr[15]);
            }

            if (hv_init_kva && g_sysent_kva) {
                /* Hook sysent[253].sy_call to hv_init */
                #define KMOD_INVOKE_SYSCALL 253
                uint64_t ent_kva = g_sysent_kva +
                                   (uint64_t)KMOD_INVOKE_SYSCALL * SYSENT_STRIDE;
                uint64_t ent_pa = va_to_pa(ent_kva);
                if (!ent_pa) {
                    printf("[-] sysent[%d] VA->PA failed\n", KMOD_INVOKE_SYSCALL);
                } else {
                    /* Save original sysent entry */
                    uint8_t orig_sysent[SYSENT_STRIDE];
                    kernel_copyout(g_dmap_base + ent_pa, orig_sysent, SYSENT_STRIDE);

                    /* Write hv_init to sy_call (offset +8) */
                    uint64_t call_pa = va_to_pa(ent_kva + 8);
                    if (call_pa) {
                        kernel_copyin(&hv_init_kva, g_dmap_base + call_pa, 8);

                        /* Set narg=0 (offset +0) */
                        int32_t narg_zero = 0;
                        kernel_copyin(&narg_zero, g_dmap_base + ent_pa, 4);

                        printf("[+] sysent[%d] hooked -> hv_init 0x%lx\n",
                               KMOD_INVOKE_SYSCALL, (unsigned long)hv_init_kva);

                        /* Invoke! */
                        printf("[*] Calling syscall(%d) to invoke hv_init...\n",
                               KMOD_INVOKE_SYSCALL);
                        fflush(stdout);

                        syscall(KMOD_INVOKE_SYSCALL);
                        printf("[+] syscall(%d) returned!\n", KMOD_INVOKE_SYSCALL);

                        /* Restore sysent immediately */
                        kernel_copyin(orig_sysent, g_dmap_base + ent_pa,
                                      SYSENT_STRIDE);
                        printf("[+] sysent[%d] restored\n", KMOD_INVOKE_SYSCALL);

                        /* Re-read result buffer */
                        memcpy(&first_qword, (void *)result_vaddr, 8);
                    }
                }
            } else if (!g_sysent_kva) {
                printf("[-] sysent not discovered — cannot invoke kmod\n");
            }
        } else {
            printf("[-] Trampoline not found in kernel memory\n");
        }
    }

    /* Read results */
    if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
        printf("\n[+] Kmod init completed successfully.\n");

        printf("\n[*] MSR/CR values from ring 0:\n");
        for (uint32_t i = 0; i < results->num_msr_results; i++) {
            if (!results->msr_results[i].valid) continue;
            uint32_t id = results->msr_results[i].msr_id;
            uint64_t val = results->msr_results[i].value;
            const char *name = "unknown";
            switch (id) {
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
            }
            printf("    %-10s (0x%08x) = 0x%016lx\n", name, id, (unsigned long)val);
            if (id == 0xC0000082) {
                printf("    → LSTAR is ktext+0x%lx\n",
                       (unsigned long)(val - g_ktext_base));
            }
        }

        if (results->idt_trampoline_kva) {
            printf("[+] IDT trampoline KVA: 0x%016lx\n",
                   (unsigned long)results->idt_trampoline_kva);
        }
    } else {
        printf("[!] Kmod init did not complete (magic=0x%lx status=%u)\n",
               (unsigned long)results->magic, results->status);
        printf("    First qword: 0x%016lx\n", (unsigned long)first_qword);
    }

    /* Unload — DO NOT unload if trampoline was found and may still be needed */
    if (kid > 0) {
        syscall(SYS_kldunload, kid);
        printf("[*] Unloaded kmod (kid=%d)\n", kid);
    }
}

/* ─── Kstuff offset verification ─── */

static void verify_kstuff_offsets(void) {
    printf("\n=============================================\n");
    printf("  Verifying Known Offsets (FW 4.03)\n");
    printf("=============================================\n\n");

    if (g_fw_version != 0x4030000) {
        printf("[*] Not FW 4.03 — skipping known-offset verification.\n");
        printf("    These offsets need to be DISCOVERED on this FW.\n\n");
        return;
    }

    /* IDT verification */
    uint64_t ks_idt = g_kdata_base + KSTUFF_IDT_OFF;
    uint64_t idt_pa = va_to_pa(ks_idt);
    if (idt_pa) {
        /* Read IDT[0] (divide error) — should have a valid ktext handler */
        uint8_t idt0[16];
        kernel_copyout(g_dmap_base + idt_pa, idt0, 16);
        uint64_t handler0 = (uint64_t)idt0[0] | ((uint64_t)idt0[1] << 8) |
                            ((uint64_t)idt0[6] << 16) | ((uint64_t)idt0[7] << 24) |
                            ((uint64_t)*(uint32_t*)&idt0[8] << 32);
        int in_ktext = (handler0 >= g_ktext_base &&
                        handler0 < g_ktext_base + 0x2000000);
        printf("[%c] IDT at kdata+0x%lx: handler[0]=0x%lx %s\n",
               in_ktext ? '+' : '-',
               (unsigned long)KSTUFF_IDT_OFF,
               (unsigned long)handler0,
               in_ktext ? "(ktext)" : "(NOT ktext!)");

        /* Print handlers for key vectors */
        static const struct { int vec; const char *name; } vecs[] = {
            {1, "#DB"}, {3, "#BP"}, {13, "#GP"}, {14, "#PF"},
            {244, "Xinvtlb"}, {255, "Xjustreturn?"},
        };
        for (int vi = 0; vi < (int)(sizeof(vecs)/sizeof(vecs[0])); vi++) {
            uint8_t gate[16];
            uint64_t gate_pa = va_to_pa(ks_idt + vecs[vi].vec * 16);
            if (!gate_pa) continue;
            kernel_copyout(g_dmap_base + gate_pa, gate, 16);
            uint64_t h = (uint64_t)gate[0] | ((uint64_t)gate[1] << 8) |
                         ((uint64_t)gate[6] << 16) | ((uint64_t)gate[7] << 24) |
                         ((uint64_t)*(uint32_t*)&gate[8] << 32);
            printf("    IDT[%3d] %-12s = 0x%016lx (ktext+0x%lx)\n",
                   vecs[vi].vec, vecs[vi].name, (unsigned long)h,
                   (unsigned long)(h - g_ktext_base));
        }
    } else {
        printf("[-] IDT VA->PA failed\n");
    }

    /* ktext offset verification */
    printf("\n[*] ktext offsets (negative from kdata):\n");
    struct { const char *name; int64_t off; } ktext_offs[] = {
        {"doreti_iret",  KSTUFF_DORETI_IRET_OFF},
        {"nop_ret",      KSTUFF_NOP_RET_OFF},
        {"justreturn",   KSTUFF_JUSTRETURN_OFF},
        {"Xinvtlb",      KSTUFF_XINVTLB_OFF},
        {"copyin",       KSTUFF_COPYIN_OFF},
        {"copyout",      KSTUFF_COPYOUT_OFF},
    };
    for (int i = 0; i < (int)(sizeof(ktext_offs)/sizeof(ktext_offs[0])); i++) {
        uint64_t addr = g_kdata_base + ktext_offs[i].off;
        int in_ktext = (addr >= g_ktext_base && addr < g_ktext_base + 0x2000000);
        printf("    %-16s = 0x%016lx (ktext+0x%lx) %s\n",
               ktext_offs[i].name, (unsigned long)addr,
               (unsigned long)(addr - g_ktext_base),
               in_ktext ? "[OK]" : "[BAD]");
    }

    printf("\n");
    fflush(stdout);
}

/* ─── PTE NX-bit management ─── */

/* Clear NX bit on the 2MB PDE covering a given KVA.
 * Returns: 1 if NX was cleared (or already clear), 0 on failure. */
static int clear_pte_nx(uint64_t kva) {
    uint64_t e;
    /* PML4 */
    kernel_copyout(g_dmap_base + g_cr3_phys + ((kva >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    /* PDPT */
    uint64_t pdpt_pa = e & PTE_PA_MASK;
    kernel_copyout(g_dmap_base + pdpt_pa + ((kva >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    /* PD */
    uint64_t pd_pa = e & PTE_PA_MASK;
    uint64_t pd_off = ((kva >> 21) & 0x1FF) * 8;
    kernel_copyout(g_dmap_base + pd_pa + pd_off, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;

    int nx = (int)(e >> 63);
    if (nx) {
        e &= ~(1ULL << 63);  /* clear NX */
        kernel_copyin(&e, g_dmap_base + pd_pa + pd_off, 8);
        printf("[+] Cleared NX on PDE for 0x%lx\n", (unsigned long)kva);
    }
    return 1;
}

/* Check if NX is clear on the PDE covering a given KVA */
static int check_nx_clear(uint64_t kva) {
    uint64_t e;
    kernel_copyout(g_dmap_base + g_cr3_phys + ((kva >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((kva >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((kva >> 21) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    return !(e >> 63);  /* 1 if NX=0 */
}

/* ═══════════════════════════════════════════════════════════════════
 *  Phase 1: Generic TF Single-Step Trace
 *
 *  Traces an arbitrary kernel function by:
 *  1. Allocating a separate direct memory buffer for shellcode
 *  2. Clearing NX on its guest PDE so code can execute
 *  3. Writing #DB handler + launcher shellcode to the buffer
 *  4. Hooking IDT[1] to the #DB handler
 *  5. Hooking sysent[253] to the launcher
 *  6. Calling syscall(253) from userland
 *  7. Reading the trace buffer (RIP, RAX per instruction)
 *
 *  IMPORTANT: We do NOT use kdata for shellcode — those offsets
 *  contain active kernel data and overwriting them causes panics.
 *  Instead we allocate fresh physically-contiguous memory.
 * ═══════════════════════════════════════════════════════════════════ */

#define TF_MAX_TRACE    256
#define TF_TEST_SYSCALL 253   /* nosys — safe to hook */
#define TF_DB_OFF       0x000 /* #DB handler at start of buffer */
#define TF_LAUNCHER_OFF 0x100 /* launcher at +256 */
#define TF_TRACE_OFF    0x200 /* trace buffer at +512 */
/* Buffer size: 0x200 + 256*16 = 0x1200, allocate 0x4000 (16KB) */
#define TF_BUF_SIZE     0x4000

struct tf_trace_entry {
    uint64_t rip;
    uint64_t rax;
};

struct tf_trace_result {
    uint32_t count;
    uint32_t retval;
    struct tf_trace_entry entries[TF_MAX_TRACE];
    int ktext_count;     /* filled by analysis */
};

static int tf_trace_function(uint64_t target_func, struct tf_trace_result *out) {
    memset(out, 0, sizeof(*out));

    printf("[*] TF trace: target = 0x%016lx (ktext+0x%lx)\n",
           (unsigned long)target_func,
           (unsigned long)(target_func - g_ktext_base));

    /* Prerequisites */
    if (!g_sysent_kva) {
        printf("[-] sysent not discovered\n");
        return -1;
    }

    /* Allocate a dedicated buffer for shellcode + trace data.
     * This avoids overwriting active kernel data in kdata. */
    off_t tf_phys = 0;
    void *tf_vaddr = NULL;

    int ret = sceKernelAllocateDirectMemory(0, 0x180000000ULL,
        TF_BUF_SIZE, 0x4000, SCE_KERNEL_WB_ONION, &tf_phys);
    if (ret != 0) {
        printf("[-] AllocateDirectMemory for TF buffer failed: 0x%x\n", ret);
        return -1;
    }
    ret = sceKernelMapDirectMemory(&tf_vaddr, TF_BUF_SIZE,
        SCE_KERNEL_PROT_CPU_RW, 0, tf_phys, 0x4000);
    if (ret != 0) {
        printf("[-] MapDirectMemory for TF buffer failed: 0x%x\n", ret);
        return -1;
    }
    memset(tf_vaddr, 0, TF_BUF_SIZE);

    /* Get CPU PA via page table walk */
    uint64_t tf_cpu_pa = va_to_cpu_pa((uint64_t)tf_vaddr);
    if (!tf_cpu_pa) {
        printf("[-] Page table walk failed for TF buffer\n");
        return -1;
    }

    uint64_t tf_kva = g_dmap_base + tf_cpu_pa;
    printf("[+] TF buffer: VA=0x%lx PA=0x%lx DMAP=0x%lx\n",
           (unsigned long)tf_vaddr, (unsigned long)tf_cpu_pa,
           (unsigned long)tf_kva);

    /* DMAP verify */
    volatile uint64_t *tp = (volatile uint64_t *)tf_vaddr;
    *tp = 0xDEADFACE11111111ULL;
    uint64_t vfy;
    kernel_copyout(tf_kva, &vfy, 8);
    if (vfy != 0xDEADFACE11111111ULL) {
        printf("[-] TF buffer DMAP verify failed!\n");
        return -1;
    }
    *tp = 0;

    /* Clear NX on the PDE covering our DMAP buffer address */
    if (!check_nx_clear(tf_kva)) {
        printf("[*] Clearing NX on TF buffer PDE...\n");
        if (!clear_pte_nx(tf_kva)) {
            printf("[-] Failed to clear NX on TF buffer\n");
            return -1;
        }
    }
    printf("[+] TF buffer NX=0 (code execution enabled)\n");

    /* Compute DMAP addresses for shellcode/trace regions */
    uint64_t db_handler_kva  = tf_kva + TF_DB_OFF;
    uint64_t launcher_kva    = tf_kva + TF_LAUNCHER_OFF;
    uint64_t db_handler_dmap = tf_kva + TF_DB_OFF;
    uint64_t launcher_dmap   = tf_kva + TF_LAUNCHER_OFF;
    uint64_t trace_buf_dmap  = tf_kva + TF_TRACE_OFF;

    /* ── Build #DB handler shellcode ──
     *
     * On entry: CPU pushed SS, RSP, RFLAGS, CS, RIP (TF cleared in RFLAGS)
     * Saved RFLAGS on stack still has TF=1 (IRET re-enables it)
     *
     * Handler:
     *   1. push rax, rbx, rcx
     *   2. Load trace buffer DMAP VA (immediate)
     *   3. Read count from [buf+0]
     *   4. If count >= MAX: clear TF in saved RFLAGS, IRET
     *   5. Store {saved_RIP, saved_RAX} at buf + 8 + count*16
     *   6. Increment count
     *   7. pop rcx, rbx, rax; IRETQ
     */
    {
        uint8_t db[128];
        int dp = 0;

        #define EMIT(b) do { if (dp < (int)sizeof(db)) db[dp++] = (uint8_t)(b); } while(0)
        #define EMIT_U32(v) do { uint32_t _v=(v); if(dp+4<=(int)sizeof(db)){memcpy(&db[dp],&_v,4);dp+=4;} } while(0)
        #define EMIT_U64(v) do { uint64_t _v=(v); if(dp+8<=(int)sizeof(db)){memcpy(&db[dp],&_v,8);dp+=8;} } while(0)

        EMIT(0x50);  /* push rax */
        EMIT(0x53);  /* push rbx */
        EMIT(0x51);  /* push rcx */

        /* movabs $trace_buf_dmap, %rbx */
        EMIT(0x48); EMIT(0xBB); EMIT_U64(trace_buf_dmap);

        /* mov (%rbx), %ecx — load count */
        EMIT(0x8B); EMIT(0x0B);

        /* cmp $TF_MAX_TRACE, %ecx */
        EMIT(0x81); EMIT(0xF9); EMIT_U32(TF_MAX_TRACE);

        /* jge .stop */
        EMIT(0x7D);
        int jge_patch = dp;
        EMIT(0x00);

        /* lea 8(%rbx), %rax */
        EMIT(0x48); EMIT(0x8D); EMIT(0x43); EMIT(0x08);

        /* shl $4, %ecx */
        EMIT(0xC1); EMIT(0xE1); EMIT(0x04);

        /* add %rcx, %rax */
        EMIT(0x48); EMIT(0x01); EMIT(0xC8);

        /* mov 24(%rsp), %rcx — saved RIP */
        EMIT(0x48); EMIT(0x8B); EMIT(0x4C); EMIT(0x24); EMIT(0x18);

        /* mov %rcx, (%rax) — store RIP */
        EMIT(0x48); EMIT(0x89); EMIT(0x08);

        /* mov 16(%rsp), %rcx — saved RAX */
        EMIT(0x48); EMIT(0x8B); EMIT(0x4C); EMIT(0x24); EMIT(0x10);

        /* mov %rcx, 8(%rax) — store RAX */
        EMIT(0x48); EMIT(0x89); EMIT(0x48); EMIT(0x08);

        /* incl (%rbx) — count++ */
        EMIT(0xFF); EMIT(0x03);

        /* pop rcx; pop rbx; pop rax; iretq */
        EMIT(0x59); EMIT(0x5B); EMIT(0x58);
        EMIT(0x48); EMIT(0xCF);

        /* .stop: clear TF in saved RFLAGS */
        int stop_label = dp;
        db[jge_patch] = (uint8_t)(stop_label - (jge_patch + 1));

        /* andq $~0x100, 40(%rsp) */
        EMIT(0x48); EMIT(0x81); EMIT(0x64); EMIT(0x24);
        EMIT(0x28); EMIT_U32(0xFFFFFEFF);

        /* pop rcx; pop rbx; pop rax; iretq */
        EMIT(0x59); EMIT(0x5B); EMIT(0x58);
        EMIT(0x48); EMIT(0xCF);

        printf("[*] #DB handler: %d bytes\n", dp);
        kernel_copyin(db, db_handler_dmap, dp);

        /* Verify */
        uint8_t vfy[128];
        kernel_copyout(db_handler_dmap, vfy, dp);
        if (memcmp(db, vfy, dp) != 0) {
            printf("[-] #DB handler write failed!\n");
            goto restore;
        }
    }

    /* ── Build launcher shellcode ──
     *
     * Called as syscall handler: sys_foo(td, uap)
     *   1. Enable TF (pushfq; or TF; popfq)
     *   2. CALL target (each instruction triggers #DB)
     *   3. Disable TF
     *   4. Store return value to trace buffer +4
     *   5. Return 0 (syscall success)
     */
    {
        uint8_t lc[128];
        int lp = 0;

        #undef EMIT
        #undef EMIT_U32
        #undef EMIT_U64
        #define EMIT(b) do { if (lp < (int)sizeof(lc)) lc[lp++] = (uint8_t)(b); } while(0)
        #define EMIT_U32(v) do { uint32_t _v=(v); if(lp+4<=(int)sizeof(lc)){memcpy(&lc[lp],&_v,4);lp+=4;} } while(0)
        #define EMIT_U64(v) do { uint64_t _v=(v); if(lp+8<=(int)sizeof(lc)){memcpy(&lc[lp],&_v,8);lp+=8;} } while(0)

        /* Save callee-saved */
        EMIT(0x53);  /* push rbx */
        EMIT(0x55);  /* push rbp */
        EMIT(0x41); EMIT(0x54);  /* push r12 */

        /* movabs $target, %r12 */
        EMIT(0x49); EMIT(0xBC); EMIT_U64(target_func);

        /* Enable TF: pushfq; or $0x100, (%rsp); popfq */
        EMIT(0x9C);
        EMIT(0x48); EMIT(0x81); EMIT(0x0C); EMIT(0x24); EMIT_U32(0x100);
        EMIT(0x9D);

        /* call *%r12 */
        EMIT(0x41); EMIT(0xFF); EMIT(0xD4);

        /* Disable TF */
        EMIT(0x9C);
        EMIT(0x48); EMIT(0x81); EMIT(0x24); EMIT(0x24); EMIT_U32(0xFFFFFEFF);
        EMIT(0x9D);

        /* Save return value: movabs $trace_buf_dmap, %rbx; mov %eax, 4(%rbx) */
        EMIT(0x48); EMIT(0xBB); EMIT_U64(trace_buf_dmap);
        EMIT(0x89); EMIT(0x43); EMIT(0x04);

        /* xor eax, eax; restore; ret */
        EMIT(0x31); EMIT(0xC0);
        EMIT(0x41); EMIT(0x5C);  /* pop r12 */
        EMIT(0x5D);              /* pop rbp */
        EMIT(0x5B);              /* pop rbx */
        EMIT(0xC3);              /* ret */

        printf("[*] Launcher: %d bytes\n", lp);
        kernel_copyin(lc, launcher_dmap, lp);

        uint8_t vfy[128];
        kernel_copyout(launcher_dmap, vfy, lp);
        if (memcmp(lc, vfy, lp) != 0) {
            printf("[-] Launcher write failed!\n");
            goto restore;
        }
    }

    /* Clear trace buffer */
    {
        uint8_t zeros[8] = {0};
        kernel_copyin(zeros, trace_buf_dmap, 8);
    }

    /* ── Hook IDT[1] (#DB) ── */
    struct {
        uint16_t offset_lo;
        uint16_t selector;
        uint8_t  ist;
        uint8_t  type_attr;
        uint16_t offset_mid;
        uint32_t offset_hi;
        uint32_t reserved;
    } __attribute__((packed)) orig_idt1, new_idt1;

    uint64_t idt_base = g_kdata_base + KSTUFF_IDT_OFF;
    uint64_t idt1_kva = idt_base + 1 * 16;
    uint64_t idt1_pa  = va_to_pa(idt1_kva);
    if (!idt1_pa) {
        printf("[-] IDT[1] VA->PA failed\n");
        goto restore;
    }

    kernel_copyout(g_dmap_base + idt1_pa, &orig_idt1, 16);
    uint64_t orig_db = (uint64_t)orig_idt1.offset_lo |
                       ((uint64_t)orig_idt1.offset_mid << 16) |
                       ((uint64_t)orig_idt1.offset_hi << 32);
    printf("[*] Original IDT[1]: 0x%016lx (ist=%d)\n",
           (unsigned long)orig_db, orig_idt1.ist);

    memset(&new_idt1, 0, sizeof(new_idt1));
    new_idt1.offset_lo  = (uint16_t)(db_handler_kva & 0xFFFF);
    new_idt1.offset_mid = (uint16_t)((db_handler_kva >> 16) & 0xFFFF);
    new_idt1.offset_hi  = (uint32_t)(db_handler_kva >> 32);
    new_idt1.selector   = orig_idt1.selector;
    new_idt1.ist        = 0;    /* use current kernel stack */
    new_idt1.type_attr  = 0x8E; /* P=1, DPL=0, interrupt gate */

    kernel_copyin(&new_idt1, g_dmap_base + idt1_pa, 16);
    printf("[+] IDT[1] hooked -> 0x%016lx\n", (unsigned long)db_handler_kva);

    /* ── Hook sysent[253] ── */
    uint64_t ent_kva = g_sysent_kva + (uint64_t)TF_TEST_SYSCALL * SYSENT_STRIDE;
    uint64_t ent_pa  = va_to_pa(ent_kva);
    if (!ent_pa) {
        printf("[-] sysent[%d] VA->PA failed! Restoring IDT...\n", TF_TEST_SYSCALL);
        kernel_copyin(&orig_idt1, g_dmap_base + idt1_pa, 16);
        goto restore;
    }

    uint8_t orig_sysent[SYSENT_STRIDE];
    kernel_copyout(g_dmap_base + ent_pa, orig_sysent, SYSENT_STRIDE);

    /* Write launcher_kva to sy_call (offset +8) */
    uint64_t call_pa = va_to_pa(ent_kva + 8);
    kernel_copyin(&launcher_kva, g_dmap_base + call_pa, 8);

    /* Set narg=0 (offset +0) */
    int32_t narg_zero = 0;
    kernel_copyin(&narg_zero, g_dmap_base + ent_pa, 4);

    printf("[+] sysent[%d] hooked -> 0x%016lx\n",
           TF_TEST_SYSCALL, (unsigned long)launcher_kva);

    /* ── Fire! ── */
    printf("[*] Calling syscall(%d)...\n", TF_TEST_SYSCALL);
    fflush(stdout);

    long sc_ret = syscall(TF_TEST_SYSCALL);
    int sc_err = errno;
    printf("[+] syscall returned %ld (errno=%d)\n", sc_ret, sc_err);

    /* ── Restore sysent + IDT immediately ── */
    kernel_copyin(orig_sysent, g_dmap_base + ent_pa, SYSENT_STRIDE);
    kernel_copyin(&orig_idt1, g_dmap_base + idt1_pa, 16);
    printf("[+] sysent[%d] and IDT[1] restored\n", TF_TEST_SYSCALL);

    /* ── Read trace ── */
    uint32_t trace_count = 0, retval = 0;
    kernel_copyout(trace_buf_dmap, &trace_count, 4);
    kernel_copyout(trace_buf_dmap + 4, &retval, 4);

    printf("\n[*] Trace results:\n");
    printf("    Instructions traced: %u (max %d)\n", trace_count, TF_MAX_TRACE);
    printf("    Return value (EAX): %u (0x%x)\n", retval, retval);

    out->count = trace_count;
    out->retval = retval;

    if (trace_count == 0) {
        printf("[-] No trace entries! #DB handler may not have fired.\n");
        goto restore;
    }

    /* Read trace entries */
    int nread = trace_count;
    if (nread > TF_MAX_TRACE) nread = TF_MAX_TRACE;
    kernel_copyout(trace_buf_dmap + 8, out->entries, nread * 16);

    /* Print ktext entries */
    printf("\n    === Instruction Trace ===\n");
    printf("    %4s  %-18s  %-18s  %s\n", "#", "RIP", "RAX", "offset");

    int ktext_count = 0;
    for (int i = 0; i < nread; i++) {
        uint64_t rip = out->entries[i].rip;
        uint64_t rax = out->entries[i].rax;
        int in_ktext = (rip >= g_ktext_base && rip < g_ktext_base + 0x2000000);

        if (in_ktext) {
            printf("    %4d  0x%016lx  0x%016lx  ktext+0x%lx\n",
                   i, (unsigned long)rip, (unsigned long)rax,
                   (unsigned long)(rip - g_ktext_base));
            ktext_count++;
        }
    }
    out->ktext_count = ktext_count;
    printf("\n    ktext entries: %d / %d total\n", ktext_count, nread);

restore:
    /* No kdata to restore — we used a dedicated buffer */
    return (out->count > 0) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Phase 1 Analysis: xapic_mode trace
 * ═══════════════════════════════════════════════════════════════════ */

static void phase1_trace_xapic_mode(void) {
    printf("\n=============================================\n");
    printf("  Phase 1: Trace xapic_mode (TF single-step)\n");
    printf("=============================================\n\n");

    if (!g_apic_ops_addr || g_apic_ops_count < 4) {
        printf("[-] apic_ops not discovered — skipping.\n");
        return;
    }

    /* Get xapic_mode address from apic_ops[2] */
    uint64_t ops_pa = va_to_pa(g_apic_ops_addr);
    if (!ops_pa) {
        printf("[-] apic_ops VA->PA failed\n");
        return;
    }

    uint64_t target;
    kernel_copyout(g_dmap_base + ops_pa + 0x10, &target, 8);  /* slot[2] */
    if (target < g_ktext_base || target >= g_ktext_base + 0x2000000) {
        printf("[-] apic_ops[2] = 0x%lx — not in ktext\n", (unsigned long)target);
        return;
    }

    printf("[*] xapic_mode = apic_ops[2] = 0x%016lx (ktext+0x%lx)\n",
           (unsigned long)target, (unsigned long)(target - g_ktext_base));

    /* Run TF trace */
    struct tf_trace_result trace;
    int ret = tf_trace_function(target, &trace);

    if (ret == 0 && trace.count > 0) {
        printf("\n[+] ============================================\n");
        printf("[+]  XAPIC_MODE TRACED SUCCESSFULLY\n");
        printf("[+] ============================================\n");
        printf("[+]  Return value: %u (0x%x)\n", trace.retval, trace.retval);
        printf("[+]  ktext instructions: %d\n", trace.ktext_count);
        printf("[+]  Total instructions: %u\n", trace.count);

        /* Verify against known offset if on 4.03 */
        if (g_fw_version == 0x4030000) {
            uint64_t expected = g_kdata_base + (int64_t)KSTUFF_DORETI_IRET_OFF;
            printf("[+]\n");
            printf("[+]  Verification (4.03 known offsets):\n");
            printf("[+]    Expected xapic_mode: ktext+0x%lx\n",
                   (unsigned long)(target - g_ktext_base));

            /* Check if any traced instruction matches known offsets */
            for (int i = 0; i < (int)trace.count && i < TF_MAX_TRACE; i++) {
                uint64_t rip = trace.entries[i].rip;
                if (rip == expected) {
                    printf("[+]    FOUND doreti_iret at trace[%d]!\n", i);
                }
            }
        }
    }

    fflush(stdout);
}

/* ─── Main entry point ─── */

int main(void) {
    notify("[Offset Discovery] Starting...");

    FILE *f = fopen("/data/etaHEN/hv_research2.log", "w");
    if (f) {
        fclose(f);
        freopen("/data/etaHEN/hv_research2.log", "w", stdout);
        freopen("/data/etaHEN/hv_research2.log", "a", stderr);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    }

    printf("\n");
    printf("==============================================\n");
    printf("  PS5 Offset Discovery Tool (hv_research2)\n");
    printf("  Firmware: auto-detect\n");
    printf("==============================================\n\n");
    fflush(stdout);

    /* Core initialization */
    if (init_fw_offsets() != 0) return 1;
    if (discover_dmap_base() != 0) {
        printf("[-] DMAP discovery failed — cannot continue\n");
        return 1;
    }

    /* Discover sysent first — needed for kmod invocation */
    discover_sysent();

    /* ── Load kernel module (MSR recon) ──
     * Try kstuff kekcall first (PS5_kldload approach: kmem_alloc + flat binary).
     * Fall back to kldload + trampoline scan if kstuff unavailable. */
    {
        /* Allocate result buffer (shared between kstuff and kldload paths) */
        off_t kmod_phys = 0;
        void *kmod_vaddr = NULL;
        int kmod_ret = sceKernelAllocateDirectMemory(0, 0x180000000ULL,
            0x4000, 0x4000, SCE_KERNEL_WB_ONION, &kmod_phys);
        if (kmod_ret == 0) {
            kmod_ret = sceKernelMapDirectMemory(&kmod_vaddr, 0x4000,
                SCE_KERNEL_PROT_CPU_RW, 0, kmod_phys, 0x4000);
        }
        if (kmod_ret != 0 || !kmod_vaddr) {
            printf("[-] Failed to allocate kmod result buffer — falling back to kldload\n");
            load_kmod();
        } else {
            memset(kmod_vaddr, 0, 0x4000);

            /* Get DMAP address for the result buffer */
            uint64_t kmod_cpu_pa = va_to_cpu_pa((uint64_t)kmod_vaddr);
            uint64_t kmod_result_kva = 0;
            if (kmod_cpu_pa) {
                kmod_result_kva = g_dmap_base + kmod_cpu_pa;
                printf("[+] Kmod result buffer: VA=0x%lx PA=0x%lx DMAP=0x%lx\n",
                       (unsigned long)kmod_vaddr, (unsigned long)kmod_cpu_pa,
                       (unsigned long)kmod_result_kva);
            }

            int kmod_ok = -1;
            if (kmod_result_kva) {
                /* Try kstuff first */
                kmod_ok = load_kmod_kstuff(kmod_vaddr, kmod_result_kva);
            }

            if (kmod_ok != 0) {
                printf("\n[*] kstuff approach failed — falling back to kldload\n");
                load_kmod();
            } else {
                /* Print kstuff results */
                struct kmod_result_buf *results =
                    (struct kmod_result_buf *)kmod_vaddr;
                printf("\n[+] Kmod init completed successfully (kstuff).\n");
                printf("\n[*] MSR/CR values from ring 0:\n");
                for (uint32_t i = 0; i < results->num_msr_results; i++) {
                    if (!results->msr_results[i].valid) continue;
                    uint32_t id = results->msr_results[i].msr_id;
                    uint64_t val = results->msr_results[i].value;
                    const char *name = "unknown";
                    switch (id) {
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
                    }
                    printf("    %-10s (0x%08x) = 0x%016lx\n",
                           name, id, (unsigned long)val);
                    if (id == 0xC0000082) {
                        printf("    → LSTAR is ktext+0x%lx\n",
                               (unsigned long)(val - g_ktext_base));
                    }
                }
            }
        }
    }

    /* Discover apic_ops table */
    discover_apic_ops();

    /* Verify known offsets on 4.03 */
    verify_kstuff_offsets();

    /* Phase 1: TF trace xapic_mode
     *
     * DISABLED: The TF trace writes shellcode to DMAP and tries to execute
     * it.  PS5's hypervisor NPT has NX=1 on DMAP regions, so code execution
     * from DMAP causes a nested page fault → hypervisor panic.
     * Need to relocate shellcode into kmod .text pages (already executable
     * in NPT) before this can work. */
    printf("\n[*] Phase 1 (TF trace) SKIPPED — DMAP exec not safe under HV.\n");
    if (g_sysent_kva && g_apic_ops_addr) {
        printf("    sysent=OK  apic_ops=OK  (ready when shellcode relocation is implemented)\n");
    }

    printf("\n==============================================\n");
    printf("  All phases complete.\n");
    printf("==============================================\n");

    fflush(stdout);
    fflush(stderr);

    notify("[Offset Discovery] Done! Check hv_research2.log");
    return 0;
}
