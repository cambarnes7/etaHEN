/*
 * PS5 APIC Ops Plugin - Userland Loader
 *
 * Standalone ELF payload for PS5 FW 4.03.
 * Uses kstuff-no-fpkg kekcalls (kmem_alloc, kproc_create) to load
 * a flat binary kernel module that reads the APIC ops table.
 *
 * The APIC ops table (struct apic_ops) resides in the kernel's RW data
 * segment. Per flatz's research, overwriting a function pointer there
 * (e.g. xapic_mode at slot[2]) and triggering a suspend/resume cycle
 * executes code before the hypervisor restarts - a key primitive for
 * applying kernel patches on PS5.
 *
 * This plugin:
 *   1. Detects kstuff-no-fpkg kekcall availability
 *   2. Allocates RWX kernel memory via kekcall
 *   3. Loads the flat binary kernel payload
 *   4. Launches it as a kthread via kproc_create kekcall
 *   5. Reads and reports results (apic_ops entries, MSRs, CRs)
 *
 * Usage: Deploy via etaHEN payload loader or send_elf.py
 * Output: /data/etaHEN/kstuff_plugin.log
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <ps5/kernel.h>
#include <ps5/payload.h>

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

/* ─── Global state ─── */

static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_cr3_phys = 0;

/* ─── Embedded flat binary kernel payload ─── */

__asm__ (
    ".section .rodata\n"
    ".global KMOD_FLAT\n"
    ".type KMOD_FLAT, @object\n"
    ".align 16\n"
    "KMOD_FLAT:\n"
    ".incbin \"kmod/apic_kmod.bin\"\n"
    "KMOD_FLAT_END:\n"
    ".global KMOD_FLAT_SZ\n"
    ".type KMOD_FLAT_SZ, @object\n"
    ".align 16\n"
    "KMOD_FLAT_SZ:\n"
    ".quad KMOD_FLAT_END - KMOD_FLAT\n"
);

extern const unsigned char KMOD_FLAT[];
extern const uint64_t KMOD_FLAT_SZ;

/* ─── kstuff kekcall interface ─── */

/*
 * kstuff-no-fpkg multiplexes kernel operations through syscall 0x27
 * (getpid) with magic upper-32-bit prefixes in rax.
 *
 * 0x600000027 → kmem_alloc(size)   : allocate RWX kernel memory
 * 0x700000027 → kproc_create(fn, args, name) : create kernel thread
 * 0xffffffff00000027 → check        : returns 0 if kstuff active
 */

static uint64_t kekcall_kmem_alloc(uint64_t size) {
    uint64_t ret;
    __asm__ volatile(
        "mov $0x600000027, %%rax\n"
        "syscall\n"
        : "=a"(ret)
        : "D"(size)
        : "rcx", "r11", "memory"
    );
    return ret | 0xffffff8000000000ULL;
}

static uint64_t kekcall_kproc_create(uint64_t func, uint64_t args,
                                      uint64_t name) {
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
    return (int)ret;
}

/* ─── Page table walking ─── */

#define PTE_PRESENT   (1ULL << 0)
#define PTE_PS        (1ULL << 7)
#define PTE_PA_MASK   0x000FFFFFFFFFF000ULL

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
        kernel_copyout(pmap_addr + cr3_offsets[i], &candidate_cr3,
                       sizeof(candidate_cr3));
        if (candidate_cr3 == 0 || candidate_cr3 > 0x800000000ULL) continue;
        if (candidate_cr3 & 0xFFF) continue;

        uint64_t candidate_dmap = pm_pml4 - candidate_cr3;
        if ((candidate_dmap >> 47) != 0 &&
            candidate_dmap > 0xFFFF800000000000ULL) {
            uint64_t verify;
            if (kernel_copyout(candidate_dmap + candidate_cr3 +
                              OFFSET_PMAP_PM_PML4,
                              &verify, sizeof(verify)) == 0) {
                g_dmap_base = candidate_dmap;
                g_cr3_phys = candidate_cr3;
                printf("[+] DMAP base: 0x%lx (cr3=0x%lx)\n",
                       g_dmap_base, candidate_cr3);
                return 0;
            }
        }
    }

    printf("[-] Failed to discover DMAP base\n");
    return -1;
}

/* ─── Kmod shared data structures (must match apic_kmod.c) ─── */

#define KMOD_MAGIC          0xA91C095DEAD1337ULL
#define KMOD_STATUS_DONE    2

#define MAX_APIC_OPS_ENTRIES  32
#define MAX_MSR_RESULTS       16

struct apic_ops_entry {
    uint64_t func_ptr;
    uint64_t ktext_offset;
};

struct msr_result {
    uint32_t msr_id;
    uint32_t valid;
    uint64_t value;
};

struct kmod_result_buf {
    volatile uint64_t magic;
    volatile uint32_t status;
    volatile uint32_t error_code;

    volatile uint64_t apic_ops_kva;
    volatile uint32_t apic_ops_count;
    volatile uint32_t apic_ops_pad;
    struct apic_ops_entry apic_ops[MAX_APIC_OPS_ENTRIES];

    volatile uint32_t num_msr_results;
    volatile uint32_t msr_pad;
    struct msr_result msr_results[MAX_MSR_RESULTS];

    volatile uint64_t kdata_base;
    volatile uint64_t ktext_base;
    volatile uint64_t lstar_value;
};

/* ─── Args struct passed to kernel module (must match apic_kmod.c) ─── */

struct kmod_flat_args {
    uint64_t output_kva;
    uint64_t kdata_base;
    uint32_t fw_ver;
    uint32_t pad;
};

/* ─── Known FW 4.03 offsets for verification ─── */

#define FW403_APIC_OPS_OFFSET   0x170650
#define FW403_APIC_OPS_COUNT    28
#define FW403_IDT_OFFSET        0x64cdc80ULL
#define FW403_SYSENTS_OFFSET    0x1709c0ULL

/* apic_ops slot names (from FreeBSD lapic.c) */
static const char *apic_op_names[] = {
    /* 0 */ "create",
    /* 1 */ "init",
    /* 2 */ "xapic_mode",
    /* 3 */ "is_x2apic",
    /* 4 */ "setup",
    /* 5 */ "dump",
    /* 6 */ "disable",
    /* 7 */ "eoi",
    /* 8 */ "id",
    /* 9 */ "set_id",
    /* 10 */ "ipi_raw",
    /* 11 */ "ipi_vectored",
    /* 12 */ "ipi_wait",
    /* 13 */ "ipi_alloc",
    /* 14 */ "ipi_free",
    /* 15 */ "set_lvt_mask",
    /* 16 */ "set_lvt_mode",
    /* 17 */ "set_lvt_polarity",
    /* 18 */ "set_lvt_triggermode",
    /* 19 */ "lvt_eoi_clear",
    /* 20 */ "set_tpr",
    /* 21 */ "get_timer_freq",
    /* 22 */ "timer_enable_intr",
    /* 23 */ "timer_disable_intr",
    /* 24 */ "timer_set_divisor",
    /* 25 */ "timer_initial_count",
    /* 26 */ "timer_current_count",
    /* 27 */ "self_ipi",
};
#define NUM_APIC_OP_NAMES (sizeof(apic_op_names) / sizeof(apic_op_names[0]))

/* ─── Print results ─── */

static void print_results(struct kmod_result_buf *results) {
    printf("\n=============================================\n");
    printf("  APIC Ops Plugin - Ring 0 Results\n");
    printf("=============================================\n\n");

    /* Kernel addresses */
    printf("[*] kdata_base = 0x%016lx\n", (unsigned long)results->kdata_base);
    printf("[*] ktext_base = 0x%016lx\n", (unsigned long)results->ktext_base);
    printf("[*] LSTAR      = 0x%016lx (ktext+0x%lx)\n",
           (unsigned long)results->lstar_value,
           (unsigned long)(results->lstar_value - results->ktext_base));

    /* MSR/CR values */
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
            case 0x0000001B: name = "APIC_BASE"; break;
            case 0xFFFF0000: name = "CR0"; break;
            case 0xFFFF0003: name = "CR3"; break;
            case 0xFFFF0004: name = "CR4"; break;
        }
        printf("    %-12s (0x%08x) = 0x%016lx\n",
               name, id, (unsigned long)val);
    }

    /* apic_ops table */
    printf("\n[*] apic_ops table at 0x%016lx (%u entries):\n",
           (unsigned long)results->apic_ops_kva,
           results->apic_ops_count);
    printf("    kdata offset: 0x%lx\n",
           (unsigned long)(results->apic_ops_kva - results->kdata_base));

    printf("\n    %4s  %-24s  %-18s  %s\n",
           "Slot", "Name", "Address", "ktext offset");
    printf("    %-4s  %-24s  %-18s  %s\n",
           "----", "------------------------",
           "------------------", "------------");

    for (uint32_t i = 0; i < results->apic_ops_count; i++) {
        const char *name = (i < NUM_APIC_OP_NAMES) ?
                           apic_op_names[i] : "???";
        printf("    [%2u]  %-24s  0x%016lx  ktext+0x%lx\n",
               i, name,
               (unsigned long)results->apic_ops[i].func_ptr,
               (unsigned long)results->apic_ops[i].ktext_offset);
    }

    /* Highlight key slots for HV defeat */
    if (results->apic_ops_count > 2) {
        printf("\n[*] Key slots for APIC-based HV defeat (flatz method):\n");
        printf("    xapic_mode (slot[2]): 0x%016lx\n",
               (unsigned long)results->apic_ops[2].func_ptr);
        printf("    → This function pointer is in RW kernel data.\n");
        printf("    → With KRW, overwrite it with a ROP gadget address.\n");
        printf("    → Trigger suspend/resume: code runs before HV restarts.\n");
        printf("    → Use this window to apply kernel patches.\n");
    }
}

/* ─── Main entry point ─── */

int main(void) {
    notify("[APIC Plugin] Starting...");

    FILE *f = fopen("/data/etaHEN/kstuff_plugin.log", "w");
    if (f) {
        fclose(f);
        freopen("/data/etaHEN/kstuff_plugin.log", "w", stdout);
        freopen("/data/etaHEN/kstuff_plugin.log", "a", stderr);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    }

    printf("\n");
    printf("==============================================\n");
    printf("  PS5 APIC Ops Plugin (kstuff-no-fpkg)\n");
    printf("  Target: FW 4.03\n");
    printf("==============================================\n\n");
    fflush(stdout);

    /* ── Init ── */

    g_fw_version = kernel_get_fw_version() & 0xFFFF0000;
    g_kdata_base = KERNEL_ADDRESS_DATA_BASE;
    g_ktext_base = KERNEL_ADDRESS_TEXT_BASE;

    printf("[*] FW: 0x%lx  kdata: 0x%lx  ktext: 0x%lx\n",
           g_fw_version, g_kdata_base, g_ktext_base);

    if (g_fw_version != 0x4030000) {
        printf("[!] WARNING: This plugin is built for FW 4.03.\n");
        printf("    Current FW: 0x%lx — offsets may be wrong.\n",
               g_fw_version);
    }

    /* Discover DMAP base */
    if (discover_dmap_base() != 0) {
        printf("[-] DMAP discovery failed — cannot continue\n");
        notify("[APIC Plugin] DMAP discovery failed!");
        return 1;
    }

    /* ── Check kstuff-no-fpkg ── */

    printf("\n[*] Checking for kstuff-no-fpkg kekcall support...\n");
    int check = kekcall_kstuff_check();
    if (check != 0) {
        printf("[-] kstuff-no-fpkg not loaded (check returned %d = ppid)\n",
               check);
        printf("    Deploy kstuff-no-fpkg's kstuff.elf to "
               "/data/etaHEN/kstuff.elf and reboot.\n");
        notify("[APIC Plugin] kstuff-no-fpkg not loaded!");
        return 1;
    }
    printf("[+] kstuff-no-fpkg active (check returned 0)\n");

    /* ── Allocate result buffer ── */

    #define RESULT_BUF_SIZE 0x4000
    off_t result_phys = 0;
    void *result_vaddr = NULL;

    int ret = sceKernelAllocateDirectMemory(0, 0x180000000ULL,
        RESULT_BUF_SIZE, 0x4000, SCE_KERNEL_WB_ONION, &result_phys);
    if (ret != 0) {
        printf("[-] AllocateDirectMemory failed: 0x%x\n", ret);
        return 1;
    }

    ret = sceKernelMapDirectMemory(&result_vaddr, RESULT_BUF_SIZE,
        SCE_KERNEL_PROT_CPU_RW, 0, result_phys, 0x4000);
    if (ret != 0) {
        printf("[-] MapDirectMemory failed: 0x%x\n", ret);
        return 1;
    }

    memset(result_vaddr, 0, RESULT_BUF_SIZE);

    /* Get DMAP KVA for result buffer */
    uint64_t cpu_pa = va_to_cpu_pa((uint64_t)result_vaddr);
    if (!cpu_pa) {
        printf("[-] Page table walk failed for result buffer\n");
        return 1;
    }
    uint64_t result_kva = g_dmap_base + cpu_pa;
    printf("[+] Result buffer: VA=0x%lx PA=0x%lx DMAP=0x%lx\n",
           (unsigned long)result_vaddr, (unsigned long)cpu_pa,
           (unsigned long)result_kva);

    /* DMAP verify */
    volatile uint64_t *test_ptr = (volatile uint64_t *)result_vaddr;
    *test_ptr = 0xBEEFCAFE12345678ULL;
    uint64_t verify;
    kernel_copyout(result_kva, &verify, sizeof(verify));
    if (verify != 0xBEEFCAFE12345678ULL) {
        printf("[-] DMAP verification failed!\n");
        return 1;
    }
    *test_ptr = 0;
    printf("[+] DMAP verified OK\n");

    /* ── Allocate RWX kernel memory for payload ── */

    size_t payload_size = (size_t)KMOD_FLAT_SZ;
    size_t alloc_size = (payload_size + 0x3FFF) & ~0x3FFFULL;

    printf("\n[*] Allocating %zu bytes (%zu payload) of RWX kernel memory...\n",
           alloc_size, payload_size);

    uint64_t exec_code = kekcall_kmem_alloc(alloc_size);
    if (!exec_code || exec_code == (uint64_t)-1 ||
        exec_code == 0xffffff8000000000ULL) {
        printf("[-] kekcall_kmem_alloc(%zu) failed: 0x%lx\n",
               alloc_size, (unsigned long)exec_code);
        return 1;
    }
    printf("[+] RWX kernel allocation: 0x%lx\n", (unsigned long)exec_code);

    /* Allocate kernel memory for kthread name */
    uint64_t kproc_name = kekcall_kmem_alloc(0x100);
    if (!kproc_name || kproc_name == (uint64_t)-1 ||
        kproc_name == 0xffffff8000000000ULL) {
        printf("[-] kekcall_kmem_alloc(name) failed\n");
        return 1;
    }

    /* Allocate kernel memory for kproc args */
    uint64_t kthread_args = kekcall_kmem_alloc(sizeof(struct kmod_flat_args));
    if (!kthread_args || kthread_args == (uint64_t)-1 ||
        kthread_args == 0xffffff8000000000ULL) {
        printf("[-] kekcall_kmem_alloc(args) failed\n");
        return 1;
    }

    printf("[+] Kernel allocations:\n");
    printf("    exec_code:    0x%lx\n", (unsigned long)exec_code);
    printf("    kproc_name:   0x%lx\n", (unsigned long)kproc_name);
    printf("    kthread_args: 0x%lx\n", (unsigned long)kthread_args);

    /* ── Set up args and write to kernel memory ── */

    struct kmod_flat_args flat_args;
    flat_args.output_kva = result_kva;
    flat_args.kdata_base = g_kdata_base;
    flat_args.fw_ver = (uint32_t)(g_fw_version >> 16);
    flat_args.pad = 0;

    printf("[*] Writing payload to RWX kernel memory...\n");
    kernel_copyin(KMOD_FLAT, exec_code, payload_size);

    static const char kthread_name_str[] = "apic_plugin\0";
    kernel_copyin(kthread_name_str, kproc_name, sizeof(kthread_name_str));
    kernel_copyin(&flat_args, kthread_args, sizeof(flat_args));

    /* Verify payload write */
    uint8_t vfy[16];
    kernel_copyout(exec_code, vfy, 16);
    printf("[*] First 16 bytes at exec_code: ");
    for (int i = 0; i < 16; i++) printf("%02x ", vfy[i]);
    printf("\n");

    if (memcmp(vfy, KMOD_FLAT, 16) == 0)
        printf("[+] Payload write verified OK\n");
    else {
        printf("[-] Payload verification mismatch!\n");
        return 1;
    }

    /* ── Launch kernel thread ── */

    printf("[*] Creating kernel thread at 0x%lx (args=0x%lx)...\n",
           (unsigned long)exec_code, (unsigned long)kthread_args);
    fflush(stdout);

    uint64_t kproc_ret = kekcall_kproc_create(exec_code, kthread_args,
                                                kproc_name);
    printf("[+] kekcall_kproc_create returned: 0x%lx\n",
           (unsigned long)kproc_ret);

    /* ── Wait for completion ── */

    printf("[*] Waiting for kernel module completion...\n");
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;

    for (int i = 0; i < 50; i++) {
        usleep(100000);
        if (results->magic == KMOD_MAGIC &&
            results->status == KMOD_STATUS_DONE) {
            printf("[+] Kernel module completed! (%dms)\n", (i + 1) * 100);
            break;
        }
        if (results->magic == KMOD_MAGIC) {
            printf("    magic OK, status=%u (waiting...)\n", results->status);
        }
    }

    /* ── Report results ── */

    if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
        print_results(results);
        notify("[APIC Plugin] Done! Check kstuff_plugin.log");
    } else {
        printf("\n[-] Kernel module did not complete.\n");
        printf("    magic=0x%lx status=%u error=%u\n",
               (unsigned long)results->magic, results->status,
               results->error_code);
        printf("    Result buffer dump: ");
        uint8_t *rb = (uint8_t *)result_vaddr;
        for (int i = 0; i < 64; i++) printf("%02x ", rb[i]);
        printf("\n");
        notify("[APIC Plugin] Kernel module failed!");
    }

    printf("\n==============================================\n");
    printf("  APIC Ops Plugin complete.\n");
    printf("==============================================\n");

    fflush(stdout);
    fflush(stderr);
    return 0;
}
