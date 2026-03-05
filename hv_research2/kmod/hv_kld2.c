/*
 * hv_kld2.c - PS5 Hypervisor Research 2 Kernel Module (KLD)
 *
 * FreeBSD kernel loadable module for PS5 FW 4.03.
 * Loaded via kldload(2), runs init code in kernel context (ring 0).
 *
 * This module focuses on SAFE reconnaissance:
 *   - MSR/CR reading
 *   - APIC base discovery via MSR
 *   - No VMMCALL probing (risk of HV kill)
 *   - Reports its own function addresses for trampoline use
 */

#include <stdint.h>

/* ============================================================
 * FreeBSD kernel module support (manual definitions)
 * ============================================================ */

typedef void (*sysinit_cfunc_t)(const void *);

struct sysinit {
    unsigned int    subsystem;
    unsigned int    order;
    sysinit_cfunc_t func;
    const void     *udata;
};

#define SI_SUB_DRIVERS      0x3100000
#define SI_ORDER_MIDDLE     0x1000000

typedef struct module *module_t;
typedef int (*modeventhand_t)(module_t, int, void *);

typedef enum modeventtype {
    MOD_LOAD     = 1,
    MOD_UNLOAD   = 2,
    MOD_SHUTDOWN = 3,
    MOD_QUIESCE  = 4,
} modeventtype_t;

struct moduledata {
    const char     *name;
    modeventhand_t  evhand;
    void           *priv;
};

#define MDT_MODULE   1
#define MDT_VERSION  5
#define MDTV_GENERIC 2

struct mod_metadata {
    int         md_ver;
    int         md_type;
    void       *md_data;
    const char *md_cval;
};

struct mod_version {
    int mv_version;
};

/* ============================================================
 * Shared data structures (must match main.c definitions)
 * ============================================================ */

#define KMOD2_MAGIC          0xCAFEBABEDEAD2337ULL
#define KMOD2_STATUS_INIT    0
#define KMOD2_STATUS_RUNNING 1
#define KMOD2_STATUS_DONE    2

struct kmod2_result_buf {
    volatile uint64_t magic;
    volatile uint32_t status;
    volatile uint32_t pad0;

    /* Trampoline addresses (KVAs within this module) */
    volatile uint64_t trampoline_func_kva;    /* KVA of trampoline_xapic_mode() */
    volatile uint64_t trampoline_target_kva;  /* KVA of g_trampoline_target */

    /* MSR results */
    volatile uint32_t num_msr_results;
    volatile uint32_t pad1;
    struct {
        uint32_t msr_id;
        uint32_t valid;
        uint64_t value;
    } msr_results[32];

    /* APIC-specific info from ring 0 */
    volatile uint64_t apic_base_msr;    /* IA32_APIC_BASE (MSR 0x1B) */
    volatile uint64_t apic_base_pa;     /* Physical address of LAPIC MMIO */
    volatile uint32_t apic_is_x2apic;   /* x2APIC mode active? */
    volatile uint32_t pad2;
};

/* ============================================================
 * Shared output KVA - patched by userland before loading
 * ============================================================ */

#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL
volatile uint64_t g_output_kva = OUTPUT_KVA_SENTINEL;

/* Local result buffer */
struct kmod2_result_buf hv_results = { .magic = 0x1 };

/* Forward declarations */
extern volatile uint64_t g_trampoline_target;
int trampoline_xapic_mode(void);

/* ============================================================
 * Inline assembly helpers - ring 0 hardware access
 * ============================================================ */

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read_cr0(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline uint64_t read_cr3(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline uint64_t read_cr4(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

static inline void memory_barrier(void) {
    __asm__ volatile("mfence" ::: "memory");
}

/* AMD MSR definitions */
#define MSR_EFER            0xC0000080
#define MSR_STAR            0xC0000081
#define MSR_LSTAR           0xC0000082
#define MSR_SFMASK          0xC0000084
#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define MSR_KERNEL_GS_BASE  0xC0000102
#define MSR_TSC_AUX         0xC0000103
#define MSR_APIC_BASE       0x0000001B

/* ============================================================
 * Campaign: MSR Reconnaissance (safe - no VMMCALL)
 * ============================================================ */

static void campaign_msr_recon(void) {
    static const uint32_t safe_msrs[] = {
        MSR_EFER, MSR_LSTAR, MSR_STAR, MSR_SFMASK,
        MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE, MSR_TSC_AUX,
        MSR_APIC_BASE,
    };
    int num_safe = sizeof(safe_msrs) / sizeof(safe_msrs[0]);

    for (int i = 0; i < num_safe && hv_results.num_msr_results < 32; i++) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = safe_msrs[i];
        hv_results.msr_results[idx].value = rdmsr(safe_msrs[i]);
        hv_results.msr_results[idx].valid = 1;
        memory_barrier();
        hv_results.num_msr_results = idx + 1;
    }

    /* CR values as pseudo-MSRs */
    if (hv_results.num_msr_results < 32) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = 0xFFFF0000;
        hv_results.msr_results[idx].value = read_cr0();
        hv_results.msr_results[idx].valid = 1;
        hv_results.num_msr_results = idx + 1;
    }
    if (hv_results.num_msr_results < 32) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = 0xFFFF0003;
        hv_results.msr_results[idx].value = read_cr3();
        hv_results.msr_results[idx].valid = 1;
        hv_results.num_msr_results = idx + 1;
    }
    if (hv_results.num_msr_results < 32) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = 0xFFFF0004;
        hv_results.msr_results[idx].value = read_cr4();
        hv_results.msr_results[idx].valid = 1;
        hv_results.num_msr_results = idx + 1;
    }

    /* APIC base analysis */
    uint64_t apic_base = rdmsr(MSR_APIC_BASE);
    hv_results.apic_base_msr = apic_base;
    hv_results.apic_base_pa = apic_base & 0xFFFFFFFFFFFFF000ULL;
    hv_results.apic_is_x2apic = (apic_base >> 10) & 1;
}

/* ============================================================
 * Module init
 * ============================================================ */

static volatile uint32_t hv_init_called = 0;

static void hv_init(const void *arg __attribute__((unused))) {
    if (hv_init_called)
        return;
    hv_init_called = 1;
    memory_barrier();

    /* Write canary */
    if (g_output_kva != OUTPUT_KVA_SENTINEL && g_output_kva != 0) {
        volatile uint64_t *canary = (volatile uint64_t *)g_output_kva;
        *canary = 0xAAAABBBBCCCCDDDDULL;
        memory_barrier();
    }

    /* Zero out results */
    volatile uint8_t *p = (volatile uint8_t *)&hv_results;
    for (unsigned int i = 0; i < sizeof(hv_results); i++)
        p[i] = 0;

    hv_results.status = KMOD2_STATUS_RUNNING;
    memory_barrier();
    hv_results.magic = KMOD2_MAGIC;
    memory_barrier();

    /* MSR reconnaissance */
    campaign_msr_recon();

    /* Record trampoline addresses using RIP-relative LEA */
    {
        uint64_t addr;
        __asm__ volatile("lea trampoline_xapic_mode(%%rip), %0" : "=r"(addr));
        hv_results.trampoline_func_kva = addr;
        __asm__ volatile("lea g_trampoline_target(%%rip), %0" : "=r"(addr));
        hv_results.trampoline_target_kva = addr;
    }

    /* Mark completion */
    memory_barrier();
    hv_results.status = KMOD2_STATUS_DONE;
    memory_barrier();

    /* Copy results to shared output buffer */
    if (g_output_kva != OUTPUT_KVA_SENTINEL && g_output_kva != 0) {
        volatile uint8_t *dst = (volatile uint8_t *)g_output_kva;
        volatile uint8_t *src = (volatile uint8_t *)&hv_results;
        for (unsigned int i = 0; i < sizeof(hv_results); i++)
            dst[i] = src[i];
        memory_barrier();
    }
}

/* Path 1: Module metadata + MOD_LOAD */
static int hv_modevent(module_t mod __attribute__((unused)),
                        int type,
                        void *data __attribute__((unused))) {
    if (type == MOD_LOAD) {
        hv_init((const void *)0);
    }
    return 0;
}

static struct moduledata hv_mod = {
    .name   = "hv_kmod2",
    .evhand = hv_modevent,
    .priv   = 0
};

static struct mod_metadata hv_mod_meta = {
    .md_ver  = MDTV_GENERIC,
    .md_type = MDT_MODULE,
    .md_data = (void *)&hv_mod,
    .md_cval = "hv_kmod2"
};

static struct mod_version hv_mod_ver = {
    .mv_version = 1
};

static struct mod_metadata hv_ver_meta = {
    .md_ver  = MDTV_GENERIC,
    .md_type = MDT_VERSION,
    .md_data = (void *)&hv_mod_ver,
    .md_cval = "hv_kmod2"
};

static const void * const __set_modmetadata_set_mod
    __attribute__((section("set_modmetadata_set"), used))
    = &hv_mod_meta;

static const void * const __set_modmetadata_set_ver
    __attribute__((section("set_modmetadata_set"), used))
    = &hv_ver_meta;

/* Path 2: SYSINIT */
static struct sysinit hv_sysinit = {
    .subsystem = SI_SUB_DRIVERS,
    .order     = SI_ORDER_MIDDLE,
    .func      = hv_init,
    .udata     = (const void *)0
};

static const void * const __set_sysinit_set_sym_hv_sysinit
    __attribute__((section("set_sysinit_set"), used))
    = &hv_sysinit;

/* Path 3: IDT trampoline */
__attribute__((naked, used))
void hv_idt_trampoline(void) {
    __asm__ volatile(
        "push %%rax\n"
        "push %%rcx\n"
        "push %%rdx\n"
        "push %%rsi\n"
        "push %%rdi\n"
        "push %%r8\n"
        "push %%r9\n"
        "push %%r10\n"
        "push %%r11\n"
        "xor %%edi, %%edi\n"
        "call hv_init\n"
        "pop %%r11\n"
        "pop %%r10\n"
        "pop %%r9\n"
        "pop %%r8\n"
        "pop %%rdi\n"
        "pop %%rsi\n"
        "pop %%rdx\n"
        "pop %%rcx\n"
        "pop %%rax\n"
        "iretq\n"
        ::: "memory"
    );
}

/* ============================================================
 * apic_ops trampoline (for Phase 7 hooking)
 * ============================================================ */

volatile uint64_t g_trampoline_target = 0;

__attribute__((noinline, used))
int trampoline_xapic_mode(void) {
    uint64_t target = g_trampoline_target;
    if (target)
        return ((int (*)(void))target)();
    return 1;
}
