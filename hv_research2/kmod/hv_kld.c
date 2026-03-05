/*
 * hv_kld.c - PS5 Offset Discovery Kernel Module (KLD)
 *
 * FreeBSD kernel loadable module for PS5 FW 4.xx.
 * Loaded via kldload(2), runs init code in kernel context (ring 0).
 *
 * Build: produces hv_kmod.ko (ET_REL ELF, loaded by kernel linker)
 * Load:  syscall(304, "/data/etaHEN/hv_kmod.ko")
 * Read:  Results written to shared buffer via DMAP
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

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_STATUS_INIT    0
#define KMOD_STATUS_RUNNING 1
#define KMOD_STATUS_DONE    2

struct kmod_result_buf {
    volatile uint64_t magic;
    volatile uint32_t status;
    volatile uint32_t pad0;
    /* KVA addresses for userland */
    volatile uint64_t idt_trampoline_kva;    /* KVA of hv_idt_trampoline() */
    /* MSR results */
    volatile uint32_t num_msr_results;
    volatile uint32_t pad1;
    struct {
        uint32_t msr_id;
        uint32_t valid;
        uint64_t value;
    } msr_results[16];
};

/* ============================================================
 * Shared output KVA - patched by userland before loading
 * ============================================================ */

#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL
volatile uint64_t g_output_kva = OUTPUT_KVA_SENTINEL;

/* Local result buffer */
struct kmod_result_buf hv_results = { .magic = 0x1 };

/* ============================================================
 * Inline assembly helpers
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

/* ============================================================
 * Campaign: MSR Reconnaissance (safe - no VMMCALL)
 * ============================================================ */

static void campaign_msr_recon(void) {
    static const uint32_t safe_msrs[] = {
        MSR_EFER, MSR_LSTAR, MSR_STAR, MSR_SFMASK,
        MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE, MSR_TSC_AUX,
    };
    int num_safe = sizeof(safe_msrs) / sizeof(safe_msrs[0]);

    for (int i = 0; i < num_safe && hv_results.num_msr_results < 16; i++) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = safe_msrs[i];
        hv_results.msr_results[idx].value = rdmsr(safe_msrs[i]);
        hv_results.msr_results[idx].valid = 1;
        memory_barrier();
        hv_results.num_msr_results = idx + 1;
    }

    /* CR values as pseudo-MSRs */
    if (hv_results.num_msr_results < 16) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = 0xFFFF0000;
        hv_results.msr_results[idx].value = read_cr0();
        hv_results.msr_results[idx].valid = 1;
        hv_results.num_msr_results = idx + 1;
    }
    if (hv_results.num_msr_results < 16) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = 0xFFFF0003;
        hv_results.msr_results[idx].value = read_cr3();
        hv_results.msr_results[idx].valid = 1;
        hv_results.num_msr_results = idx + 1;
    }
    if (hv_results.num_msr_results < 16) {
        uint32_t idx = hv_results.num_msr_results;
        hv_results.msr_results[idx].msr_id = 0xFFFF0004;
        hv_results.msr_results[idx].value = read_cr4();
        hv_results.msr_results[idx].valid = 1;
        hv_results.num_msr_results = idx + 1;
    }
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

    /* Pre-campaign canary */
    if (g_output_kva != OUTPUT_KVA_SENTINEL && g_output_kva != 0) {
        volatile uint64_t *canary = (volatile uint64_t *)g_output_kva;
        *canary = 0xAAAABBBBCCCCDDDDULL;
        memory_barrier();
    }

    /* Zero result buffer (no memset in freestanding kernel) */
    volatile uint8_t *p = (volatile uint8_t *)&hv_results;
    for (unsigned int i = 0; i < sizeof(hv_results); i++)
        p[i] = 0;

    hv_results.status = KMOD_STATUS_RUNNING;
    memory_barrier();
    hv_results.magic = KMOD_MAGIC;
    memory_barrier();

    /* MSR recon */
    campaign_msr_recon();

    /* Record IDT trampoline address via RIP-relative LEA.
     * Direct casts generate R_X86_64_64 relocations that PS5's
     * kernel linker does NOT resolve. LEA with (%rip) generates
     * R_X86_64_PC32 which the PS5 linker DOES resolve. */
    {
        uint64_t addr;
        __asm__ volatile("lea hv_idt_trampoline(%%rip), %0" : "=r"(addr));
        hv_results.idt_trampoline_kva = addr;
    }

    /* Mark completion */
    memory_barrier();
    hv_results.status = KMOD_STATUS_DONE;
    memory_barrier();

    /* Copy results to shared output buffer via DMAP */
    if (g_output_kva != OUTPUT_KVA_SENTINEL && g_output_kva != 0) {
        volatile uint8_t *dst = (volatile uint8_t *)g_output_kva;
        volatile uint8_t *src = (volatile uint8_t *)&hv_results;
        for (unsigned int i = 0; i < sizeof(hv_results); i++)
            dst[i] = src[i];
        memory_barrier();
    }
}

/* ============================================================
 * Path 1: Module metadata + MOD_LOAD
 * ============================================================ */

static int hv_modevent(module_t mod __attribute__((unused)),
                        int type,
                        void *data __attribute__((unused))) {
    if (type == MOD_LOAD)
        hv_init((const void *)0);
    return 0;
}

static struct moduledata hv_mod = {
    .name   = "hv_kmod",
    .evhand = hv_modevent,
    .priv   = 0
};

static struct mod_metadata hv_mod_meta = {
    .md_ver  = MDTV_GENERIC,
    .md_type = MDT_MODULE,
    .md_data = (void *)&hv_mod,
    .md_cval = "hv_kmod"
};

static struct mod_version hv_mod_ver = {
    .mv_version = 1
};

static struct mod_metadata hv_ver_meta = {
    .md_ver  = MDTV_GENERIC,
    .md_type = MDT_VERSION,
    .md_data = (void *)&hv_mod_ver,
    .md_cval = "hv_kmod"
};

static const void * const __set_modmetadata_set_mod
    __attribute__((section("set_modmetadata_set"), used))
    = &hv_mod_meta;

static const void * const __set_modmetadata_set_ver
    __attribute__((section("set_modmetadata_set"), used))
    = &hv_ver_meta;

/* ============================================================
 * Path 2: SYSINIT (fallback)
 * ============================================================ */

static struct sysinit hv_sysinit = {
    .subsystem = SI_SUB_DRIVERS,
    .order     = SI_ORDER_MIDDLE,
    .func      = hv_init,
    .udata     = (const void *)0
};

static const void * const __set_sysinit_set_sym_hv_sysinit
    __attribute__((section("set_sysinit_set"), used))
    = &hv_sysinit;

/* ============================================================
 * Path 3: IDT trampoline (manual invocation from userland)
 *
 * MUST be at a known position in .text for the scanner.
 * Userland hooks an IDT entry to point here, triggers INT N
 * from ring 3. CPU transitions to ring 0 via IDT gate.
 * ============================================================ */

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
