/*
 * hv_flat.c - PS5 Offset Discovery Kernel Payload (Flat Binary)
 *
 * Loaded via kstuff kekcall: kmem_alloc + kernel_copyin + kproc_create
 * Based on PS5_kldload approach (buzzer-re).
 *
 * Entry: module_start(kmod_args *args)
 *   - args->output_kva: DMAP address of result buffer
 *   - args->kdata_base: kernel .data base
 *   - args->fw_ver:     firmware version
 *
 * Build: clang → ELF → objcopy -O binary → hv_flat.bin
 */

typedef unsigned char      uint8_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;

/* ── Args passed from userland via kernel_copyin ── */

struct kmod_args {
    uint64_t output_kva;    /* DMAP address to write results */
    uint64_t kdata_base;    /* kernel .data base */
    uint32_t fw_ver;        /* firmware version */
    uint32_t pad;
};

/* ── Result buffer (must match main.c) ── */

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_STATUS_RUNNING 1
#define KMOD_STATUS_DONE    2

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

/* ── Inline assembly helpers ── */

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

static inline void mfence(void) {
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

/* ── Entry point ──
 * Called by kproc_create as: module_start(kmod_args *args)
 * Runs in ring 0 kernel context. */

__attribute__((section(".text.module_start")))
int module_start(struct kmod_args *args) {
    if (!args || !args->output_kva)
        return 1;

    volatile struct kmod_result_buf *out =
        (volatile struct kmod_result_buf *)args->output_kva;

    /* Zero result buffer */
    volatile uint8_t *p = (volatile uint8_t *)out;
    for (unsigned int i = 0; i < sizeof(*out); i++)
        p[i] = 0;

    out->status = KMOD_STATUS_RUNNING;
    mfence();
    out->magic = KMOD_MAGIC;
    mfence();

    /* MSR recon */
    static const uint32_t safe_msrs[] = {
        MSR_EFER, MSR_LSTAR, MSR_STAR, MSR_SFMASK,
        MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE, MSR_TSC_AUX,
    };
    int num_safe = sizeof(safe_msrs) / sizeof(safe_msrs[0]);

    for (int i = 0; i < num_safe && out->num_msr_results < 16; i++) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = safe_msrs[i];
        out->msr_results[idx].value = rdmsr(safe_msrs[i]);
        out->msr_results[idx].valid = 1;
        mfence();
        out->num_msr_results = idx + 1;
    }

    /* CR values as pseudo-MSRs */
    if (out->num_msr_results < 16) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = 0xFFFF0000;
        out->msr_results[idx].value = read_cr0();
        out->msr_results[idx].valid = 1;
        out->num_msr_results = idx + 1;
    }
    if (out->num_msr_results < 16) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = 0xFFFF0003;
        out->msr_results[idx].value = read_cr3();
        out->msr_results[idx].valid = 1;
        out->num_msr_results = idx + 1;
    }
    if (out->num_msr_results < 16) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = 0xFFFF0004;
        out->msr_results[idx].value = read_cr4();
        out->msr_results[idx].valid = 1;
        out->num_msr_results = idx + 1;
    }

    /* No trampoline KVA in flat binary mode */
    out->idt_trampoline_kva = 0;

    /* Done */
    mfence();
    out->status = KMOD_STATUS_DONE;
    mfence();

    return 0;
}
