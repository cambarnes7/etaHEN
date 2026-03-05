/*
 * apic_kmod.c - PS5 APIC Ops Kernel Payload (Flat Binary)
 *
 * Loaded via kstuff kekcall: kmem_alloc + kernel_copyin + kproc_create
 * Runs in ring 0 kernel context on PS5 FW 4.03.
 *
 * Purpose:
 *   - Read apic_ops function pointer table from kernel RW data segment
 *   - Read MSRs and control registers from ring 0
 *   - Provide the foundation for APIC-based HV defeat (flatz method):
 *     overwrite a function pointer in apic_ops (e.g. xapic_mode),
 *     trigger suspend/resume cycle to execute before HV restarts.
 *
 * Entry: module_start(kmod_args *args)
 *   - args->output_kva: DMAP address of result buffer
 *   - args->kdata_base: kernel .data base address
 *   - args->fw_ver:     firmware version (e.g. 0x403)
 *
 * Build: clang -> ELF -> objcopy -O binary -> apic_kmod.bin
 */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef long long          int64_t;

/* ── Args passed from userland via kernel_copyin ── */

struct kmod_args {
    uint64_t output_kva;    /* DMAP address to write results */
    uint64_t kdata_base;    /* kernel .data base */
    uint32_t fw_ver;        /* firmware version */
    uint32_t pad;
};

/* ── Result buffer layout ── */

#define KMOD_MAGIC          0xA91C095DEAD1337ULL
#define KMOD_STATUS_INIT    0
#define KMOD_STATUS_RUNNING 1
#define KMOD_STATUS_DONE    2
#define KMOD_STATUS_ERROR   3

#define MAX_APIC_OPS_ENTRIES  32
#define MAX_MSR_RESULTS       16

struct apic_ops_entry {
    uint64_t func_ptr;      /* original function pointer */
    uint64_t ktext_offset;  /* offset from ktext base (func_ptr - ktext_base) */
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

    /* apic_ops discovery results */
    volatile uint64_t apic_ops_kva;         /* kernel VA of apic_ops table */
    volatile uint32_t apic_ops_count;       /* number of entries found */
    volatile uint32_t apic_ops_pad;
    struct apic_ops_entry apic_ops[MAX_APIC_OPS_ENTRIES];

    /* MSR/CR results */
    volatile uint32_t num_msr_results;
    volatile uint32_t msr_pad;
    struct msr_result msr_results[MAX_MSR_RESULTS];

    /* Kernel info */
    volatile uint64_t kdata_base;
    volatile uint64_t ktext_base;           /* computed: kdata - ktext_size */
    volatile uint64_t lstar_value;          /* MSR_LSTAR: syscall entry point */
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

/* AMD APIC MSRs */
#define MSR_APIC_BASE       0x0000001B
#define MSR_X2APIC_APICID   0x00000802
#define MSR_X2APIC_VERSION  0x00000803
#define MSR_X2APIC_SIVR     0x0000080F

/* ── FW 4.03 offsets ── */

#define FW403_APIC_OPS_OFFSET   0x170650
#define FW403_APIC_OPS_COUNT    28
#define FW403_IDT_OFFSET        0x64cdc80
#define FW403_PCPU_OFFSET       0x64d2280
#define FW403_SYSENTS_OFFSET    0x1709c0
#define FW403_SYSENTVEC_OFFSET  0xd11bb8

/* ── Helper: check if value looks like a kernel text pointer ── */

static int is_ktext_ptr(uint64_t val, uint64_t ktext_base) {
    /* ktext is typically 12-16 MB before kdata */
    return (val >= ktext_base &&
            val < ktext_base + 0x2000000 &&
            (val & 0x3) == 0);
}

/* ── Read a uint64 from kernel VA (we're in ring 0, direct access) ── */

static inline uint64_t kread64(uint64_t kva) {
    return *(volatile uint64_t *)kva;
}

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

    uint64_t kdata_base = args->kdata_base;
    out->kdata_base = kdata_base;

    /* ── Step 1: Read MSRs ── */

    static const uint32_t safe_msrs[] = {
        MSR_EFER, MSR_LSTAR, MSR_STAR, MSR_SFMASK,
        MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE, MSR_TSC_AUX,
        MSR_APIC_BASE,
    };
    int num_safe = sizeof(safe_msrs) / sizeof(safe_msrs[0]);

    for (int i = 0; i < num_safe && out->num_msr_results < MAX_MSR_RESULTS; i++) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = safe_msrs[i];
        out->msr_results[idx].value = rdmsr(safe_msrs[i]);
        out->msr_results[idx].valid = 1;
        mfence();
        out->num_msr_results = idx + 1;
    }

    /* CR values as pseudo-MSRs */
    if (out->num_msr_results < MAX_MSR_RESULTS) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = 0xFFFF0000;
        out->msr_results[idx].value = read_cr0();
        out->msr_results[idx].valid = 1;
        out->num_msr_results = idx + 1;
    }
    if (out->num_msr_results < MAX_MSR_RESULTS) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = 0xFFFF0003;
        out->msr_results[idx].value = read_cr3();
        out->msr_results[idx].valid = 1;
        out->num_msr_results = idx + 1;
    }
    if (out->num_msr_results < MAX_MSR_RESULTS) {
        uint32_t idx = out->num_msr_results;
        out->msr_results[idx].msr_id = 0xFFFF0004;
        out->msr_results[idx].value = read_cr4();
        out->msr_results[idx].valid = 1;
        out->num_msr_results = idx + 1;
    }

    /* Record LSTAR (syscall entry) for ktext base calculation */
    out->lstar_value = rdmsr(MSR_LSTAR);

    /* ── Step 2: Compute ktext base from LSTAR ──
     *
     * LSTAR points to Xfast_syscall in ktext. On FW 4.03 this is at
     * a known offset from ktext base. We use LSTAR to derive ktext_base
     * independently of hardcoded offsets. */
    uint64_t lstar = out->lstar_value;
    /* ktext_base is LSTAR rounded down to 2MB boundary, then adjusted.
     * On 4.03: LSTAR ~ ktext + 0x2307xx, ktext_base ~ kdata - 0xA00000.
     * Safe heuristic: ktext starts within 16MB before kdata. */
    uint64_t ktext_base = kdata_base - 0xA00000;  /* ~10MB before kdata for 4.03 */
    if (lstar >= kdata_base - 0x1000000 && lstar < kdata_base) {
        /* Better estimate: align LSTAR down to get approximate base */
        ktext_base = lstar & ~0xFFFFFULL;  /* round down to 1MB */
        /* Walk back to find actual base — for now use the known 4.03 delta */
        if (args->fw_ver == 0x403) {
            ktext_base = kdata_base - 0xA00000;
        }
    }
    out->ktext_base = ktext_base;

    /* ── Step 3: Read apic_ops table ──
     *
     * On FW 4.03, apic_ops is at kdata + 0x170650.
     * It's a table of function pointers in the RW data segment.
     * This is the key target for flatz's HV defeat method:
     *   - Overwrite xapic_mode (slot[2]) with a ROP gadget
     *   - Trigger suspend/resume → code executes before HV restarts
     *   - Apply kernel patches in that window */

    uint64_t apic_ops_kva = 0;
    uint32_t apic_ops_count = 0;

    if (args->fw_ver == 0x403) {
        apic_ops_kva = kdata_base + FW403_APIC_OPS_OFFSET;
    }

    if (apic_ops_kva) {
        out->apic_ops_kva = apic_ops_kva;

        /* Read and validate entries */
        for (uint32_t i = 0; i < MAX_APIC_OPS_ENTRIES; i++) {
            uint64_t ptr = kread64(apic_ops_kva + i * 8);
            if (!is_ktext_ptr(ptr, ktext_base))
                break;

            out->apic_ops[i].func_ptr = ptr;
            out->apic_ops[i].ktext_offset = ptr - ktext_base;
            apic_ops_count++;
        }
        out->apic_ops_count = apic_ops_count;
    }

    /* ── Done ── */

    mfence();
    out->status = KMOD_STATUS_DONE;
    mfence();

    return 0;
}
