/*
 * hv_kld.c - PS5 Hypervisor Research Kernel Module (KLD)
 *
 * FreeBSD kernel loadable module for PS5 FW 4.03.
 * Loaded via kldload(2), runs init code in kernel context (ring 0).
 *
 * Build: produces hv_kmod.ko (ET_REL ELF, loaded by kernel linker)
 * Load:  syscall(304, "/data/etaHEN/hv_kmod.ko")
 * Read:  Results written to shared buffer via DMAP (address patched
 *        into g_output_kva by userland before loading)
 * Unload: syscall(305, kid)
 *
 * The kernel linker handles all memory allocation, relocation, and
 * SYSINIT dispatch. No sysent hijacking, NX clearing, or data cave
 * hunting required.
 */

#include <stdint.h>

/* ============================================================
 * FreeBSD kernel module support (manual definitions)
 *
 * We define these manually since we don't have FreeBSD kernel
 * headers available for cross-compilation.
 *
 * Two independent init paths are provided:
 *   1. Module metadata (set_modmetadata_set) + MOD_LOAD event
 *      → linker_file_register_modules() finds our metadata,
 *        kernel calls our modevent handler with MOD_LOAD
 *   2. SYSINIT (set_sysinit_set) as a fallback
 *      → linker_file_sysinit() calls hv_init directly
 *
 * PS5's kernel may not process one or both of these.
 * Using both maximizes the chance that hv_init runs.
 * ============================================================ */

/* --- SYSINIT types --- */

typedef void (*sysinit_cfunc_t)(const void *);

struct sysinit {
    unsigned int    subsystem;
    unsigned int    order;
    sysinit_cfunc_t func;
    const void     *udata;
};

#define SI_SUB_DRIVERS      0x3100000
#define SI_ORDER_MIDDLE     0x1000000

/* --- Module framework types --- */

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

/* Module metadata types - used by linker_file_register_modules() */
#define MDT_MODULE   1
#define MDT_VERSION  5
#define MDTV_GENERIC 2

struct mod_metadata {
    int         md_ver;     /* structure version (MDTV_GENERIC) */
    int         md_type;    /* type (MDT_MODULE, MDT_VERSION, etc) */
    void       *md_data;    /* type-specific data */
    const char *md_cval;    /* module name */
};

struct mod_version {
    int mv_version;
};

/* ============================================================
 * Campaign control - comment out to disable
 *
 * MSR recon is always safe (reads standard MSRs).
 * VMMCALL enum probes hypercall numbers 0-31 - the HV may
 * kill the guest for unknown/unauthorized calls.
 * IOMMU probing is more targeted and slightly riskier.
 * ============================================================ */

#define RUN_MSR_RECON       1
#define RUN_VMMCALL_ENUM    0  /* Disabled - focus on apic_ops */
#define RUN_VMMCALL_IOMMU   0  /* Enable after confirming enum works */
#define RUN_APIC_OPS_TEST   1  /* Ring-0 apic_ops CFI bypass test */

/* ============================================================
 * Shared data structures (must match main.c definitions)
 * ============================================================ */

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_MAX_RESULTS    64
#define KMOD_STATUS_INIT    0
#define KMOD_STATUS_RUNNING 1
#define KMOD_STATUS_DONE    2

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
};

/* ============================================================
 * Shared output KVA - patched by userland before loading
 *
 * Userland patches this sentinel with a DMAP-mapped kernel VA
 * pointing to a physically-contiguous buffer. After running
 * campaigns, the kmod copies hv_results to this address so
 * userland can read results directly from its mapped buffer.
 *
 * This bypasses kldsym/kldstat entirely - the PS5's kernel
 * linker doesn't update st_value for KLD symbols and kldstat
 * returns all zeros (likely Sony modifications).
 * ============================================================ */

#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL
volatile uint64_t g_output_kva = OUTPUT_KVA_SENTINEL;

/* Sentinels for kernel base addresses - patched by userland before load */
#define KDATA_BASE_SENTINEL 0xBEEF000000000001ULL
#define KTEXT_BASE_SENTINEL 0xBEEF000000000002ULL
volatile uint64_t g_kdata_base = KDATA_BASE_SENTINEL;
volatile uint64_t g_ktext_base = KTEXT_BASE_SENTINEL;

/* Local result buffer - filled by campaigns, then copied out */
struct kmod_result_buf hv_results = { .magic = 0x1 };

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

/* ============================================================
 * VMMCALL with full register control
 *
 * On AMD SVM, VMMCALL causes a #VMEXIT(VMMCALL).
 * The hypervisor reads guest registers, processes the request,
 * and resumes the guest (or kills it).
 * ============================================================ */

static int do_vmmcall(uint64_t rax_in, uint64_t rcx_in,
                      uint64_t rdx_in, uint64_t rdi_in,
                      uint64_t rsi_in, uint64_t r8_in,
                      uint64_t *rax_out, uint64_t *rcx_out,
                      uint64_t *rdx_out, uint64_t *rdi_out,
                      uint64_t *rsi_out, uint64_t *r8_out) {
    register uint64_t r8_val __asm__("r8") = r8_in;
    uint64_t a, c, d, di, si;

    __asm__ volatile(
        "vmmcall\n"
        : "=a"(a), "=c"(c), "=d"(d), "=D"(di), "=S"(si), "+r"(r8_val)
        : "a"(rax_in), "c"(rcx_in), "d"(rdx_in), "D"(rdi_in), "S"(rsi_in)
        : "memory"
    );

    *rax_out = a;  *rcx_out = c;  *rdx_out = d;
    *rdi_out = di; *rsi_out = si; *r8_out  = r8_val;
    return 1;
}

static void store_result(uint32_t campaign,
                         uint64_t rax_in, uint64_t rcx_in,
                         uint64_t rdx_in, uint64_t rdi_in,
                         uint64_t rsi_in, uint64_t r8_in,
                         uint64_t rax_out, uint64_t rcx_out,
                         uint64_t rdx_out, uint64_t rdi_out,
                         uint64_t rsi_out, uint64_t r8_out,
                         uint32_t survived) {
    if (hv_results.num_results >= KMOD_MAX_RESULTS) return;
    uint32_t idx = hv_results.num_results;
    struct vmmcall_result *r = &hv_results.results[idx];
    r->rax_in = rax_in;   r->rcx_in = rcx_in;
    r->rdx_in = rdx_in;   r->rdi_in = rdi_in;
    r->rsi_in = rsi_in;   r->r8_in = r8_in;
    r->rax_out = rax_out;  r->rcx_out = rcx_out;
    r->rdx_out = rdx_out;  r->rdi_out = rdi_out;
    r->rsi_out = rsi_out;  r->r8_out = r8_out;
    r->survived = survived;
    r->campaign_id = campaign;
    memory_barrier();
    hv_results.num_results = idx + 1;
}

/* ============================================================
 * Campaign: MSR Reconnaissance (safe - no VMMCALL)
 * ============================================================ */

static void campaign_msr_recon(void) {
    hv_results.current_campaign = 4;

    static const uint32_t safe_msrs[] = {
        MSR_EFER, MSR_LSTAR, MSR_STAR, MSR_SFMASK,
        MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE, MSR_TSC_AUX,
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
}

/* ============================================================
 * Campaign: VMMCALL Hypercall Number Enumeration
 *
 * Probe RAX = 0x00 through 0x1F with all other registers zeroed.
 * The PS5 HV uses RAX as the hypercall number.
 * ============================================================ */

#if RUN_VMMCALL_ENUM
static void campaign_vmmcall_enum(void) {
    hv_results.current_campaign = 1;

    for (uint64_t i = 0; i < 32 && hv_results.num_results < KMOD_MAX_RESULTS; i++) {
        hv_results.current_probe = (uint32_t)i;
        memory_barrier();

        uint64_t rax_out, rcx_out, rdx_out, rdi_out, rsi_out, r8_out;
        int ok = do_vmmcall(i, 0, 0, 0, 0, 0,
                            &rax_out, &rcx_out, &rdx_out,
                            &rdi_out, &rsi_out, &r8_out);

        store_result(1, i, 0, 0, 0, 0, 0,
                     rax_out, rcx_out, rdx_out,
                     rdi_out, rsi_out, r8_out, ok);
    }
}
#endif

/* ============================================================
 * Campaign: IOMMU Hypercall Probing
 *
 * IOMMU hypercalls are likely in RAX range 0x06-0x0C.
 * Probe with various device IDs.
 * ============================================================ */

#if RUN_VMMCALL_IOMMU
static void campaign_vmmcall_iommu(void) {
    hv_results.current_campaign = 2;

    static const uint64_t dev_ids[] = { 0, 1, 0x10, 0x100, 0xFFFF };
    int num_devs = sizeof(dev_ids) / sizeof(dev_ids[0]);

    for (uint64_t hc = 6; hc <= 12 && hv_results.num_results < KMOD_MAX_RESULTS; hc++) {
        for (int d = 0; d < num_devs && hv_results.num_results < KMOD_MAX_RESULTS; d++) {
            hv_results.current_probe = (uint32_t)((hc << 16) | d);
            memory_barrier();

            uint64_t rax_out, rcx_out, rdx_out, rdi_out, rsi_out, r8_out;
            int ok = do_vmmcall(hc, 0, 0, dev_ids[d], 0, 0,
                                &rax_out, &rcx_out, &rdx_out,
                                &rdi_out, &rsi_out, &r8_out);

            store_result(2, hc, 0, 0, dev_ids[d], 0, 0,
                         rax_out, rcx_out, rdx_out,
                         rdi_out, rsi_out, r8_out, ok);
        }
    }
}
#endif

/* ============================================================
 * Campaign: APIC_OPS Ring-0 CFI Bypass Test
 *
 * From ring 0, we can do direct memory stores without going
 * through CFI-instrumented kernel functions like kernel_copyin().
 * This campaign:
 *   1. Scans kdata for the apic_ops vtable (28 consecutive ktext ptrs)
 *   2. Reads apic_ops[2] (xapic_mode) — verifies known offset 0x170650
 *   3. Same-value writeback test via direct mov — the critical CFI test
 *   4. Reports whether the write survived (no #GP / panic)
 *
 * Results are stored in the vmmcall_result array with campaign_id=5:
 *   results[0]: apic_ops discovery (rax_out=addr, rcx_out=count)
 *   results[1]: xapic_mode read (rax_out=original value)
 *   results[2]: same-value writeback (survived=1 means CFI bypassed)
 *   results[3]: different-value write test (survived=1 means full hijack)
 *   results[4]: post-test verify (rax_out=final value at xapic_mode)
 * ============================================================ */

#if RUN_APIC_OPS_TEST

/* Known apic_ops offset from kdata base on FW 4.03 */
#define APIC_OPS_OFFSET_403  0x170650
#define APIC_OPS_NUM_PTRS    28

/* Helper: check if value looks like a kernel .text pointer */
static int is_ktext_ptr(uint64_t val) {
    if (g_ktext_base == KTEXT_BASE_SENTINEL || g_ktext_base == 0)
        return 0;
    /* ktext pointers should be within 32MB of ktext base */
    return (val >= g_ktext_base && val < g_ktext_base + 0x2000000);
}

static void campaign_apic_ops_test(void) {
    hv_results.current_campaign = 5;
    memory_barrier();

    if (g_kdata_base == KDATA_BASE_SENTINEL || g_kdata_base == 0)
        return;
    if (g_ktext_base == KTEXT_BASE_SENTINEL || g_ktext_base == 0)
        return;

    /* ── Step 1: Verify apic_ops at known offset ── */

    uint64_t apic_ops_kva = g_kdata_base + APIC_OPS_OFFSET_403;
    volatile uint64_t *apic_ops = (volatile uint64_t *)apic_ops_kva;

    /* Count consecutive ktext pointers starting at known offset */
    int consecutive = 0;
    for (int i = 0; i < 40; i++) {
        uint64_t val = apic_ops[i];
        if (is_ktext_ptr(val))
            consecutive++;
        else
            break;
    }

    /* Result 0: apic_ops discovery
     * rax_out = apic_ops KVA, rcx_out = consecutive ktext ptr count */
    if (hv_results.num_results < KMOD_MAX_RESULTS) {
        uint32_t idx = hv_results.num_results;
        struct vmmcall_result *r = &hv_results.results[idx];
        r->rax_in = 0;  /* test phase 0: discovery */
        r->rcx_in = APIC_OPS_OFFSET_403;
        r->rax_out = apic_ops_kva;
        r->rcx_out = (uint64_t)consecutive;
        r->rdx_out = apic_ops[0];  /* first pointer (create) */
        r->rdi_out = apic_ops[1];  /* second pointer (init) */
        r->rsi_out = apic_ops[2];  /* third pointer (xapic_mode) */
        r->r8_out  = apic_ops[3];  /* fourth pointer (is_x2apic) */
        r->survived = (consecutive >= 20) ? 1 : 0;
        r->campaign_id = 5;
        memory_barrier();
        hv_results.num_results = idx + 1;
    }

    /* If we didn't find enough consecutive pointers, scan for it */
    uint64_t found_addr = 0;
    int found_count = 0;

    if (consecutive < 20) {
        /* Scan first 4MB of kdata for the largest run of ktext ptrs */
        int best_count = 0;
        uint64_t best_addr = 0;
        int run = 0;
        uint64_t run_start = 0;

        for (uint64_t off = 0; off < 0x400000; off += 8) {
            volatile uint64_t *p = (volatile uint64_t *)(g_kdata_base + off);
            uint64_t val = *p;
            if (is_ktext_ptr(val)) {
                if (run == 0)
                    run_start = g_kdata_base + off;
                run++;
            } else {
                if (run > best_count) {
                    best_count = run;
                    best_addr = run_start;
                }
                run = 0;
            }
        }
        if (run > best_count) {
            best_count = run;
            best_addr = run_start;
        }

        if (best_count >= 20) {
            found_addr = best_addr;
            found_count = best_count;
            apic_ops = (volatile uint64_t *)found_addr;
        }
    } else {
        found_addr = apic_ops_kva;
        found_count = consecutive;
    }

    if (found_count < 20)
        return;  /* No apic_ops found */

    /* ── Step 2: Read xapic_mode (slot 2, offset +0x10) ── */

    uint64_t orig_xapic_mode = apic_ops[2];

    /* Result 1: xapic_mode read */
    if (hv_results.num_results < KMOD_MAX_RESULTS) {
        uint32_t idx = hv_results.num_results;
        struct vmmcall_result *r = &hv_results.results[idx];
        r->rax_in = 1;  /* test phase 1: read */
        r->rcx_in = (uint64_t)(found_addr - g_kdata_base);
        r->rax_out = orig_xapic_mode;
        r->rcx_out = found_addr;
        r->rdx_out = (uint64_t)found_count;
        r->survived = 1;
        r->campaign_id = 5;
        memory_barrier();
        hv_results.num_results = idx + 1;
    }

    /* ── Step 3: Same-value writeback — THE critical CFI test ──
     *
     * Previous userland tests used kernel_copyin() which is
     * CFI-instrumented. From ring 0, this is a direct store
     * instruction with no CFI checks in the execution path.
     *
     * If this doesn't crash, we've proven that ring 0 bypasses
     * CFI protection on apic_ops function pointers.
     */

    /* Write the SAME value back — if CFI is enforced at the
     * memory/hardware level (HV NPT, watchpoint), even this will crash.
     * If it survives, CFI is purely software and ring 0 bypasses it. */
    memory_barrier();
    apic_ops[2] = orig_xapic_mode;  /* Direct ring-0 store! */
    memory_barrier();

    /* If we're still alive, read it back to confirm */
    uint64_t readback = apic_ops[2];

    /* Result 2: same-value writeback survived */
    if (hv_results.num_results < KMOD_MAX_RESULTS) {
        uint32_t idx = hv_results.num_results;
        struct vmmcall_result *r = &hv_results.results[idx];
        r->rax_in = 2;  /* test phase 2: same-value writeback */
        r->rax_out = readback;
        r->rcx_out = orig_xapic_mode;
        r->rdx_out = (readback == orig_xapic_mode) ? 1 : 0;  /* match? */
        r->survived = 1;  /* If we get here, it survived! */
        r->campaign_id = 5;
        memory_barrier();
        hv_results.num_results = idx + 1;
    }

    /* ── Step 4: Different-value write test ──
     *
     * Write apic_ops[5] (dump, void(*)(const char*)) to slot 2 (xapic_mode,
     * void(*)(void)). These have DIFFERENT type signatures, so if CFI were
     * active, even a valid ktext pointer with wrong type would be rejected.
     *
     * We pick slot 5 because dump() is unlikely to be called during our
     * brief test window, and we immediately restore the original.
     */

    uint64_t alt_ptr = apic_ops[5];  /* dump function pointer */

    /* Only attempt if alt_ptr is also a valid ktext pointer */
    if (is_ktext_ptr(alt_ptr) && alt_ptr != orig_xapic_mode) {
        /* Write different ktext pointer to xapic_mode slot */
        memory_barrier();
        apic_ops[2] = alt_ptr;  /* Cross-type write! */
        memory_barrier();

        uint64_t readback2 = apic_ops[2];

        /* IMMEDIATELY restore original value */
        memory_barrier();
        apic_ops[2] = orig_xapic_mode;
        memory_barrier();

        /* Result 3: cross-type write survived */
        if (hv_results.num_results < KMOD_MAX_RESULTS) {
            uint32_t idx = hv_results.num_results;
            struct vmmcall_result *r = &hv_results.results[idx];
            r->rax_in = 3;  /* test phase 3: cross-type write */
            r->rax_out = readback2;
            r->rcx_out = alt_ptr;
            r->rdx_out = (readback2 == alt_ptr) ? 1 : 0;  /* match? */
            r->rdi_out = orig_xapic_mode;  /* what we restored to */
            r->survived = 1;
            r->campaign_id = 5;
            memory_barrier();
            hv_results.num_results = idx + 1;
        }
    }

    /* ── Step 5: Final verification — confirm apic_ops is restored ── */

    uint64_t final_val = apic_ops[2];

    /* Dump all 28 pointers for the full apic_ops snapshot */
    if (hv_results.num_results < KMOD_MAX_RESULTS) {
        uint32_t idx = hv_results.num_results;
        struct vmmcall_result *r = &hv_results.results[idx];
        r->rax_in = 4;  /* test phase 4: final verify */
        r->rax_out = final_val;
        r->rcx_out = orig_xapic_mode;
        r->rdx_out = (final_val == orig_xapic_mode) ? 1 : 0;  /* restored? */
        r->rdi_out = found_addr;
        r->rsi_out = (uint64_t)found_count;
        r->survived = 1;
        r->campaign_id = 5;
        memory_barrier();
        hv_results.num_results = idx + 1;
    }
}

#endif /* RUN_APIC_OPS_TEST */

/* ============================================================
 * Module init - called by kernel linker during kldload
 *
 * The kernel linker finds hv_init via the SYSINIT entry in
 * the set_sysinit_set section and calls it during module load.
 * By the time kldload() returns to userland, all campaigns
 * have completed and hv_results is populated.
 * ============================================================ */

static volatile uint32_t hv_init_called = 0;

static void hv_init(const void *arg __attribute__((unused))) {
    /* Guard against double-call (both SYSINIT and MOD_LOAD might fire) */
    if (hv_init_called)
        return;
    hv_init_called = 1;
    memory_barrier();

    /*
     * Write a canary to the output address FIRST, before anything else.
     * This lets userland distinguish "init never ran" from "init ran but
     * campaigns crashed" by checking for the canary value.
     */
    if (g_output_kva != OUTPUT_KVA_SENTINEL && g_output_kva != 0) {
        volatile uint64_t *canary = (volatile uint64_t *)g_output_kva;
        *canary = 0xAAAABBBBCCCCDDDDULL;  /* pre-campaign canary */
        memory_barrier();
    }

    /* Zero out the result buffer (no memset in freestanding kernel) */
    volatile uint8_t *p = (volatile uint8_t *)&hv_results;
    for (unsigned int i = 0; i < sizeof(hv_results); i++)
        p[i] = 0;

    hv_results.status = KMOD_STATUS_RUNNING;
    memory_barrier();
    hv_results.magic = KMOD_MAGIC;
    memory_barrier();

    /* MSR reconnaissance - always safe */
#if RUN_MSR_RECON
    campaign_msr_recon();
#endif

    /* VMMCALL enumeration - may trigger HV kill */
#if RUN_VMMCALL_ENUM
    campaign_vmmcall_enum();
#endif

    /* IOMMU probing - more targeted, slightly riskier */
#if RUN_VMMCALL_IOMMU
    campaign_vmmcall_iommu();
#endif

    /* APIC_OPS ring-0 CFI bypass test */
#if RUN_APIC_OPS_TEST
    campaign_apic_ops_test();
#endif

    /* Mark completion */
    memory_barrier();
    hv_results.status = KMOD_STATUS_DONE;
    memory_barrier();

    /* Copy results to shared output buffer via DMAP.
     * g_output_kva was patched by userland with a kernel VA
     * (DMAP base + physical address) before the .ko was loaded.
     * Writing here lets userland read results directly from its
     * mapped buffer without needing kldsym or kernel_copyout. */
    if (g_output_kva != OUTPUT_KVA_SENTINEL && g_output_kva != 0) {
        volatile uint8_t *dst = (volatile uint8_t *)g_output_kva;
        volatile uint8_t *src = (volatile uint8_t *)&hv_results;
        for (unsigned int i = 0; i < sizeof(hv_results); i++)
            dst[i] = src[i];
        memory_barrier();
    }
}

/* ============================================================
 * Path 1: Module metadata + MOD_LOAD event handler
 *
 * linker_file_register_modules() finds set_modmetadata_set,
 * registers our module, then the kernel calls hv_modevent
 * with MOD_LOAD. This is the standard FreeBSD mechanism for
 * loadable kernel module initialization.
 * ============================================================ */

static int hv_modevent(module_t mod __attribute__((unused)),
                        int type,
                        void *data __attribute__((unused))) {
    if (type == MOD_LOAD) {
        hv_init((const void *)0);
    }
    return 0;
}

static struct moduledata hv_mod = {
    .name   = "hv_kmod",
    .evhand = hv_modevent,
    .priv   = 0
};

/* MDT_MODULE metadata - tells kernel this is a loadable module */
static struct mod_metadata hv_mod_meta = {
    .md_ver  = MDTV_GENERIC,
    .md_type = MDT_MODULE,
    .md_data = (void *)&hv_mod,
    .md_cval = "hv_kmod"
};

/* MDT_VERSION metadata - required by some FreeBSD kernel versions */
static struct mod_version hv_mod_ver = {
    .mv_version = 1
};

static struct mod_metadata hv_ver_meta = {
    .md_ver  = MDTV_GENERIC,
    .md_type = MDT_VERSION,
    .md_data = (void *)&hv_mod_ver,
    .md_cval = "hv_kmod"
};

/* Place metadata pointers in set_modmetadata_set linker set */
static const void * const __set_modmetadata_set_mod
    __attribute__((section("set_modmetadata_set"), used))
    = &hv_mod_meta;

static const void * const __set_modmetadata_set_ver
    __attribute__((section("set_modmetadata_set"), used))
    = &hv_ver_meta;

/* ============================================================
 * Path 2: SYSINIT (fallback)
 *
 * If the module metadata path doesn't work on PS5, this
 * provides a second chance. The kernel linker iterates
 * set_sysinit_set and calls hv_init directly.
 * The hv_init_called guard prevents double execution.
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
 * On PS5 FW 4.03, the kernel linker loads the module into
 * RWX kernel memory (GMET is not enforced until FW 6.50)
 * but does not process SYSINIT or MOD_LOAD for loaded modules.
 *
 * As a fallback, userland hooks an IDT entry to point to this
 * trampoline, then triggers "int N" from ring 3.  The CPU
 * transitions to ring 0 via the IDT gate and executes the
 * trampoline on the current thread's kernel stack.
 *
 * The trampoline saves caller-clobbered registers, calls
 * hv_init, restores them, and returns via IRETQ.
 * ============================================================ */

__attribute__((naked, used))
void hv_idt_trampoline(void) {
    __asm__ volatile(
        /* CPU already pushed SS, RSP, RFLAGS, CS, RIP onto
         * the kernel stack (IST=0 → TSS.RSP0 for ring 3→0).
         * Save registers that hv_init may clobber. */
        "push %%rax\n"
        "push %%rcx\n"
        "push %%rdx\n"
        "push %%rsi\n"
        "push %%rdi\n"
        "push %%r8\n"
        "push %%r9\n"
        "push %%r10\n"
        "push %%r11\n"
        /* Call hv_init(NULL) */
        "xor %%edi, %%edi\n"
        "call hv_init\n"
        /* Restore registers */
        "pop %%r11\n"
        "pop %%r10\n"
        "pop %%r9\n"
        "pop %%r8\n"
        "pop %%rdi\n"
        "pop %%rsi\n"
        "pop %%rdx\n"
        "pop %%rcx\n"
        "pop %%rax\n"
        /* Return from interrupt → back to ring 3 userland */
        "iretq\n"
        ::: "memory"
    );
}
