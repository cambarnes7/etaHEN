/*
 * hv_kld.c - PS5 Hypervisor Research Kernel Module (KLD)
 *
 * FreeBSD kernel loadable module for PS5 FW 4.03.
 * Loaded via kldload(2), runs init code in kernel context (ring 0).
 *
 * Build: produces hv_kmod.ko (ET_REL ELF, loaded by kernel linker)
 * Load:  syscall(304, "/data/etaHEN/hv_kmod.ko")
 * Read:  kldsym() to find hv_results, kernel_copyout() to read
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

/* ============================================================
 * Campaign control - comment out to disable
 *
 * MSR recon is always safe (reads standard MSRs).
 * VMMCALL enum probes hypercall numbers 0-31 - the HV may
 * kill the guest for unknown/unauthorized calls.
 * IOMMU probing is more targeted and slightly riskier.
 * ============================================================ */

#define RUN_MSR_RECON       1
#define RUN_VMMCALL_ENUM    1
#define RUN_VMMCALL_IOMMU   0  /* Enable after confirming enum works */

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
 * Global result buffer - exported for kldsym lookup
 *
 * Non-static so the kernel linker includes it in the symbol
 * table. Userland finds it via:
 *   kldsym(kid, KLDSYM_LOOKUP, { .symname = "hv_results" })
 * then reads it with kernel_copyout().
 * ============================================================ */

struct kmod_result_buf hv_results;

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
 * Module init - called by kernel linker during kldload
 *
 * The kernel linker finds hv_init via the SYSINIT entry in
 * the set_sysinit_set section and calls it during module load.
 * By the time kldload() returns to userland, all campaigns
 * have completed and hv_results is populated.
 * ============================================================ */

static void hv_init(const void *arg __attribute__((unused))) {
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

    /* Mark completion */
    memory_barrier();
    hv_results.status = KMOD_STATUS_DONE;
    memory_barrier();
}

/* ============================================================
 * SYSINIT registration
 *
 * Places a pointer to our sysinit struct in the set_sysinit_set
 * section. The FreeBSD kernel linker iterates this section
 * during module load and calls each registered function.
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
