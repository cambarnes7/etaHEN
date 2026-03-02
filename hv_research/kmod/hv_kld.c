/*
 * hv_kld.c - PS5 Hypervisor Research Kernel Module (KLD)
 *
 * FreeBSD kernel loadable module for PS5 FW 4.03.
 * Loaded via kldload(2), runs init code in kernel context (ring 0).
 *
 * Build: produces hv_kmod.ko (ET_REL ELF, loaded by kernel linker)
 * Load:  syscall(304, "/data/etaHEN/hv_kmod.ko")
 * Read:  results written to shared DMAP buffer (PA provided by userland)
 * Unload: syscall(305, kid)
 *
 * The kernel linker handles all memory allocation, relocation, and
 * SYSINIT dispatch. No sysent hijacking, NX clearing, or data cave
 * hunting required.
 *
 * Result delivery: Userland allocates direct memory, computes the
 * kernel DMAP VA, and patches this .ko's hv_result_dest variable
 * with that VA before writing to disk. The module writes results
 * directly to that address, bypassing kldsym (which is unreliable
 * on PS5).
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
 * Shared memory destination (patched by userland before load)
 *
 * Userland allocates direct memory, computes the kernel DMAP VA
 * (dmap_base + physical_address), and replaces this sentinel
 * value in the .ko binary before writing it to disk.
 *
 * The sentinel 0xD5C0FFEED5C0FFEE is scanned for and replaced.
 * If not patched, we fall back to the BSS hv_results buffer
 * (which requires kldsym to find - may not work on PS5).
 * ============================================================ */

#define RESULT_DEST_SENTINEL 0xD5C0FFEED5C0FFEEULL

volatile uint64_t hv_result_dest = RESULT_DEST_SENTINEL;

/* BSS fallback buffer (used only if sentinel not patched) */
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

static void store_result(struct kmod_result_buf *buf, uint32_t campaign,
                         uint64_t rax_in, uint64_t rcx_in,
                         uint64_t rdx_in, uint64_t rdi_in,
                         uint64_t rsi_in, uint64_t r8_in,
                         uint64_t rax_out, uint64_t rcx_out,
                         uint64_t rdx_out, uint64_t rdi_out,
                         uint64_t rsi_out, uint64_t r8_out,
                         uint32_t survived) {
    if (buf->num_results >= KMOD_MAX_RESULTS) return;
    uint32_t idx = buf->num_results;
    struct vmmcall_result *r = &buf->results[idx];
    r->rax_in = rax_in;   r->rcx_in = rcx_in;
    r->rdx_in = rdx_in;   r->rdi_in = rdi_in;
    r->rsi_in = rsi_in;   r->r8_in = r8_in;
    r->rax_out = rax_out;  r->rcx_out = rcx_out;
    r->rdx_out = rdx_out;  r->rdi_out = rdi_out;
    r->rsi_out = rsi_out;  r->r8_out = r8_out;
    r->survived = survived;
    r->campaign_id = campaign;
    memory_barrier();
    buf->num_results = idx + 1;
}

/* ============================================================
 * Campaign: MSR Reconnaissance (safe - no VMMCALL)
 * ============================================================ */

static void campaign_msr_recon(struct kmod_result_buf *buf) {
    buf->current_campaign = 4;

    static const uint32_t safe_msrs[] = {
        MSR_EFER, MSR_LSTAR, MSR_STAR, MSR_SFMASK,
        MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE, MSR_TSC_AUX,
    };
    int num_safe = sizeof(safe_msrs) / sizeof(safe_msrs[0]);

    for (int i = 0; i < num_safe && buf->num_msr_results < 32; i++) {
        uint32_t idx = buf->num_msr_results;
        buf->msr_results[idx].msr_id = safe_msrs[i];
        buf->msr_results[idx].value = rdmsr(safe_msrs[i]);
        buf->msr_results[idx].valid = 1;
        memory_barrier();
        buf->num_msr_results = idx + 1;
    }

    /* CR values as pseudo-MSRs */
    if (buf->num_msr_results < 32) {
        uint32_t idx = buf->num_msr_results;
        buf->msr_results[idx].msr_id = 0xFFFF0000;
        buf->msr_results[idx].value = read_cr0();
        buf->msr_results[idx].valid = 1;
        buf->num_msr_results = idx + 1;
    }
    if (buf->num_msr_results < 32) {
        uint32_t idx = buf->num_msr_results;
        buf->msr_results[idx].msr_id = 0xFFFF0003;
        buf->msr_results[idx].value = read_cr3();
        buf->msr_results[idx].valid = 1;
        buf->num_msr_results = idx + 1;
    }
    if (buf->num_msr_results < 32) {
        uint32_t idx = buf->num_msr_results;
        buf->msr_results[idx].msr_id = 0xFFFF0004;
        buf->msr_results[idx].value = read_cr4();
        buf->msr_results[idx].valid = 1;
        buf->num_msr_results = idx + 1;
    }
}

/* ============================================================
 * Campaign: VMMCALL Hypercall Number Enumeration
 *
 * Probe RAX = 0x00 through 0x1F with all other registers zeroed.
 * The PS5 HV uses RAX as the hypercall number.
 * ============================================================ */

#if RUN_VMMCALL_ENUM
static void campaign_vmmcall_enum(struct kmod_result_buf *buf) {
    buf->current_campaign = 1;

    for (uint64_t i = 0; i < 32 && buf->num_results < KMOD_MAX_RESULTS; i++) {
        buf->current_probe = (uint32_t)i;
        memory_barrier();

        uint64_t rax_out, rcx_out, rdx_out, rdi_out, rsi_out, r8_out;
        int ok = do_vmmcall(i, 0, 0, 0, 0, 0,
                            &rax_out, &rcx_out, &rdx_out,
                            &rdi_out, &rsi_out, &r8_out);

        store_result(buf, 1, i, 0, 0, 0, 0, 0,
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
static void campaign_vmmcall_iommu(struct kmod_result_buf *buf) {
    buf->current_campaign = 2;

    static const uint64_t dev_ids[] = { 0, 1, 0x10, 0x100, 0xFFFF };
    int num_devs = sizeof(dev_ids) / sizeof(dev_ids[0]);

    for (uint64_t hc = 6; hc <= 12 && buf->num_results < KMOD_MAX_RESULTS; hc++) {
        for (int d = 0; d < num_devs && buf->num_results < KMOD_MAX_RESULTS; d++) {
            buf->current_probe = (uint32_t)((hc << 16) | d);
            memory_barrier();

            uint64_t rax_out, rcx_out, rdx_out, rdi_out, rsi_out, r8_out;
            int ok = do_vmmcall(hc, 0, 0, dev_ids[d], 0, 0,
                                &rax_out, &rcx_out, &rdx_out,
                                &rdi_out, &rsi_out, &r8_out);

            store_result(buf, 2, hc, 0, 0, dev_ids[d], 0, 0,
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
 * have completed and the result buffer is populated.
 *
 * Result buffer selection:
 * - If hv_result_dest was patched by userland (≠ sentinel),
 *   use it as a kernel DMAP VA pointing to shared memory.
 *   Userland can read results directly without kldsym.
 * - Otherwise fall back to BSS hv_results (requires kldsym).
 * ============================================================ */

static void hv_init(const void *arg __attribute__((unused))) {
    struct kmod_result_buf *buf;

    /* Choose result buffer: shared memory (preferred) or BSS fallback */
    if (hv_result_dest != RESULT_DEST_SENTINEL && hv_result_dest != 0) {
        buf = (struct kmod_result_buf *)hv_result_dest;
    } else {
        buf = &hv_results;
    }

    /* Zero out the result buffer (no memset in freestanding kernel) */
    volatile uint8_t *p = (volatile uint8_t *)buf;
    for (unsigned int i = 0; i < sizeof(struct kmod_result_buf); i++)
        p[i] = 0;

    buf->status = KMOD_STATUS_RUNNING;
    memory_barrier();
    buf->magic = KMOD_MAGIC;
    memory_barrier();

    /* MSR reconnaissance - always safe */
#if RUN_MSR_RECON
    campaign_msr_recon(buf);
#endif

    /* VMMCALL enumeration - may trigger HV kill */
#if RUN_VMMCALL_ENUM
    campaign_vmmcall_enum(buf);
#endif

    /* IOMMU probing - more targeted, slightly riskier */
#if RUN_VMMCALL_IOMMU
    campaign_vmmcall_iommu(buf);
#endif

    /* Mark completion */
    memory_barrier();
    buf->status = KMOD_STATUS_DONE;
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
