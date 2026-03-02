/*
 * hv_kmod.c - PS5 Hypervisor VMMCALL Fuzzer Kernel Module
 *
 * This is a flat binary kernel module for PS5 FW 4.03.
 * It runs in ring 0 (kernel mode) with full hardware access.
 *
 * Loading: The userland payload (main.c) allocates physical memory,
 * copies this binary there, clears NX in guest page tables, installs
 * a custom syscall pointing here, and calls it.
 *
 * Calling convention:
 *   int kmod_main(struct thread *td, struct kmod_args *args)
 *   args->dmap_base:  DMAP virtual address base
 *   args->result_pa:  Physical address of shared result buffer
 *   args->flags:      Control flags (which campaigns to run)
 */

#include <stdint.h>

/* ============================================================
 * Shared data structures (must match main.c definitions)
 * ============================================================ */

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_MAX_RESULTS    64
#define KMOD_STATUS_INIT    0
#define KMOD_STATUS_RUNNING 1
#define KMOD_STATUS_DONE    2

/* Flags for selecting campaigns */
#define KMOD_FLAG_VMMCALL_ENUM     (1 << 0)  /* Enumerate hypercall numbers */
#define KMOD_FLAG_VMMCALL_IOMMU    (1 << 1)  /* Probe IOMMU hypercalls */
#define KMOD_FLAG_VMCB_PROBE       (1 << 2)  /* Probe VMCB fields */
#define KMOD_FLAG_MSR_RECON        (1 << 3)  /* Read HV-related MSRs */
#define KMOD_FLAG_ALL              0xFFFFFFFF

struct vmmcall_result {
    uint64_t rax_in;
    uint64_t rcx_in;
    uint64_t rdx_in;
    uint64_t rdi_in;
    uint64_t rsi_in;
    uint64_t r8_in;
    uint64_t rax_out;
    uint64_t rcx_out;
    uint64_t rdx_out;
    uint64_t rdi_out;
    uint64_t rsi_out;
    uint64_t r8_out;
    uint32_t survived;     /* 1 = returned normally */
    uint32_t campaign_id;  /* Which campaign produced this */
};

struct kmod_result_buf {
    volatile uint64_t magic;
    volatile uint32_t status;
    volatile uint32_t current_campaign;
    volatile uint32_t current_probe;
    volatile uint32_t num_results;
    volatile uint32_t num_msr_results;
    volatile uint32_t pad;
    /* MSR results */
    struct {
        uint32_t msr_id;
        uint32_t valid;   /* 1 = read succeeded */
        uint64_t value;
    } msr_results[32];
    /* VMMCALL results */
    struct vmmcall_result results[KMOD_MAX_RESULTS];
};

/* Syscall args passed from userland */
struct kmod_args {
    uint64_t dmap_base;
    uint64_t result_pa;
    uint64_t flags;
};

/* ============================================================
 * Inline assembly helpers - direct hardware access in ring 0
 * ============================================================ */

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
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

/*
 * Execute VMMCALL with full register control.
 * On AMD SVM, VMMCALL causes a #VMEXIT(VMMCALL).
 * The hypervisor reads guest registers, processes the request,
 * and resumes the guest (or kills it).
 *
 * Returns 1 if the VMMCALL returned normally, 0 if it didn't
 * (which shouldn't happen since we wouldn't be running).
 */
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

    *rax_out = a;
    *rcx_out = c;
    *rdx_out = d;
    *rdi_out = di;
    *rsi_out = si;
    *r8_out  = r8_val;
    return 1;
}

static void store_result(struct kmod_result_buf *buf,
                         uint32_t campaign,
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
 * Campaign 1: VMMCALL Hypercall Number Enumeration
 *
 * Systematically probe RAX = 0x00 through 0x1F (32 values)
 * with all other registers zeroed.
 * The PS5 HV uses RAX as the hypercall number.
 * Known range: 17 hypercalls identified in earlier research.
 * ============================================================ */

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

/* ============================================================
 * Campaign 2: IOMMU Hypercall Probing
 *
 * Known IOMMU hypercalls from PS5 HV research:
 *   - alloc_dev, free_dev, set_dev, inv_dev, etc.
 * Try RAX values that might be IOMMU-related with
 * plausible device ID arguments.
 *
 * We use RDI = device_id candidates (0, 1, 0x10, 0x100)
 * with hypercall numbers in the expected IOMMU range.
 * ============================================================ */

static void campaign_vmmcall_iommu(struct kmod_result_buf *buf) {
    buf->current_campaign = 2;

    /* IOMMU hypercalls are likely in the range 0x06-0x0C based on
       research showing 6 IOMMU-related + 2 SELF-loading hypercalls.
       Probe with various device IDs. */
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

/* ============================================================
 * Campaign 3: MSR Reconnaissance
 *
 * Read AMD SVM and HV-related MSRs from kernel mode.
 * These provide insight into HV configuration without
 * requiring VMMCALL (safer).
 *
 * Note: Some MSRs may cause #GP if the HV traps them.
 * We don't have exception handling, so if a read causes
 * a fault, the kernel will panic. Start with safe MSRs only.
 * ============================================================ */

/* AMD MSR definitions */
#define MSR_EFER            0xC0000080  /* Extended Feature Enable */
#define MSR_STAR            0xC0000081  /* SYSCALL target */
#define MSR_LSTAR           0xC0000082  /* Long mode SYSCALL target */
#define MSR_SFMASK          0xC0000084  /* SYSCALL flag mask */
#define MSR_FS_BASE         0xC0000100  /* FS base */
#define MSR_GS_BASE         0xC0000101  /* GS base */
#define MSR_KERNEL_GS_BASE  0xC0000102  /* Kernel GS base (swapgs) */
#define MSR_TSC_AUX         0xC0000103  /* TSC auxiliary */

/* AMD SVM MSRs - these may be trapped by the HV */
#define MSR_VM_CR           0xC0010114  /* VM_CR - SVM control */
#define MSR_VM_HSAVE_PA     0xC0010117  /* Host save area PA */

static void campaign_msr_recon(struct kmod_result_buf *buf) {
    buf->current_campaign = 4;

    /* Safe MSRs that the kernel itself reads - unlikely to be trapped */
    static const uint32_t safe_msrs[] = {
        MSR_EFER,
        MSR_LSTAR,
        MSR_STAR,
        MSR_SFMASK,
        MSR_FS_BASE,
        MSR_GS_BASE,
        MSR_KERNEL_GS_BASE,
        MSR_TSC_AUX,
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

    /* Also read CR values and store as pseudo-MSRs */
    if (buf->num_msr_results < 32) {
        uint32_t idx = buf->num_msr_results;
        buf->msr_results[idx].msr_id = 0xFFFF0000; /* pseudo: CR0 */
        buf->msr_results[idx].value = read_cr0();
        buf->msr_results[idx].valid = 1;
        buf->num_msr_results = idx + 1;
    }
    if (buf->num_msr_results < 32) {
        uint32_t idx = buf->num_msr_results;
        buf->msr_results[idx].msr_id = 0xFFFF0003; /* pseudo: CR3 */
        buf->msr_results[idx].value = read_cr3();
        buf->msr_results[idx].valid = 1;
        buf->num_msr_results = idx + 1;
    }
    if (buf->num_msr_results < 32) {
        uint32_t idx = buf->num_msr_results;
        buf->msr_results[idx].msr_id = 0xFFFF0004; /* pseudo: CR4 */
        buf->msr_results[idx].value = read_cr4();
        buf->msr_results[idx].valid = 1;
        buf->num_msr_results = idx + 1;
    }
}

/* ============================================================
 * Module entry point
 *
 * Called from the kernel syscall dispatcher:
 *   int kmod_main(struct thread *td, struct kmod_args *uap)
 *
 * The userland loader installs this as a custom syscall handler.
 * ============================================================ */

int kmod_main(void *td, struct kmod_args *args) {
    /* Compute result buffer virtual address via DMAP */
    struct kmod_result_buf *buf = (struct kmod_result_buf *)
        (args->dmap_base + args->result_pa);

    /* Initialize result buffer */
    buf->status = KMOD_STATUS_RUNNING;
    buf->current_campaign = 0;
    buf->current_probe = 0;
    buf->num_results = 0;
    buf->num_msr_results = 0;
    memory_barrier();
    buf->magic = KMOD_MAGIC;
    memory_barrier();

    uint64_t flags = args->flags;

    /* Campaign 4 (MSR recon) first - safest, no VMMCALL */
    if (flags & KMOD_FLAG_MSR_RECON) {
        campaign_msr_recon(buf);
    }

    /* Campaign 1: VMMCALL enumeration */
    if (flags & KMOD_FLAG_VMMCALL_ENUM) {
        campaign_vmmcall_enum(buf);
    }

    /* Campaign 2: IOMMU probing (more targeted, slightly riskier) */
    if (flags & KMOD_FLAG_VMMCALL_IOMMU) {
        campaign_vmmcall_iommu(buf);
    }

    /* Mark completion */
    memory_barrier();
    buf->status = KMOD_STATUS_DONE;
    memory_barrier();

    return 0;
}
