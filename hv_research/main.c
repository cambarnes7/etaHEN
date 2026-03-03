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

/* Sentinel value in .ko that gets patched with DMAP-mapped output KVA */
#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL

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
#define SYS_kldstat     306
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
    g_ktext_base = KERNEL_ADDRESS_TEXT_BASE;

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
    printf("[*] KERNEL_ADDRESS_TEXT_BASE  = 0x%lx\n", KERNEL_ADDRESS_TEXT_BASE);
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

    if (ehdr->e_shoff && ehdr->e_shnum > 0) {
        Elf64_Shdr_t *shdrs = (Elf64_Shdr_t *)(ko_bytes + ehdr->e_shoff);

        /* Find .symtab */
        Elf64_Shdr_t *symtab_sh = NULL;
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
    printf("    SYSINIT has already executed - campaigns complete.\n");

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

        uint64_t trampoline_kva = 0;
        uint64_t total_2mb_checked = 0, total_2mb_mapped = 0;
        uint64_t total_pages_mapped = 0;
        uint8_t hdr[64];

        /* Scan ranges */
        struct { uint64_t start, end; const char *label; } ranges[4];
        int nranges = 0;

        /* Range 1: above kernel data */
        {
            uint64_t s = g_kdata_base + 0x8000000;
            uint64_t e = s + 0x40000000ULL; /* +1GB cap */
            if (s < e) { ranges[nranges++] = (typeof(ranges[0])){s, e, "above kdata"}; }
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

        if (trampoline_kva == 0) {
            printf("[-] Trampoline not found in any scan range.\n");
            goto idt_skip;
        }

        /* ── 4b-2: Read IDTR (SIDT is unprivileged on AMD64) ── */
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

        /* ── 4b-3: Install IDT gate ── */
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

        /* ── 4b-4: Fire! ── */
        printf("[*] Triggering INT %u → hv_idt_trampoline → hv_init...\n", HV_IDT_VECTOR);
        __asm__ volatile("int $210" ::: "memory");
        printf("[+] Returned from ring-0 interrupt handler!\n");

        /* ── 4b-5: Restore original IDT entry ── */
        kernel_copyin(&orig_gate, gate_addr, sizeof(orig_gate));
        printf("[*] IDT[%u] restored.\n", HV_IDT_VECTOR);

        /* Re-check results */
        memcpy(&first_qword, (void *)result_vaddr, sizeof(first_qword));
        if (first_qword != 0)
            printf("[+] Buffer is no longer zero — IDT invocation worked!\n");
        else
            printf("[-] Buffer still zero after IDT invocation.\n");

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
