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

/* ─── Global state ─── */

static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_mmio_vaddr = 0;

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
 * Get the physical address of a kernel virtual address.
 * This walks the 4-level page tables through DMAP.
 */
static uint64_t kva_to_pa(uint64_t va) {
    /* We need the kernel's PML4 (CR3). We can get it from the kernel pmap. */
    /* For now, use a simplified approach via DMAP scanning */

    /* If the address is already in DMAP range, just subtract DMAP base */
    if (g_dmap_base && va >= g_dmap_base && va < g_dmap_base + 0x800000000ULL) {
        return va - g_dmap_base;
    }

    /* Otherwise we need full page table walk - not implemented yet */
    printf("[!] kva_to_pa: address 0x%lx is not in DMAP range\n", va);
    return 0;
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

/* ─── Main entry point ─── */

int main(void) {
    printf("\n");
    printf("==============================================\n");
    printf("  PS5 Hypervisor Research Tool\n");
    printf("  Target: FW 4.03 (educational/personal use)\n");
    printf("==============================================\n\n");

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

    notify("[HV Research] Done! Check logs.");

    return 0;
}
