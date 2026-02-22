/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/mman.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <machine/param.h>
#include <ps5/payload.h>
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include "payload_bin.c"

int patch_app_db(void);
int sceKernelSetProcessName(const char *name);

/*
 * KCFI bypass: Patch IDT[6] to redirect Invalid Opcode (UD2) exceptions
 * through kstuff's INT1 handler on IST7.
 *
 * How this works (verified by disassembly of the kstuff payload binary):
 *
 * LLVM KCFI inserts before each indirect call:
 *   mov eax, <expected_hash>
 *   sub eax, [target-4]
 *   je  .ok
 *   ud2            ; 2-byte opcode 0F 0B triggers INT6
 *   .ok: call target
 *
 * By copying IDT[1] (kstuff's handler) to IDT[6], UD2 exceptions enter
 * kstuff's IST7 handler at offset 0x276d0 in the payload. For ring 0
 * faults (kernel KCFI checks), the handler:
 *
 *   1. Checks RFLAGS.AC - not set for KCFI, takes breakpoint table path
 *   2. Searches breakpoint table (0x27930) - no match for UD2 addresses
 *   3. Checks 2 special addresses (0x279c0) - no match
 *   4. Calls address validator at 0x273d0 - returns 0 (unknown address)
 *   5. Calls dispatch at 0x266c0 - returns 0 (unknown address)
 *   6. Calls handlers at 0x25920, 0x28b20, 0x29510 - all return 0
 *   7. Falls through 0xDEB7 register signature checks - no match
 *   8. At 0x27d3a: test eax,eax - eax IS 0 from step 6
 *   9. At 0x27d42: add qword [rbx+0xe8], 2 - advances RIP past UD2
 *  10. Returns to instruction after UD2 - kernel continues normally
 *
 * INT1 and INT6 share the same stack frame layout (no error code) and
 * can safely share IST7 since both are synchronous exceptions.
 */

static uint64_t cfi_get_idt_offset(uint32_t fw) {
    switch (fw & 0xFFFF0000) {
    case 0x03000000: case 0x03100000:
    case 0x03200000: case 0x03210000: return 0x642dc80;
    case 0x04000000: case 0x04020000: case 0x04030000:
    case 0x04500000: case 0x04510000: return 0x64cdc80;
    case 0x05000000: case 0x05020000:
    case 0x05100000: case 0x05500000: return 0x660dca0;
    case 0x06000000: case 0x06020000: case 0x06500000: return 0x655dde0;
    case 0x07000000: case 0x07010000: case 0x07200000:
    case 0x07400000: case 0x07600000: case 0x07610000: return 0x2E7FDF0;
    case 0x08000000: case 0x08200000:
    case 0x08400000: case 0x08600000: return 0x2eb3df0;
    case 0x09000000: case 0x09050000: case 0x09200000:
    case 0x09400000: case 0x09600000: return 0x2d94300;
    case 0x10000000: case 0x10010000: case 0x10200000:
    case 0x10400000: case 0x10600000: return 0x2d5c300;
    default: return 0;
    }
}

static void cfi_bypass(void) {
    uint32_t fw = 0;
    size_t sz = sizeof(fw);
    sysctlbyname("kern.sdk_version", &fw, &sz, NULL, 0);

    if (fw < 0x03000000) return; /* Byepervisor handles FW < 3.00 */

    uint64_t idt_off = cfi_get_idt_offset(fw);
    if (!idt_off) {
        klog_printf("[cfi] unsupported FW 0x%08x\n", fw);
        return;
    }

    uint64_t idt_base = KERNEL_ADDRESS_DATA_BASE + idt_off;

    /* Read IDT[1] - kstuff's INT1 handler with IST7 */
    uint8_t int1[16], int6[16];
    if (kernel_copyout(idt_base + 16, int1, 16) != 0) {
        klog_puts("[cfi] failed to read IDT[1]");
        return;
    }

    /* Verify kstuff installed its handler with IST7 */
    if ((int1[4] & 7) != 7) {
        klog_printf("[cfi] IDT[1] IST=%d (expected 7), kstuff not ready\n",
                    int1[4] & 7);
        return;
    }

    /* Check if already patched */
    kernel_copyout(idt_base + 16 * 6, int6, 16);
    if (memcmp(int1, int6, 16) == 0) {
        klog_puts("[cfi] IDT[6] already redirected to kstuff");
        return;
    }

    /* Copy IDT[1] to IDT[6] */
    if (kernel_copyin(int1, idt_base + 16 * 6, 16) != 0) {
        klog_puts("[cfi] failed to write IDT[6]");
        return;
    }

    /* Verify the write */
    uint8_t verify[16];
    kernel_copyout(idt_base + 16 * 6, verify, 16);
    if (memcmp(int1, verify, 16) != 0) {
        klog_puts("[cfi] IDT[6] write verification failed");
        return;
    }

    klog_puts("[cfi] KCFI bypass active: IDT[6] -> kstuff INT1 handler");
}

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))

#define IOVEC_ENTRY(x) { (void*)(x), (x) ? strlen(x) + 1 : 0 }
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

static int remount_system_ex(void) {
    struct iovec iov[] = {
        IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
        IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
        IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
        IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
        IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
        IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
        IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
    };
    return nmount(iov, IOVEC_SIZE(iov), MNT_UPDATE);
}

static int mount_nullfs(const char* src, const char* dst) {
    struct iovec iov[] = {
        IOVEC_ENTRY("fstype"), IOVEC_ENTRY("nullfs"),
        IOVEC_ENTRY("from"),   IOVEC_ENTRY(src),
        IOVEC_ENTRY("fspath"), IOVEC_ENTRY(dst),
    };
    return nmount(iov, IOVEC_SIZE(iov), 0);
}

static int bind_mount_title(const char* title_id, const char* src) {
    char dst[PATH_MAX];
    struct stat st;

    snprintf(dst, sizeof(dst), "/system_ex/app/%s/sce_sys", title_id);
    if (stat(dst, &st) == 0) {
        klog_printf("Title already mounted: %s\n", title_id);
        return 0;
    }

    snprintf(dst, sizeof(dst), "/system_ex/app/%s", title_id);
    if (unmount(dst, 0) != 0 && errno != EINVAL) {
        klog_perror("Failed to unmount partially mounted title");
    }

    if (mkdir(dst, 0755) && errno != EEXIST) {
        klog_perror("Failed to create mount directory for title");
        return -1;
    }

    if (mount_nullfs(src, dst) != 0) {
        klog_perror("Failed to bind mount title with mount_nullfs");
        return -1;
    }

    klog_printf("Title Mounted Successfully: %s -> %s\n", src, dst);
    return 0;
}

static int read_mount_link(const char* path, char* buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        klog_perror("Failed to open mount.lnk file");
        return -1;
    }

    memset(buf, 0, size);
    ssize_t n = read(fd, buf, size - 1);
    if (n < 0) {
        klog_perror("Failed to read mount.lnk file");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int bind_mount_all_titles(const char* path) {
    char mountlnk[PATH_MAX];
    struct dirent *entry;
    struct stat st;
    DIR *dir = opendir(path);

    if (!dir) {
        klog_perror("Failed to open directory while binding mounts");
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (strlen(entry->d_name) != 9) {
            continue;
        }

        snprintf(mountlnk, sizeof(mountlnk), "%s/%s/mount.lnk", path, entry->d_name);

        if (stat(mountlnk, &st) != 0) {
            continue;
        }

        if (read_mount_link(mountlnk, mountlnk, sizeof(mountlnk)) != 0) {
            klog_printf("Failed to read mount.lnk for title %s\n", entry->d_name);
            continue;
        }

        if (bind_mount_title(entry->d_name, mountlnk) != 0) {
            klog_printf("Failed to bind mount title %s -> %s\n", entry->d_name, mountlnk);
            continue;
        }

        klog_printf("Successfully mounted title %s -> %s\n", entry->d_name, mountlnk);
    }

    closedir(dir);
    return 0;
}

static int monitor_usb_changes(void) {
    struct kevent evt;
    int kq;

    if ((kq = kqueue()) < 0) {
        klog_perror("Failed to create kqueue");
        return -1;
    }

    EV_SET(&evt, 0, EVFILT_FS, EV_ADD | EV_CLEAR, 0, 0, 0);
    if (kevent(kq, &evt, 1, NULL, 0, NULL) < 0) {
        klog_perror("Failed to register usb event filter with kevent");
        close(kq);
        return -1;
    }

    while (1) {
        if (kevent(kq, NULL, 0, &evt, 1, NULL) < 0) {
            klog_perror("kevent wait failed while monitoring USB changes");
            break;
        }

        if (bind_mount_all_titles("/user/app") < 0) {
            klog_perror("Failed to bind mount /user/app titles after USB change");
        }
    }

    close(kq);
    return 0;
}

static void
pt_load(const void* image, void* base, Elf64_Phdr *phdr) {
  if(phdr->p_memsz && phdr->p_filesz) {
      memcpy(base + phdr->p_vaddr, image + phdr->p_offset, phdr->p_filesz);
  }
}

int main(void) {
	sceKernelSetProcessName("kstuff.elf");
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)___ps5_kstuff_payload_bin;
    Elf64_Phdr *phdr = (Elf64_Phdr*)(___ps5_kstuff_payload_bin + ehdr->e_phoff);
    Elf64_Shdr *shdr = (Elf64_Shdr*)(___ps5_kstuff_payload_bin + ehdr->e_shoff);
    void *base = (void*)0x0000000926100000;
    uintptr_t min_vaddr = -1;
    uintptr_t max_vaddr = 0;
    size_t base_size;

    // Compute size of virtual memory region.
    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_vaddr < min_vaddr) {
            min_vaddr = phdr[i].p_vaddr;
        }

        if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }
    min_vaddr = TRUNC_PG(min_vaddr);
    max_vaddr = ROUND_PG(max_vaddr);
    base_size = max_vaddr - min_vaddr;

    // allocate memory.
    if((base=mmap(base, base_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Parse program headers.
    for(int i=0; i<ehdr->e_phnum; i++) {
        switch(phdr[i].p_type) {
        case PT_LOAD:
            pt_load(___ps5_kstuff_payload_bin, base, &phdr[i]);
            break;
        }
    }

    // Set protection bits on mapped segments.
    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
            continue;
        }
        if(mprotect(base + phdr[i].p_vaddr, ROUND_PG(phdr[i].p_memsz),
                    PFLAGS(phdr[i].p_flags))) {
            perror("mprotect");
            return EXIT_FAILURE;
        }
    }

    void (*entry)(payload_args_t*) = base + ehdr->e_entry;
    payload_args_t* args = payload_get_args();

    entry(args);
    if(*args->payloadout == 0) {
        puts("patching app.db");
        *args->payloadout = patch_app_db();
    }

    /* Apply KCFI bypass now that kstuff has initialized */
    cfi_bypass();

    klog_printf("Remounting /system_ex and mounting titles...\n");
    remount_system_ex();
    bind_mount_all_titles("/user/app");

    monitor_usb_changes();

    return 0; 
}
