/*
 * dump_system.c - Standalone PS5 system SELF dumper payload
 *
 * Self-contained payload that decrypts system SELFs using the pagertab swap
 * technique. Does NOT require daemon IPC - runs directly as a payload.
 *
 * Compile:
 *   /opt/ps5-payload-sdk/bin/prospero-clang dump_system.c -o dump_system.elf -lps5api
 *
 * Send to PS5 (after etaHEN is loaded):
 *   nc <PS5_IP> 9021 < dump_system.elf
 *
 * Decrypted ELFs will be written to /data/etaHEN/system_dump/
 * Retrieve via FTP on port 1337.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/elf64.h>

#include <ps5/kernel.h>

/* ============================================================
 * PS5 notification support
 * ============================================================ */

typedef struct {
    int type;
    int req_id;
    int priority;
    int msg_id;
    int target_id;
    int user_id;
    int unk1;
    int unk2;
    int app_id;
    int error_num;
    int unk3;
    char use_icon_image_uri;
    char message[1024];
    char uri[1024];
    char unkstr[1024];
} SceNotificationRequest;

int sceKernelSendNotificationRequest(int device,
    SceNotificationRequest *req, size_t size, int blocking);

static void notify(const char *fmt, ...) {
    SceNotificationRequest noti;
    memset(&noti, 0, sizeof(noti));

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(noti.message, sizeof(noti.message), fmt, ap);
    va_end(ap);

    noti.type = 0;
    noti.use_icon_image_uri = 1;
    noti.target_id = -1;
    strncpy(noti.uri, "cxml://psnotification/tex_icon_system",
            sizeof(noti.uri) - 1);

    sceKernelSendNotificationRequest(0, &noti, sizeof(noti), 0);
    printf("[dump] %s\n", noti.message);
}

/* ============================================================
 * SELF header structures
 * ============================================================ */

#define SELF_ORBIS_MAGIC    0x1D3D154F
#define SELF_PROSPERO_MAGIC 0xEEF51454
#define PS5_PAGE_SIZE       0x4000
#define SUPERPAGE_SIZE      0x200000

#define PT_SCE_DYNLIBDATA   0x61000000
#define PT_SCE_RELRO        0x61000010
#define PT_SCE_COMMENT      0x6FFFFF00
#define PT_SCE_VERSION      0x6FFFFF01

struct sce_self_header {
    uint32_t magic;
    uint8_t  version;
    uint8_t  mode;
    uint8_t  endian;
    uint8_t  attributes;
    uint32_t key_type;
    uint16_t header_size;
    uint16_t metadata_size;
    uint64_t file_size;
    uint16_t segment_count;
    uint16_t flags;
    char     pad_2[0x4];
};

struct sce_self_segment_header {
    uint64_t flags;
    uint64_t offset;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
};

/* ============================================================
 * Pagertab swap (self pager) - decrypts SELF segments via kernel
 * ============================================================ */

static uint16_t g_fwver = 0;
static intptr_t g_pagertab_addr = 0;
static intptr_t g_vnodepagerops_addr = 0;
static intptr_t g_selfpagerops_addr = 0;

static const int PAGERTAB_VNODE_INDEX = 2;
static const int PAGERTAB_SELF_INDEX  = 7;

static int pager_init(void) {
    if (g_pagertab_addr != 0)
        return 0;

    g_fwver = kernel_get_fw_version() >> 16;

    switch (g_fwver) {
    case 0x100: case 0x101: case 0x102: case 0x105:
    case 0x110: case 0x111: case 0x112:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC27C40;
        break;
    case 0x113: case 0x114:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC27CA0;
        break;
    case 0x200:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4EF60;
        break;
    case 0x220: case 0x225: case 0x226:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4EFA0;
        break;
    case 0x230: case 0x250: case 0x270:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4F120;
        break;
    case 0x300: case 0x310: case 0x320: case 0x321:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xCAF8C0;
        break;
    case 0x400: case 0x402: case 0x403: case 0x450: case 0x451:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xD20840;
        break;
    case 0x500: case 0x502: case 0x510: case 0x550:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE0FEF0;
        break;
    case 0x600: case 0x602: case 0x650:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE30410;
        break;
    case 0x700: case 0x701:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE310C0;
        break;
    case 0x720: case 0x740: case 0x760: case 0x761:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE41180;
        break;
    case 0x800: case 0x820: case 0x840: case 0x860:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE31250;
        break;
    case 0x900: case 0x905: case 0x920: case 0x940: case 0x960:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDE0420;
        break;
    case 0x1000: case 0x1001:
        g_pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDE04F0;
        break;
    default:
        printf("[dump] Unsupported firmware 0x%x\n", g_fwver);
        return ENOSYS;
    }

    g_vnodepagerops_addr = kernel_getlong(g_pagertab_addr + PAGERTAB_VNODE_INDEX * 8);
    g_selfpagerops_addr  = kernel_getlong(g_pagertab_addr + PAGERTAB_SELF_INDEX * 8);

    printf("[dump] Pagertab init OK (fw=0x%x)\n", g_fwver);
    return 0;
}

static void *mmap_self(void *addr, size_t len, int prot, int flags,
                       int fd, off_t offset) {
    int rc = pager_init();
    if (rc != 0) {
        errno = rc;
        return MAP_FAILED;
    }

    /* Swap vnode pager ops -> self pager ops */
    kernel_setlong(g_pagertab_addr + (PAGERTAB_VNODE_INDEX * 8),
                   g_selfpagerops_addr);

    void *res = mmap(addr, len, prot, flags, fd, offset);

    /* Restore vnode pager ops */
    kernel_setlong(g_pagertab_addr + (PAGERTAB_VNODE_INDEX * 8),
                   g_vnodepagerops_addr);

    return res;
}

/* ============================================================
 * SELF decryption
 * ============================================================ */

static int decrypt_self_fd(int fd, char **out_data, uint64_t *out_size) {
    if (!out_data || !out_size)
        return -1;

    *out_data = NULL;
    *out_size = 0;

    struct sce_self_header self_hdr;
    if (pread(fd, &self_hdr, sizeof(self_hdr), 0) != sizeof(self_hdr))
        return -5; /* not a SELF */

    if (self_hdr.magic != SELF_ORBIS_MAGIC &&
        self_hdr.magic != SELF_PROSPERO_MAGIC)
        return -5; /* not a SELF */

    int elf_off = sizeof(struct sce_self_header) +
                  sizeof(struct sce_self_segment_header) * self_hdr.segment_count;

    Elf64_Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), elf_off) != sizeof(ehdr))
        return -2;

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3)
        return -3;

    int phdr_count = ehdr.e_phnum;
    Elf64_Phdr phdrs[phdr_count];
    int phdrs_size = phdr_count * sizeof(Elf64_Phdr);
    int phdrs_off = elf_off + sizeof(ehdr);

    if (pread(fd, phdrs, phdrs_size, phdrs_off) != phdrs_size)
        return -2;

    uint64_t output_size = 0;
    int version_seg = -1;
    for (int i = 0; i < phdr_count; i++) {
        if (phdrs[i].p_offset + phdrs[i].p_filesz > output_size)
            output_size = phdrs[i].p_offset + phdrs[i].p_filesz;
        if (phdrs[i].p_type == PT_SCE_VERSION)
            version_seg = i;
    }

    if (output_size == 0)
        return -3;

    void *out_buf = mmap(NULL, output_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_buf == MAP_FAILED)
        return -3;

    for (int i = 0; i < phdr_count; i++) {
        Elf64_Phdr *p = &phdrs[i];
        if ((p->p_type != PT_LOAD && p->p_type != PT_SCE_DYNLIBDATA &&
             p->p_type != PT_SCE_RELRO && p->p_type != PT_SCE_COMMENT) ||
            p->p_filesz == 0)
            continue;

        off_t seg_off = ((uint64_t)i) << 32;
        if (g_fwver >= 0x900) {
            uint64_t aligned_vaddr = p->p_vaddr & ~(p->p_align - 1);
            seg_off |= aligned_vaddr & (SUPERPAGE_SIZE - 1);
        }

        void *seg = mmap_self(NULL, p->p_filesz, PROT_READ,
                              MAP_PRIVATE | MAP_ALIGNED(p->p_align),
                              fd, seg_off);
        if (seg == MAP_FAILED) {
            munmap(out_buf, output_size);
            return (errno == ENOSYS) ? -4 : -3;
        }

        if (mlock(seg, p->p_filesz)) {
            munmap(seg, p->p_filesz);
            munmap(out_buf, output_size);
            return -6;
        }

        memcpy((uint8_t *)out_buf + p->p_offset, seg, p->p_filesz);
        munmap(seg, p->p_filesz);
    }

    /* Copy version segment (unencrypted, at end of file) */
    if (version_seg != -1) {
        Elf64_Phdr *p = &phdrs[version_seg];
        struct stat st;
        if (fstat(fd, &st) == 0) {
            int ver_self_off = st.st_size - p->p_filesz;
            pread(fd, (char *)out_buf + p->p_offset, p->p_filesz, ver_self_off);
        }
    }

    /* Copy ELF + program headers */
    memcpy(out_buf, &ehdr, sizeof(ehdr));
    memcpy((char *)out_buf + sizeof(ehdr), phdrs, phdrs_size);

    *out_data = out_buf;
    *out_size = output_size;
    return 0;
}

/* ============================================================
 * File/directory helpers
 * ============================================================ */

static void mkdirs(const char *dir) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    }
    mkdir(tmp, 0777);
}

static int is_self_magic(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    uint32_t magic = 0;
    read(fd, &magic, sizeof(magic));
    close(fd);
    return (magic == SELF_PROSPERO_MAGIC || magic == SELF_ORBIS_MAGIC);
}

static int has_self_ext(const char *name) {
    const char *ext = strrchr(name, '.');
    if (!ext) return 0;
    return (strcasecmp(ext, ".sprx") == 0 ||
            strcasecmp(ext, ".prx")  == 0 ||
            strcasecmp(ext, ".self") == 0 ||
            strcasecmp(ext, ".elf")  == 0 ||
            strcasecmp(ext, ".bin")  == 0 ||
            strcasecmp(ext, ".dll")  == 0);
}

/* ============================================================
 * Decrypt a single file
 * ============================================================ */

static int decrypt_file(const char *in_path, const char *out_path,
                        int *ok, int *fail) {
    int fd = open(in_path, O_RDONLY);
    if (fd < 0) {
        printf("[dump] Cannot open: %s (%s)\n", in_path, strerror(errno));
        if (fail) (*fail)++;
        return -1;
    }

    char *data = NULL;
    uint64_t size = 0;
    int rc = decrypt_self_fd(fd, &data, &size);
    close(fd);

    if (rc == -5)
        return rc; /* not a SELF, skip silently */

    if (rc != 0) {
        printf("[dump] Decrypt failed (%d): %s\n", rc, in_path);
        if (fail) (*fail)++;
        return rc;
    }

    /* Ensure parent dir exists */
    char dir_buf[PATH_MAX];
    strncpy(dir_buf, out_path, sizeof(dir_buf) - 1);
    dir_buf[sizeof(dir_buf) - 1] = '\0';
    char *sl = strrchr(dir_buf, '/');
    if (sl) {
        *sl = '\0';
        mkdirs(dir_buf);
    }

    int ofd = open(out_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (ofd < 0) {
        printf("[dump] Cannot create: %s (%s)\n", out_path, strerror(errno));
        munmap(data, size);
        if (fail) (*fail)++;
        return -1;
    }

    ssize_t wr = write(ofd, data, size);
    close(ofd);
    munmap(data, size);

    if (wr != (ssize_t)size) {
        printf("[dump] Short write: %s\n", out_path);
        unlink(out_path);
        if (fail) (*fail)++;
        return -1;
    }

    printf("[dump] OK: %s\n", in_path);
    if (ok) (*ok)++;
    return 0;
}

/* ============================================================
 * Scan a directory and decrypt all SELFs
 * ============================================================ */

static void scan_dir(const char *sys_dir, const char *out_base,
                     const char *label, int *ok, int *fail) {
    DIR *dir = opendir(sys_dir);
    if (!dir) {
        printf("[dump] Cannot open dir: %s (%s)\n", sys_dir, strerror(errno));
        return;
    }

    printf("[dump] Scanning: %s\n", sys_dir);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            /* Recurse into subdirectories */
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            char sub_in[PATH_MAX], sub_out[PATH_MAX];
            snprintf(sub_in,  sizeof(sub_in),  "%s/%s", sys_dir, entry->d_name);
            snprintf(sub_out, sizeof(sub_out), "%s/%s/%s", out_base, label, entry->d_name);
            scan_dir(sub_in, out_base, label, ok, fail);
            continue;
        }

        if (entry->d_type != DT_REG)
            continue;

        if (!has_self_ext(entry->d_name))
            continue;

        char in_path[PATH_MAX], out_path[PATH_MAX];
        snprintf(in_path,  sizeof(in_path),  "%s/%s", sys_dir, entry->d_name);
        snprintf(out_path, sizeof(out_path), "%s/%s/%s", out_base, label, entry->d_name);

        if (!is_self_magic(in_path))
            continue;

        decrypt_file(in_path, out_path, ok, fail);
    }

    closedir(dir);
}

/* ============================================================
 * Main entry point
 * ============================================================ */

int main(void) {
    const char *output_dir = "/data/etaHEN/system_dump";

    /* System directories containing SELFs on PS5 */
    static const struct {
        const char *path;
        const char *label;
        int is_file;  /* 1 = single file, 0 = directory */
    } targets[] = {
        { "/system/common/lib",            "system_common_lib",            0 },
        { "/system/common/lib/Firmware",   "system_common_lib_Firmware",   0 },
        { "/system/priv/lib",              "system_priv_lib",              0 },
        { "/system/sys",                   "system_sys",                   0 },
        { "/system/vsh/app",               "system_vsh_app",               0 },
        { "/system_ex/common_ex/lib",      "system_ex_common_ex_lib",      0 },
        { "/system_ex/app",                "system_ex_app",                0 },
        { "/mini-syscore.elf",             "mini-syscore.elf",             1 },
    };
    int num_targets = sizeof(targets) / sizeof(targets[0]);

    int total_ok = 0, total_fail = 0;

    notify("Starting system SELF dump...\nThis may take a while.");
    mkdirs(output_dir);

    /* Initialize the pagertab swap */
    int rc = pager_init();
    if (rc != 0) {
        notify("FAILED: Unsupported firmware (0x%x)\nCannot decrypt.", g_fwver);
        return 1;
    }

    for (int i = 0; i < num_targets; i++) {
        struct stat st;
        if (stat(targets[i].path, &st) != 0) {
            printf("[dump] Not found: %s\n", targets[i].path);
            continue;
        }

        if (targets[i].is_file && S_ISREG(st.st_mode)) {
            char out_path[PATH_MAX];
            snprintf(out_path, sizeof(out_path), "%s/%s",
                     output_dir, targets[i].label);
            if (is_self_magic(targets[i].path))
                decrypt_file(targets[i].path, out_path, &total_ok, &total_fail);
        } else if (S_ISDIR(st.st_mode)) {
            scan_dir(targets[i].path, output_dir, targets[i].label,
                     &total_ok, &total_fail);
        }

        /* Progress notification every few directories */
        if ((i % 3) == 2) {
            notify("Dump progress: %d OK, %d failed so far...",
                   total_ok, total_fail);
        }
    }

    notify("System SELF dump complete!\n%d decrypted, %d failed\nOutput: %s",
           total_ok, total_fail, output_dir);

    printf("[dump] Done. %d ok, %d fail\n", total_ok, total_fail);
    return 0;
}
