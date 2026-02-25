/*
 * cfi_bypass.c - KCFI Bypass for PS5 FW 3.00+
 *
 * After kstuff installs its kernel payload with an INT1 (#DB) handler on
 * IST7, this module copies the IDT[1] gate descriptor to IDT[6] (Invalid
 * Opcode). KCFI check failures emit UD2 (0F 0B), which the CPU dispatches
 * as INT6. With our redirect, UD2 enters kstuff's handler, which on its
 * fallthrough path does RIP += 2 (skips the 2-byte UD2) and returns.
 * Execution continues at the call instruction after the CFI check.
 *
 * === KCFI instruction sequence ===
 *
 *     mov  eax, <expected_type_hash>
 *     sub  eax, dword ptr [target - 4]
 *     je   .Lok
 *     ud2                               ; INT6 - 2 bytes (0F 0B)
 *   .Lok:
 *     call target
 *
 * === Why kstuff's handler naturally handles this ===
 *
 * Verified by disassembly of the kstuff payload binary:
 *
 * The handler at payload offset 0x276d0 processes ring 0 faults through
 * table lookups. For an unrecognized address (like a KCFI UD2 site):
 *   - Search breakpoint table -> no match
 *   - Check special addresses -> no match
 *   - Call dispatch tables -> all return 0
 *   - Check for 0xDEB7 signature -> no match
 *   - Fallthrough: add qword [rbx+0xe8], 2 -> RIP += 2 (skip UD2)
 *   - Return to kernel -> execution continues after UD2
 *
 * INT1 and INT6 share the same stack frame layout (no error code pushed
 * for either) and can safely share IST7 since both are synchronous
 * exceptions that cannot nest with each other.
 *
 * === Integration ===
 *
 * Call patch_idt_cfi_bypass() from the bootstrapper AFTER kstuff has been
 * loaded and initialized. This reads IDT[1] via kernel_copyout, copies it
 * to IDT[6] via kernel_copyin, then verifies the write.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>

extern int kernel_copyin(const void *src, uint64_t kdest, size_t len);
extern int kernel_copyout(uint64_t ksrc, void *dest, size_t len);

#define IDT_ENTRY_SIZE  16   /* x86-64 IDT gate descriptor = 16 bytes */
#define IDT_VECTOR_DB    1   /* #DB - Debug Exception */
#define IDT_VECTOR_UD    6   /* #UD - Invalid Opcode (KCFI UD2 lands here) */

/* IDT gate descriptor (x86-64) */
struct idt_gate {
    uint16_t offset_lo;     /* handler offset bits 0-15 */
    uint16_t selector;      /* code segment selector */
    uint8_t  ist;           /* IST index (bits 0-2) */
    uint8_t  type_attr;     /* type, DPL, present */
    uint16_t offset_mid;    /* handler offset bits 16-31 */
    uint32_t offset_hi;     /* handler offset bits 32-63 */
    uint32_t reserved;
};

static uint64_t idt_handler_addr(const struct idt_gate *g) {
    return (uint64_t)g->offset_lo
         | ((uint64_t)g->offset_mid << 16)
         | ((uint64_t)g->offset_hi  << 32);
}

/*
 * IDT base address from KERNEL_ADDRESS_DATA_BASE.
 * These offsets are from kstuff's offsets.c (prosper0gdb).
 */
static uint64_t get_idt_base_offset(uint32_t fw) {
    switch (fw & 0xFFFF0000) {
    /* FW 3.xx */
    case 0x03000000: case 0x03100000:
    case 0x03200000: case 0x03210000:
        return 0x642dc80;
    /* FW 4.xx */
    case 0x04000000: case 0x04020000: case 0x04030000:
    case 0x04500000: case 0x04510000:
        return 0x64cdc80;
    /* FW 5.xx */
    case 0x05000000: case 0x05020000:
    case 0x05100000: case 0x05500000:
        return 0x658dc80;
    /* FW 6.xx */
    case 0x06000000: case 0x06020000: case 0x06500000:
        return 0x65ddc80;
    /* FW 7.xx */
    case 0x07000000: case 0x07010000:
    case 0x07200000: case 0x07400000:
        return 0x6601c80;
    /* FW 8.xx */
    case 0x08000000: case 0x08200000:
    case 0x08400000: case 0x08600000:
        return 0x6601c80;
    /* FW 9.xx */
    case 0x09000000: case 0x09200000:
    case 0x09400000: case 0x09600000:
        return 0x6601c80;
    /* FW 10.xx */
    case 0x0A000000: case 0x0A020000:
    case 0x0A060000:
        return 0x6601c80;
    default:
        return 0;
    }
}

static uint32_t get_fw_version(void) {
    uint32_t ver = 0;
    size_t sz = sizeof(ver);
    sysctlbyname("kern.sdk_version", &ver, &sz, NULL, 0);
    return ver;
}

/*
 * patch_idt_cfi_bypass - Copy IDT[1] (#DB) gate to IDT[6] (#UD)
 *
 * Returns:
 *   0  = success
 *  -1  = firmware not supported (unknown IDT offset)
 *  -2  = IDT[1] handler is NULL (kstuff not loaded yet)
 *  -3  = verification failed after write
 */
int patch_idt_cfi_bypass(void) {
    uint32_t fw = get_fw_version();
    uint64_t idt_offset = get_idt_base_offset(fw);
    if (!idt_offset)
        return -1;

    /* KERNEL_ADDRESS_DATA_BASE = 0xffffffff83000000 on all known FW */
    uint64_t kdata = 0xffffffff83000000ULL;
    uint64_t idt_base = kdata + idt_offset;

    /* Read IDT[1] (#DB) - this is kstuff's handler on IST7 */
    struct idt_gate db_gate;
    kernel_copyout(idt_base + IDT_VECTOR_DB * IDT_ENTRY_SIZE,
                   &db_gate, sizeof(db_gate));

    uint64_t handler = idt_handler_addr(&db_gate);
    if (!handler || handler < 0xffff800000000000ULL)
        return -2;  /* kstuff handler not installed */

    /* Read current IDT[6] (#UD) for logging */
    struct idt_gate ud_gate_before;
    kernel_copyout(idt_base + IDT_VECTOR_UD * IDT_ENTRY_SIZE,
                   &ud_gate_before, sizeof(ud_gate_before));

    printf("[CFI] IDT[1] handler: 0x%lx (IST=%d)\n",
           handler, db_gate.ist & 7);
    printf("[CFI] IDT[6] handler before: 0x%lx (IST=%d)\n",
           idt_handler_addr(&ud_gate_before), ud_gate_before.ist & 7);

    /* Write IDT[1]'s gate to IDT[6] */
    kernel_copyin(&db_gate,
                  idt_base + IDT_VECTOR_UD * IDT_ENTRY_SIZE,
                  sizeof(db_gate));

    /* Verify the write */
    struct idt_gate ud_gate_after;
    kernel_copyout(idt_base + IDT_VECTOR_UD * IDT_ENTRY_SIZE,
                   &ud_gate_after, sizeof(ud_gate_after));

    uint64_t new_handler = idt_handler_addr(&ud_gate_after);
    printf("[CFI] IDT[6] handler after: 0x%lx (IST=%d)\n",
           new_handler, ud_gate_after.ist & 7);

    if (new_handler != handler)
        return -3;

    printf("[CFI] KCFI bypass active: UD2 -> kstuff handler -> RIP+=2 -> continue\n");
    return 0;
}

/*
 * unpatch_idt_cfi_bypass - Restore original IDT[6] handler
 *
 * Reads the original #UD handler from CPU 0's TSS or restores the
 * kernel's default handler. For safety, we save the original gate
 * in a static so we can restore it.
 *
 * In practice, etaHEN may not need this - the bypass stays active
 * for the lifetime of the session. But it's here for completeness.
 */
static struct idt_gate saved_original_ud;
static int original_saved = 0;

int save_original_idt6(void) {
    uint32_t fw = get_fw_version();
    uint64_t idt_offset = get_idt_base_offset(fw);
    if (!idt_offset) return -1;

    uint64_t kdata = 0xffffffff83000000ULL;
    uint64_t idt_base = kdata + idt_offset;

    kernel_copyout(idt_base + IDT_VECTOR_UD * IDT_ENTRY_SIZE,
                   &saved_original_ud, sizeof(saved_original_ud));
    original_saved = 1;
    return 0;
}

int unpatch_idt_cfi_bypass(void) {
    if (!original_saved) return -1;

    uint32_t fw = get_fw_version();
    uint64_t idt_offset = get_idt_base_offset(fw);
    if (!idt_offset) return -1;

    uint64_t kdata = 0xffffffff83000000ULL;
    uint64_t idt_base = kdata + idt_offset;

    kernel_copyin(&saved_original_ud,
                  idt_base + IDT_VECTOR_UD * IDT_ENTRY_SIZE,
                  sizeof(saved_original_ud));
    return 0;
}
