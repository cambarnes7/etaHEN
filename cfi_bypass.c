/*
 * cfi_bypass.c - KCFI (Kernel Control Flow Integrity) Bypass for PS5
 *
 * Multi-strategy approach to bypassing LLVM KCFI in the PS5 kernel.
 *
 * === How KCFI works on PS5 ===
 *
 * The PS5 kernel uses LLVM's Kernel CFI (KCFI) to protect indirect calls.
 * At each indirect call site, the compiler inserts:
 *
 *     mov eax, <expected_type_hash>
 *     sub eax, dword ptr [target - 4]   ; compare with hash before function
 *     je  .Lok                           ; match -> proceed
 *     ud2                                ; mismatch -> trap (0F 0B, 2 bytes)
 *   .Lok:
 *     call target
 *
 * When the hash check fails, UD2 triggers CPU exception 6 (Invalid Opcode).
 * The kernel's default INT6 handler calls cfi_check_fail() which panics.
 *
 * === Strategy 1: Patch cfi_check_fail() directly ===
 *
 * The simplest bypass: overwrite cfi_check_fail() with a RET instruction.
 * This is the proven approach used by Byepervisor on FW < 3.00, where
 * kernel text is made writable via page table manipulation (clear XOTEXT,
 * set RW on all kernel text PTEs).
 *
 * On FW >= 3.00, kernel text is protected by the hypervisor. After kstuff
 * loads, we attempt this anyway - kstuff modifies the hypervisor and may
 * have relaxed the XOM restriction enough for kernel_copyin to succeed.
 *
 * === Strategy 2: Redirect IDT[6] through kstuff's INT1 handler ===
 *
 * Patch IDT[6] to reuse kstuff's INT1 handler and IST7. This routes UD2
 * exceptions through kstuff's uelf handler. Requires the uelf to advance
 * RIP by 2 for unrecognized addresses (see kstuff modification notes).
 *
 * Even without the uelf modification, this converts kernel panics into
 * handler returns (the system stays alive instead of crashing).
 *
 * INT6 and INT1 can safely share IST7 because both are synchronous
 * exceptions that can't be pending simultaneously with interrupts disabled.
 *
 * === Build ===
 *
 *   /opt/ps5-payload-sdk/bin/prospero-clang cfi_bypass.c -o cfi_bypass.elf -lps5api
 *
 * === Usage ===
 *
 * Load this payload AFTER kstuff has been loaded by etaHEN (FW >= 3.00).
 * On FW < 3.00, load after Byepervisor has run.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <ps5/payload.h>
#include <ps5/kernel.h>

#define IDT_ENTRY_SIZE  16
#define INT_DEBUG       1   /* #DB - Debug Exception */
#define INT_INVOPCODE   6   /* #UD - Invalid Opcode (UD2) */

/* x86_64 IDT Gate Descriptor (16 bytes) */
struct idt_gate {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed));

static uint32_t get_fw_version(void) {
    uint32_t version = 0;
    size_t size = sizeof(version);
    sysctlbyname("kern.sdk_version", &version, &size, NULL, 0);
    return version;
}

/*
 * cfi_check_fail() offsets from kernel text base.
 * Sourced from Byepervisor patch tables (FW 1.00 - 2.70).
 */
static uint64_t get_cfi_check_fail_offset(uint32_t fw_version) {
    switch (fw_version & 0xFFFF0000) {
    /* FW 1.00 - 1.02 */
    case 0x01000000: case 0x01010000: case 0x01020000:
        return 0x4587e0;
    /* FW 1.05 */
    case 0x01050000:
        return 0x458c10;
    /* FW 1.10 */
    case 0x01100000:
        return 0x458C50;
    /* FW 1.11 */
    case 0x01110000:
        return 0x458D10;
    /* FW 1.12 - 1.14 */
    case 0x01120000: case 0x01130000: case 0x01140000:
        return 0x458D70;
    /* FW 2.00 */
    case 0x02000000:
        return 0x41FC60;
    /* FW 2.20, 2.25, 2.26 */
    case 0x02200000: case 0x02250000: case 0x02260000:
        return 0x41FCB0;
    /* FW 2.30 */
    case 0x02300000:
        return 0x41FB70;
    /* FW 2.50, 2.70 */
    case 0x02500000: case 0x02700000:
        return 0x41FCA0;
    default:
        return 0; /* Unknown - will attempt scan */
    }
}

/*
 * IDT base offsets from KERNEL_ADDRESS_DATA_BASE.
 * Sourced from kstuff prosper0gdb/offsets.c.
 */
static uint64_t get_idt_base(uint32_t fw_version) {
    uint64_t kdata = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
    switch (fw_version & 0xFFFF0000) {
    /* FW 3.xx */
    case 0x03000000: case 0x03100000:
    case 0x03200000: case 0x03210000:
        return kdata + 0x642dc80;
    /* FW 4.xx */
    case 0x04000000: case 0x04020000: case 0x04030000:
    case 0x04500000: case 0x04510000:
        return kdata + 0x64cdc80;
    /* FW 5.xx */
    case 0x05000000: case 0x05020000:
    case 0x05100000: case 0x05500000:
        return kdata + 0x660dca0;
    /* FW 6.xx */
    case 0x06000000: case 0x06020000: case 0x06500000:
        return kdata + 0x655dde0;
    /* FW 7.xx */
    case 0x07000000: case 0x07010000: case 0x07200000:
    case 0x07400000: case 0x07600000: case 0x07610000:
        return kdata + 0x2E7FDF0;
    /* FW 8.xx */
    case 0x08000000: case 0x08200000:
    case 0x08400000: case 0x08600000:
        return kdata + 0x2eb3df0;
    /* FW 9.xx */
    case 0x09000000: case 0x09050000: case 0x09200000:
    case 0x09400000: case 0x09600000:
        return kdata + 0x2d94300;
    /* FW 10.xx */
    case 0x10000000: case 0x10010000: case 0x10200000:
    case 0x10400000: case 0x10600000:
        return kdata + 0x2d5c300;
    default:
        return 0;
    }
}

/*
 * Strategy 1: Patch cfi_check_fail() to RET.
 *
 * On FW < 3.00, Byepervisor has already cleared XOM and set RW on kernel
 * text pages, so kernel_copyin to text addresses works directly.
 *
 * On FW >= 3.00, kernel text may or may not be writable depending on what
 * kstuff has done to the hypervisor. We attempt the write and verify.
 *
 * Returns 1 on success, 0 on failure.
 */
static int try_patch_cfi_check_fail(uint32_t fw_version) {
    uint64_t offset = get_cfi_check_fail_offset(fw_version);
    if (offset == 0) {
        printf("[cfi] Strategy 1: No cfi_check_fail offset for FW 0x%08x\n",
               fw_version);
        return 0;
    }

    uint64_t ktext_base = (uint64_t)KERNEL_ADDRESS_DATA_BASE -
                          ((uint64_t)KERNEL_ADDRESS_DATA_BASE -
                           (uint64_t)KERNEL_ADDRESS_TEXT_BASE);
    uint64_t target = ktext_base + offset;

    printf("[cfi] Strategy 1: Patching cfi_check_fail() at 0x%lx\n",
           (unsigned long)target);

    /* Read current byte to verify we can access kernel text */
    uint8_t original;
    if (kernel_copyout(target, &original, 1) != 0) {
        printf("[cfi] Strategy 1: Cannot read kernel text (XOM active)\n");
        return 0;
    }

    printf("[cfi] Strategy 1: Current byte at cfi_check_fail: 0x%02x\n",
           original);

    /* Already patched? */
    if (original == 0xC3) {
        printf("[cfi] Strategy 1: Already patched (RET)\n");
        return 1;
    }

    /* Write RET (0xC3) to cfi_check_fail() */
    uint8_t ret_opcode = 0xC3;
    if (kernel_copyin(&ret_opcode, target, 1) != 0) {
        printf("[cfi] Strategy 1: kernel_copyin failed (text not writable)\n");
        return 0;
    }

    /* Verify */
    uint8_t verify;
    if (kernel_copyout(target, &verify, 1) != 0 || verify != 0xC3) {
        printf("[cfi] Strategy 1: Verification failed (read=0x%02x)\n", verify);
        return 0;
    }

    printf("[cfi] Strategy 1: SUCCESS - cfi_check_fail() patched to RET\n");
    return 1;
}

/*
 * Strategy 2: Redirect IDT[6] through kstuff's INT1 handler.
 *
 * Patches IDT[6] to share INT1's handler address and IST7 stack.
 * This routes UD2 exceptions through kstuff's register-save ROP chain
 * and into the uelf C handler.
 *
 * Returns 1 on success, 0 on failure.
 */
static int try_idt_redirect(uint32_t fw_version) {
    uint64_t idt_base = get_idt_base(fw_version);
    if (idt_base == 0) {
        printf("[cfi] Strategy 2: No IDT offset for FW 0x%08x\n", fw_version);
        return 0;
    }

    printf("[cfi] Strategy 2: IDT base = 0x%lx\n", (unsigned long)idt_base);

    /* Read IDT[1] (INT1 = Debug Exception, installed by kstuff) */
    struct idt_gate int1_gate, int6_gate;

    if (kernel_copyout(idt_base + IDT_ENTRY_SIZE * INT_DEBUG,
                       &int1_gate, sizeof(int1_gate)) != 0) {
        printf("[cfi] Strategy 2: Failed to read IDT[1]\n");
        return 0;
    }

    kernel_copyout(idt_base + IDT_ENTRY_SIZE * INT_INVOPCODE,
                   &int6_gate, sizeof(int6_gate));

    uint64_t int1_handler = (uint64_t)int1_gate.offset_low |
                            ((uint64_t)int1_gate.offset_mid << 16) |
                            ((uint64_t)int1_gate.offset_high << 32);
    uint64_t int6_handler = (uint64_t)int6_gate.offset_low |
                            ((uint64_t)int6_gate.offset_mid << 16) |
                            ((uint64_t)int6_gate.offset_high << 32);

    printf("[cfi] IDT[1]: handler=0x%lx IST=%d type=0x%02x\n",
           (unsigned long)int1_handler, int1_gate.ist & 7, int1_gate.type_attr);
    printf("[cfi] IDT[6]: handler=0x%lx IST=%d type=0x%02x\n",
           (unsigned long)int6_handler, int6_gate.ist & 7, int6_gate.type_attr);

    /* Verify kstuff's INT1 is set up with IST7 */
    if ((int1_gate.ist & 7) != 7) {
        printf("[cfi] Strategy 2: IDT[1] IST=%d, expected 7 (kstuff not loaded?)\n",
               int1_gate.ist & 7);
        return 0;
    }

    if (int1_handler == 0 || int1_gate.type_attr == 0) {
        printf("[cfi] Strategy 2: IDT[1] appears invalid\n");
        return 0;
    }

    /* Already patched? */
    if (int6_handler == int1_handler && (int6_gate.ist & 7) == 7) {
        printf("[cfi] Strategy 2: IDT[6] already redirected\n");
        return 1;
    }

    /* Build new IDT[6] entry: copy INT1, ensure interrupt gate + IST7 */
    struct idt_gate new_int6 = int1_gate;
    new_int6.type_attr = 0x8E; /* P=1, DPL=0, Interrupt Gate */
    new_int6.ist = 7;          /* IST7 */

    printf("[cfi] Strategy 2: Writing IDT[6] -> handler=0x%lx IST=7\n",
           (unsigned long)int1_handler);

    if (kernel_copyin(&new_int6, idt_base + IDT_ENTRY_SIZE * INT_INVOPCODE,
                      sizeof(new_int6)) != 0) {
        printf("[cfi] Strategy 2: Failed to write IDT[6]\n");
        return 0;
    }

    /* Verify */
    struct idt_gate verify;
    kernel_copyout(idt_base + IDT_ENTRY_SIZE * INT_INVOPCODE,
                   &verify, sizeof(verify));

    uint64_t v_handler = (uint64_t)verify.offset_low |
                         ((uint64_t)verify.offset_mid << 16) |
                         ((uint64_t)verify.offset_high << 32);

    if (v_handler != int1_handler || (verify.ist & 7) != 7) {
        printf("[cfi] Strategy 2: Verification failed (handler=0x%lx IST=%d)\n",
               (unsigned long)v_handler, verify.ist & 7);
        return 0;
    }

    printf("[cfi] Strategy 2: SUCCESS - IDT[6] redirected through kstuff\n");
    return 1;
}

int main(void) {
    uint32_t fw = get_fw_version();
    int result = 0;

    printf("[cfi] PS5 KCFI Bypass - FW 0x%08x\n", fw);

    /*
     * Strategy 1: Direct cfi_check_fail() patch.
     * Works on FW < 3.00 (Byepervisor has made text writable).
     * Attempted on FW >= 3.00 (may work post-kstuff).
     */
    if (try_patch_cfi_check_fail(fw)) {
        printf("[cfi] KCFI bypass active via cfi_check_fail() patch\n");
        result = 1;
    }

    /*
     * Strategy 2: IDT redirect (FW >= 3.00 with kstuff).
     * Apply this as a complementary layer even if Strategy 1 succeeded.
     * On FW < 3.00, kstuff isn't loaded so this will be skipped.
     */
    if (fw >= 0x03000000) {
        if (try_idt_redirect(fw)) {
            printf("[cfi] IDT[6] redirect active (kstuff INT1 handler)\n");
            if (!result) {
                printf("[cfi] NOTE: For full bypass via IDT, kstuff uelf needs\n");
                printf("[cfi]       handle() fallthrough: regs[RIP] += 2\n");
            }
            result = 1;
        }
    }

    if (!result) {
        printf("[cfi] WARNING: No CFI bypass strategy succeeded\n");
        return 1;
    }

    return 0;
}
