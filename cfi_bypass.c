/*
 * cfi_bypass.c - KCFI Bypass for PS5 (standalone payload)
 *
 * Redirects IDT[6] (Invalid Opcode) through kstuff's INT1 handler on IST7.
 * This causes UD2 exceptions from KCFI hash mismatches to be handled by
 * kstuff instead of triggering cfi_check_fail() and a kernel panic.
 *
 * === How KCFI works on PS5 ===
 *
 * The PS5 kernel uses LLVM's KCFI to protect indirect calls:
 *
 *     mov eax, <expected_type_hash>
 *     sub eax, dword ptr [target - 4]   ; compare with hash before function
 *     je  .Lok                           ; match -> proceed
 *     ud2                                ; mismatch -> INT6 (0F 0B, 2 bytes)
 *   .Lok:
 *     call target
 *
 * === Why the IDT redirect works ===
 *
 * Verified by disassembly of the kstuff payload binary (payload_bin.c):
 *
 * The handler at payload offset 0x276d0 processes ring 0 (kernel) faults
 * through a chain of table lookups. For an unrecognized address (like a
 * KCFI UD2 site), the flow is:
 *
 *   0x27930: Search breakpoint table - no match
 *   0x279c0: Check special addresses - no match
 *   0x279dd: Call 0x273d0 (address validator) - returns 0
 *   0x279ed: Call 0x266c0 (dispatch table) - returns 0
 *   0x27c5e: Call 0x25920, 0x28b20, 0x29510 - all return 0
 *   0x27c8e: Check registers for 0xDEB7 signature - no match
 *   0x27d3a: test eax,eax - eax is 0 (preserved from handler returns)
 *   0x27d42: add qword [rbx+0xe8], 2 - regs[RIP] += 2 (skip UD2)
 *   0x27d4a: jmp 0x27797 - return, kernel continues after UD2
 *
 * INT1 and INT6 share the same stack frame (no error code for either)
 * and can safely share IST7 since both are synchronous exceptions.
 *
 * === Build ===
 *
 *   prospero-clang cfi_bypass.c -o cfi_bypass.elf -lps5api
 *
 * === Usage ===
 *
 * Load AFTER kstuff has been loaded by etaHEN (FW >= 3.00).
 * etaHEN's bootstrapper already applies this patch automatically;
 * this standalone payload is for manual application or debugging.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>

#include <ps5/payload.h>
#include <ps5/kernel.h>

#define IDT_ENTRY_SIZE 16

static uint32_t get_fw_version(void) {
    uint32_t version = 0;
    size_t size = sizeof(version);
    sysctlbyname("kern.sdk_version", &version, &size, NULL, 0);
    return version;
}

/* IDT base offsets from KERNEL_ADDRESS_DATA_BASE (from kstuff offsets.c) */
static uint64_t get_idt_base(uint32_t fw_version) {
    uint64_t kdata = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
    switch (fw_version & 0xFFFF0000) {
    case 0x03000000: case 0x03100000:
    case 0x03200000: case 0x03210000:
        return kdata + 0x642dc80;
    case 0x04000000: case 0x04020000: case 0x04030000:
    case 0x04500000: case 0x04510000:
        return kdata + 0x64cdc80;
    case 0x05000000: case 0x05020000:
    case 0x05100000: case 0x05500000:
        return kdata + 0x660dca0;
    case 0x06000000: case 0x06020000: case 0x06500000:
        return kdata + 0x655dde0;
    case 0x07000000: case 0x07010000: case 0x07200000:
    case 0x07400000: case 0x07600000: case 0x07610000:
        return kdata + 0x2E7FDF0;
    case 0x08000000: case 0x08200000:
    case 0x08400000: case 0x08600000:
        return kdata + 0x2eb3df0;
    case 0x09000000: case 0x09050000: case 0x09200000:
    case 0x09400000: case 0x09600000:
        return kdata + 0x2d94300;
    case 0x10000000: case 0x10010000: case 0x10200000:
    case 0x10400000: case 0x10600000:
        return kdata + 0x2d5c300;
    default:
        return 0;
    }
}

int main(void) {
    uint32_t fw = get_fw_version();

    printf("[cfi] PS5 KCFI Bypass - FW 0x%08x\n", fw);

    if (fw < 0x03000000) {
        printf("[cfi] FW < 3.00: use Byepervisor cfi_check_fail() patch instead\n");
        return 1;
    }

    uint64_t idt_base = get_idt_base(fw);
    if (idt_base == 0) {
        printf("[cfi] No IDT offset for FW 0x%08x\n", fw);
        return 1;
    }

    printf("[cfi] IDT base = 0x%lx\n", (unsigned long)idt_base);

    /* Read IDT[1] (kstuff's INT1 handler with IST7) */
    uint8_t int1_entry[IDT_ENTRY_SIZE];
    if (kernel_copyout(idt_base + IDT_ENTRY_SIZE * 1, int1_entry, IDT_ENTRY_SIZE) != 0) {
        printf("[cfi] Failed to read IDT[1]\n");
        return 1;
    }

    /* Verify kstuff installed its handler with IST7 */
    uint8_t ist = int1_entry[4] & 7;
    if (ist != 7) {
        printf("[cfi] IDT[1] IST=%d, expected 7 (kstuff not loaded?)\n", ist);
        return 1;
    }

    /* Decode handler address for diagnostic output */
    uint64_t handler = (uint64_t)*(uint16_t *)&int1_entry[0] |
                       ((uint64_t)*(uint16_t *)&int1_entry[6] << 16) |
                       ((uint64_t)*(uint32_t *)&int1_entry[8] << 32);
    printf("[cfi] IDT[1]: handler=0x%lx IST=7 type=0x%02x\n",
           (unsigned long)handler, int1_entry[5]);

    /* Check if already patched */
    uint8_t int6_entry[IDT_ENTRY_SIZE];
    kernel_copyout(idt_base + IDT_ENTRY_SIZE * 6, int6_entry, IDT_ENTRY_SIZE);
    if (memcmp(int1_entry, int6_entry, IDT_ENTRY_SIZE) == 0) {
        printf("[cfi] IDT[6] already redirected to kstuff\n");
        return 0;
    }

    /* Copy IDT[1] to IDT[6] */
    if (kernel_copyin(int1_entry, idt_base + IDT_ENTRY_SIZE * 6, IDT_ENTRY_SIZE) != 0) {
        printf("[cfi] Failed to write IDT[6]\n");
        return 1;
    }

    /* Verify */
    uint8_t verify[IDT_ENTRY_SIZE];
    kernel_copyout(idt_base + IDT_ENTRY_SIZE * 6, verify, IDT_ENTRY_SIZE);
    if (memcmp(int1_entry, verify, IDT_ENTRY_SIZE) != 0) {
        printf("[cfi] IDT[6] write verification failed\n");
        return 1;
    }

    printf("[cfi] KCFI bypass active: IDT[6] -> kstuff INT1 handler (IST7)\n");
    printf("[cfi] UD2 exceptions will advance RIP by 2 and continue\n");
    return 0;
}
