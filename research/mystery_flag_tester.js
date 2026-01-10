///////////////////////////////////////////////////////////////////////////////
// MYSTERY FLAG TESTER
// Tests the unknown flag at 0xD11D08 (between sysentvec_ps5 and sysentvec_ps4)
//
// From kernel dump analysis:
// 0x00D11D08: 01 00 00 00 FF FF FF 0F
//             ^^^^^^^^    ^^^^^^^^^^^
//             Flag = 1    Mask = 0x0FFFFFFF
//
// This could be a security-related flag given its location
///////////////////////////////////////////////////////////////////////////////

// Offset from kernel data base
const MYSTERY_FLAG_OFFSET = 0xD11D08;
const MYSTERY_MASK_OFFSET = 0xD11D0C;

// Other interesting flags found between sysentvec structures
const INTER_SYSENTVEC_FLAGS = [
    { off: 0xD11CD8, name: "flag_1", expected: 0x01 },
    { off: 0xD11CDC, name: "flag_2", expected: 0x01 },
    { off: 0xD11CE8, name: "flag_3", expected: 0x01 },  // After a pointer
    { off: 0xD11CEC, name: "value_1", expected: 0x02 },
    { off: 0xD11D08, name: "mystery_flag", expected: 0x01 },
    { off: 0xD11D0C, name: "mystery_mask", expected: 0x0FFFFFFF },
];

async function testMysteryFlags(krw, log, LogLevel) {
    await log("[MYSTERY] Starting mystery flag analysis...", LogLevel.INFO);
    await log("[MYSTERY] kdataBase = 0x" + krw.kdataBase, LogLevel.INFO);

    await log("\n[MYSTERY] Reading flags between sysentvec_ps5 and sysentvec_ps4:", LogLevel.INFO);
    await log("─".repeat(60), LogLevel.INFO);

    for (const f of INTER_SYSENTVEC_FLAGS) {
        const addr = krw.kdataBase.add32(f.off);
        try {
            const val = await krw.read8(addr);
            const valLow = val.low >>> 0;  // Ensure unsigned

            const match = valLow === f.expected ? "✓" : "≠";
            await log(`  0x${f.off.toString(16)}: ${f.name.padEnd(15)} = 0x${valLow.toString(16).padStart(8,'0')} (expected 0x${f.expected.toString(16)}) ${match}`, LogLevel.INFO);
        } catch (e) {
            await log(`  0x${f.off.toString(16)}: ${f.name} - READ FAILED: ${e}`, LogLevel.ERROR);
        }
    }

    // Show context around mystery flag
    await log("\n[MYSTERY] Memory context around 0xD11D08:", LogLevel.INFO);
    for (let off = 0xD11D00; off < 0xD11D20; off += 8) {
        const addr = krw.kdataBase.add32(off);
        const val = await krw.read8(addr);
        await log(`  0x${off.toString(16)}: 0x${val.hi.toString(16).padStart(8,'0')}${val.low.toString(16).padStart(8,'0')}`, LogLevel.INFO);
    }

    // Ask user if they want to test modifying the mystery flag
    const test = confirm(
        "MYSTERY FLAG TEST\n\n" +
        "Found flag at offset 0xD11D08 = 1\n" +
        "This is between sysentvec_ps5 and sysentvec_ps4\n\n" +
        "Want to try setting it to 0?\n\n" +
        "This is a DATA field (not function pointer)\n" +
        "CFI should NOT block this write.\n\n" +
        "If crash = This flag is protected somehow\n" +
        "If no crash = We can toggle this flag!\n\n" +
        "Proceed?"
    );

    if (test) {
        const flagAddr = krw.kdataBase.add32(MYSTERY_FLAG_OFFSET);
        const original = await krw.read8(flagAddr);

        await log("[MYSTERY] Writing 0 to mystery flag...", LogLevel.WARN);

        // Write 0 to the flag (preserve the mask in upper bytes if same qword)
        await krw.write8(flagAddr, new int64(0, original.hi));

        // Verify
        const verify = await krw.read8(flagAddr);
        await log("[MYSTERY] After write: 0x" + verify.low.toString(16), LogLevel.INFO);

        if (verify.low === 0) {
            await log("[MYSTERY] SUCCESS! Flag was modified!", LogLevel.SUCCESS);

            // Restore
            await krw.write8(flagAddr, original);
            await log("[MYSTERY] Restored original value", LogLevel.INFO);

            alert(
                "SUCCESS!\n\n" +
                "The mystery flag at 0xD11D08 is WRITABLE!\n\n" +
                "Next: Test what happens when this flag is 0\n" +
                "(might need to test with suspend/resume)"
            );
        }
    }
}

// Export for use
// Add to main.js: await testMysteryFlags(krw, log, LogLevel);
