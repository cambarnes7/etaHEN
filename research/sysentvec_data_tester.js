///////////////////////////////////////////////////////////////////////////////
// SYSENTVEC DATA-ONLY FIELD TESTER
// Tests modifying non-function-pointer fields in sysentvec structure
// These should NOT trigger CFI since they're scalar data, not function pointers
//
// Based on analysis of kernel_data.bin dump from FW 4.03
///////////////////////////////////////////////////////////////////////////////

// Sysentvec offsets for FW 4.03
const SYSENTVEC_OFFSET = 0xd11bb8;      // PS5 sysentvec
const SYSENTVEC_PS4_OFFSET = 0xd11d30;  // PS4 compat sysentvec

// Non-function-pointer fields we can safely test
// These are DATA fields, not function pointers - CFI should NOT block these
const DATA_FIELDS = [
    // Field offset, size, name, description, test_value
    { off: 0x00, size: 4, name: "sv_size", desc: "Number of syscalls (0x2D4)", test: 0x2D5 },
    { off: 0x10, size: 4, name: "sv_mask", desc: "Signal mask (0)", test: 0xFFFFFFFF },
    { off: 0x14, size: 2, name: "sv_sigsize", desc: "KSTUFF TARGET (0->0xFFFF)", test: 0xFFFF },
    { off: 0x20, size: 4, name: "sv_errsize", desc: "Error table size (0)", test: 0x100 },
    { off: 0x78, size: 4, name: "sv_minsigstksz", desc: "Min signal stack (3)", test: 0x1000 },
    { off: 0xA0, size: 4, name: "sv_psstrings", desc: "PS strings (0x10209)", test: 0 },
    { off: 0xF8, size: 4, name: "unknown_flag", desc: "Mystery flag (1)", test: 0 },
    { off: 0xFC, size: 4, name: "unknown_mask", desc: "Mystery mask (0x0FFFFFFF)", test: 0 },
];

// Test index - change this to test different fields
// null = read-only mode (safe)
// 0-7 = test that specific field (WILL MODIFY KERNEL DATA)
const TEST_INDEX = null;

async function runSysentvecDataTest(krw, log, LogLevel) {
    await log("[SYSENT DATA] Starting sysentvec data field tests...", LogLevel.INFO);
    await log("[SYSENT DATA] kdataBase = 0x" + krw.kdataBase, LogLevel.INFO);

    const sysentvec = krw.kdataBase.add32(SYSENTVEC_OFFSET);
    await log("[SYSENT DATA] sysentvec @ 0x" + sysentvec, LogLevel.INFO);

    // Read all data fields first
    await log("\n[SYSENT DATA] Reading non-pointer fields:", LogLevel.INFO);
    await log("─".repeat(60), LogLevel.INFO);

    for (let i = 0; i < DATA_FIELDS.length; i++) {
        const f = DATA_FIELDS[i];
        const addr = sysentvec.add32(f.off);

        try {
            let val;
            if (f.size === 2) {
                // Read as 8 bytes, extract low 16 bits
                const full = await krw.read8(addr);
                val = full.low & 0xFFFF;
            } else if (f.size === 4) {
                const full = await krw.read8(addr);
                val = full.low;
            } else {
                const full = await krw.read8(addr);
                val = full;
            }

            const valStr = (typeof val === 'object') ?
                `0x${val.hi.toString(16)}${val.low.toString(16).padStart(8,'0')}` :
                `0x${val.toString(16).toUpperCase()}`;

            await log(`[${i}] +0x${f.off.toString(16).padStart(2,'0')}: ${f.name.padEnd(18)} = ${valStr}`, LogLevel.INFO);
            await log(`     ${f.desc}`, LogLevel.INFO);
        } catch (e) {
            await log(`[${i}] +0x${f.off.toString(16)}: ${f.name} - READ FAILED: ${e}`, LogLevel.ERROR);
        }
    }

    // If TEST_INDEX is set, try modifying that field
    if (TEST_INDEX !== null && TEST_INDEX < DATA_FIELDS.length) {
        const f = DATA_FIELDS[TEST_INDEX];
        const addr = sysentvec.add32(f.off);

        await log("\n" + "=".repeat(60), LogLevel.WARN);
        await log("[SYSENT DATA] WRITE TEST MODE", LogLevel.WARN);
        await log("=".repeat(60), LogLevel.WARN);

        // Read original value
        let original;
        if (f.size === 2) {
            const full = await krw.read8(addr);
            original = full.low & 0xFFFF;
        } else if (f.size === 4) {
            const full = await krw.read8(addr);
            original = full.low;
        }

        const proceed = confirm(
            `DATA FIELD WRITE TEST\n\n` +
            `Field: ${f.name}\n` +
            `Offset: +0x${f.off.toString(16)}\n` +
            `Address: 0x${addr}\n` +
            `Current: 0x${original.toString(16)}\n` +
            `New value: 0x${f.test.toString(16)}\n\n` +
            `This modifies DATA (not function pointer).\n` +
            `CFI should NOT block this!\n\n` +
            `If PS5 crashes = Something else protects this\n` +
            `If NO crash = We can modify this field!\n\n` +
            `Proceed?`
        );

        if (proceed) {
            await log(`[SYSENT DATA] Writing 0x${f.test.toString(16)} to ${f.name}...`, LogLevel.WARN);

            // Write new value (need to preserve other bytes in the 8-byte write)
            const fullOrig = await krw.read8(addr);
            let newVal;

            if (f.size === 2) {
                // Replace low 16 bits
                newVal = new int64((fullOrig.low & 0xFFFF0000) | (f.test & 0xFFFF), fullOrig.hi);
            } else if (f.size === 4) {
                // Replace low 32 bits
                newVal = new int64(f.test, fullOrig.hi);
            }

            await krw.write8(addr, newVal);

            // Verify
            const verify = await krw.read8(addr);
            const verifyVal = (f.size === 2) ? (verify.low & 0xFFFF) : verify.low;

            if (verifyVal === f.test) {
                await log(`[SYSENT DATA] SUCCESS! Field modified without crash!`, LogLevel.SUCCESS);
                await log(`[SYSENT DATA] ${f.name} is WRITABLE!`, LogLevel.SUCCESS);

                // Restore original
                await krw.write8(addr, fullOrig);
                await log(`[SYSENT DATA] Restored original value`, LogLevel.INFO);

                alert(
                    `SUCCESS!\n\n` +
                    `${f.name} at offset +0x${f.off.toString(16)} is WRITABLE!\n\n` +
                    `This data field can be modified without CFI crash.\n` +
                    `Original value has been restored.`
                );
            } else {
                await log(`[SYSENT DATA] Write may have failed. Read back: 0x${verifyVal.toString(16)}`, LogLevel.WARN);
            }
        }
    } else if (TEST_INDEX !== null) {
        await log(`[SYSENT DATA] Invalid TEST_INDEX: ${TEST_INDEX}`, LogLevel.ERROR);
    } else {
        await log("\n[SYSENT DATA] Read-only mode. Set TEST_INDEX to 0-7 to test a field.", LogLevel.INFO);
        await log("[SYSENT DATA] Recommended: Start with index 2 (sv_sigsize) - this is what kstuff uses!", LogLevel.INFO);
    }
}

// Export for use in main.js
// Add to main.js after kernel R/W is established:
//   await runSysentvecDataTest(krw, log, LogLevel);
