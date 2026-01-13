/**
 * PS2 Emulator Memory Finder for mast1c0re
 *
 * This script uses kernel R/W primitives to:
 * 1. Find the ps2emu process in the kernel's process list
 * 2. Dump its memory mappings
 * 3. Search for critical addresses needed for emulator escape:
 *    - N status buffer (was 0x897810 in Okage - ASLR disabled offset)
 *    - S status buffer (was 0x897820 in Okage - 16 bytes after N)
 *    - IOP RAM pointer (was 0xAF6E38 in Okage)
 *
 * Key mast1c0re emulator layout (from CTurt's research):
 * - 0x897810: N status buffer (16-bytes)
 * - 0x897820: S status buffer (16-bytes)
 * - 0x897890: N status index (4-bytes)
 * - 0x8978A0: S status index (4-bytes)
 * - 0xAF6E38: IOP RAM pointer (normally points to 0x9000000000)
 *
 * PS5 uses ASLR, so these are relative offsets from eboot base.
 * The offset from N_STATUS_BUFFER to IOP_RAM_POINTER is:
 *   0xAF6E38 - 0x897810 = 0x25F628 (about 2.4MB)
 *
 * To use: Add this code to main.js after the exploit returns kernel primitives
 */

// Process structure offsets (FreeBSD kernel)
const PROC_P_LIST_NEXT = 0x0;      // LIST_ENTRY(proc) p_list
const PROC_P_LIST_PREV = 0x8;
const PROC_P_VMSPACE = 0x200;      // struct vmspace *p_vmspace
const PROC_P_COMM = 0x470;         // char p_comm[MAXCOMLEN+1] (process name)
const PROC_P_PID = 0xC4;           // pid_t p_pid

// VM map entry structure offsets
const VM_MAP_ENTRY_NEXT = 0x8;     // RB_ENTRY(vm_map_entry) next
const VM_MAP_ENTRY_START = 0x20;   // vm_offset_t start
const VM_MAP_ENTRY_END = 0x28;     // vm_offset_t end
const VM_MAP_ENTRY_OFFSET = 0x50;  // vm_ooffset_t offset
const VM_MAP_ENTRY_PROTECTION = 0x60; // vm_prot_t protection
const VM_MAP_ENTRY_EFLAGS = 0x44;  // int eflags

// vmspace structure offsets
// On PS5, vm_map has an sx lock (~0x50 bytes) before the header entry
// vmspace offset 0 = vm_map, vm_map offset 0x50 = header entry
const VM_MAP_HEADER_OFFSET = 0x50;

// Protection flags
const VM_PROT_READ = 0x1;
const VM_PROT_WRITE = 0x2;
const VM_PROT_EXECUTE = 0x4;

/**
 * Read a null-terminated string from kernel memory
 */
async function kreadString(k, addr, maxLen = 32) {
    let str = "";
    for (let i = 0; i < maxLen; i++) {
        const byte = await k.read1(addr.add32(i));
        if (byte === 0) break;
        str += String.fromCharCode(byte);
    }
    return str;
}

/**
 * Find a process by name in the kernel's allproc list
 * Returns the proc structure address or null if not found
 */
async function findProcessByName(k, allprocAddr, targetName) {
    log(`Searching for process: ${targetName}`, LogLevel.INFO);

    let proc = await k.read8(allprocAddr);
    let found = [];

    for (let i = 0; i < 500; i++) {
        if (proc.low === 0 && proc.hi === 0) break;

        try {
            const name = await kreadString(k, proc.add32(PROC_P_COMM));
            const pid = await k.read4(proc.add32(PROC_P_PID));

            if (name.toLowerCase().includes(targetName.toLowerCase())) {
                log(`Found: ${name} (PID: ${pid}) @ ${proc.toString()}`, LogLevel.SUCCESS);
                found.push({ proc, name, pid });
            }

            // Move to next process
            proc = await k.read8(proc.add32(PROC_P_LIST_NEXT));
        } catch (e) {
            log(`Error reading proc at ${proc.toString()}: ${e}`, LogLevel.WARN);
            break;
        }
    }

    return found;
}

/**
 * Dump all memory mappings for a process
 */
async function dumpProcessMemoryMap(k, procAddr) {
    const vmspace = await k.read8(procAddr.add32(PROC_P_VMSPACE));
    log(`vmspace @ ${vmspace.toString()}`, LogLevel.INFO);

    // Get the vm_map header (after the sx lock in vm_map structure)
    const mapHeader = vmspace.add32(VM_MAP_HEADER_OFFSET);
    log(`mapHeader @ ${mapHeader.toString()}`, LogLevel.DEBUG);
    const firstEntry = await k.read8(mapHeader.add32(VM_MAP_ENTRY_NEXT));
    log(`firstEntry @ ${firstEntry.toString()}`, LogLevel.DEBUG);

    let entry = firstEntry;
    let mappings = [];

    for (let i = 0; i < 1000; i++) {
        if (entry.low === 0 && entry.hi === 0) break;
        if (entry.eq(mapHeader)) break; // Circular list - we're back at header

        try {
            const start = await k.read8(entry.add32(VM_MAP_ENTRY_START));
            const end = await k.read8(entry.add32(VM_MAP_ENTRY_END));
            const prot = await k.read4(entry.add32(VM_MAP_ENTRY_PROTECTION));

            const size = end.sub64(start);
            const protStr =
                ((prot & VM_PROT_READ) ? 'R' : '-') +
                ((prot & VM_PROT_WRITE) ? 'W' : '-') +
                ((prot & VM_PROT_EXECUTE) ? 'X' : '-');

            mappings.push({
                start: start,
                end: end,
                size: size,
                prot: protStr,
                protRaw: prot
            });

            // Move to next entry
            entry = await k.read8(entry.add32(VM_MAP_ENTRY_NEXT));
        } catch (e) {
            log(`Error reading entry at ${entry.toString()}: ${e}`, LogLevel.WARN);
            break;
        }
    }

    return mappings;
}

/**
 * Search for emulator-specific patterns in memory regions
 * Looking for:
 * - JIT code regions (RWX or RX after JIT)
 * - PS2 RAM region (0x9000000000 range for IOP)
 * - Emulator data sections
 */
async function analyzeEmuMappings(mappings) {
    log("=== Memory Region Analysis ===", LogLevel.INFO);

    let executable = [];
    let writable = [];
    let iopCandidates = [];
    let ebootCandidates = [];

    for (const m of mappings) {
        const startHex = m.start.toString();
        const sizeHex = m.size.toString();

        // Look for executable regions (potential eboot .text)
        if (m.prot.includes('X')) {
            executable.push(m);
            log(`EXEC: ${startHex} - ${m.end.toString()} [${m.prot}] size: ${sizeHex}`, LogLevel.DEBUG);
        }

        // Look for writable regions (potential .data, status buffers)
        if (m.prot.includes('W') && !m.prot.includes('X')) {
            writable.push(m);
        }

        // Look for IOP RAM candidates (address around 0x9000000000)
        if (m.start.hi >= 0x90 && m.start.hi <= 0x91) {
            iopCandidates.push(m);
            log(`IOP CANDIDATE: ${startHex} - ${m.end.toString()} [${m.prot}]`, LogLevel.SUCCESS);
        }

        // Look for low-address executable (potential eboot @ 0x400000)
        if (m.start.hi === 0 && m.start.low < 0x10000000 && m.prot.includes('X')) {
            ebootCandidates.push(m);
            log(`EBOOT CANDIDATE: ${startHex} - ${m.end.toString()} [${m.prot}]`, LogLevel.SUCCESS);
        }
    }

    return {
        executable,
        writable,
        iopCandidates,
        ebootCandidates
    };
}

/**
 * Search for IOP RAM pointer pattern in emulator data sections
 * The IOP RAM pointer should point to 0x9000000000 region
 *
 * Key insight: IOP RAM pointer normally contains exactly 0x9000000000
 * This is a very distinctive 64-bit value we can search for
 */
async function findIopRamPointer(k, mappings) {
    log("=== Searching for IOP RAM Pointer (0x9000000000) ===", LogLevel.INFO);

    let candidates = [];

    for (const m of mappings) {
        // Only search writable, non-executable regions
        if (!m.prot.includes('W') || m.prot.includes('X')) continue;

        // Skip very large regions (too slow to scan)
        const size = m.size.low;
        if (m.size.hi > 0 || size > 0x2000000) continue; // Skip > 32MB
        if (size < 0x1000) continue; // Skip < 4KB

        log(`Scanning ${m.start.toString()} (${(size/1024).toFixed(0)}KB)...`, LogLevel.DEBUG | LogLevel.FLAG_TEMP);

        // Scan for pointer patterns - look every 8 bytes
        for (let offset = 0; offset < size; offset += 8) {
            try {
                const value = await k.read8(m.start.add32(offset));

                // Check for exact IOP RAM base: 0x0000009000000000
                if (value.hi === 0x00000090 && value.low === 0x00000000) {
                    const addr = m.start.add32(offset);
                    log(`EXACT IOP RAM PTR @ ${addr.toString()}: ${value.toString()}`, LogLevel.SUCCESS);
                    candidates.push({
                        addr: addr,
                        value: value,
                        regionStart: m.start,
                        offsetInRegion: offset
                    });
                }
                // Also check for nearby IOP addresses (in case of different mapping)
                else if (value.hi >= 0x00000090 && value.hi <= 0x00000091 &&
                         (value.low & 0xFFF) === 0) {
                    const addr = m.start.add32(offset);
                    log(`NEAR IOP PTR @ ${addr.toString()}: ${value.toString()}`, LogLevel.INFO);
                }
            } catch (e) {
                // Skip read errors
            }
        }
    }

    if (candidates.length > 0) {
        log(`\n=== Found ${candidates.length} IOP RAM Pointer Candidate(s) ===`, LogLevel.SUCCESS);
        for (const c of candidates) {
            // Calculate where N_STATUS_BUFFER should be (0x25F628 bytes before IOP ptr)
            const N_TO_IOP_OFFSET = 0x25F628;
            const estimatedNBuffer = c.addr.sub32(N_TO_IOP_OFFSET);
            log(`  IOP PTR: ${c.addr.toString()}`, LogLevel.INFO);
            log(`  Estimated N_STATUS_BUFFER: ${estimatedNBuffer.toString()}`, LogLevel.INFO);
            log(`  Estimated S_STATUS_BUFFER: ${estimatedNBuffer.add32(0x10).toString()}`, LogLevel.INFO);
        }
    }

    return candidates;
}

/**
 * Search for N/S status buffer patterns
 * These are typically 16-byte structures with specific bit patterns
 */
async function findStatusBuffers(k, mappings) {
    log("=== Searching for N/S Status Buffers ===", LogLevel.INFO);

    // In mast1c0re, N and S buffers are typically:
    // - Adjacent (0x10 bytes apart)
    // - In read-write data section
    // - Near other emulator state

    // We'll look for patterns that match status buffer signatures
    // This requires dumping and analyzing data sections

    for (const m of mappings) {
        if (!m.prot.includes('W') || m.prot.includes('X')) continue;

        const size = m.size.low;
        if (m.size.hi > 0 || size > 0x100000) continue; // Skip > 1MB
        if (size < 0x1000) continue;

        // Log candidate regions for manual inspection
        log(`DATA REGION: ${m.start.toString()} size=${size.toString(16)}`, LogLevel.INFO);
    }
}

/**
 * Main function to analyze ps2emu process
 */
async function findMast1coreAddresses(k) {
    log("=== PS2 Emulator Memory Analysis ===", LogLevel.INFO);
    log("Looking for mast1c0re-critical addresses...", LogLevel.INFO);

    // Find ps2emu processes
    const searchTerms = ["ps2", "emu", "eboot", "racer"];
    let allProcesses = [];

    for (const term of searchTerms) {
        const procs = await findProcessByName(k, k.kdataBase.add32(OFFSET_KERNEL_ALLPROC - OFFSET_KERNEL_DATA), term);
        allProcesses = allProcesses.concat(procs);
    }

    if (allProcesses.length === 0) {
        // List all processes to find the right one
        log("No ps2emu found, listing all processes...", LogLevel.WARN);
        await listAllProcesses(k);
        return;
    }

    // Analyze each found process
    for (const p of allProcesses) {
        log(`\n=== Analyzing: ${p.name} (PID: ${p.pid}) ===`, LogLevel.INFO);

        const mappings = await dumpProcessMemoryMap(k, p.proc);
        log(`Found ${mappings.length} memory mappings`, LogLevel.INFO);

        const analysis = await analyzeEmuMappings(mappings);

        log(`Executable regions: ${analysis.executable.length}`, LogLevel.INFO);
        log(`Writable regions: ${analysis.writable.length}`, LogLevel.INFO);
        log(`IOP candidates: ${analysis.iopCandidates.length}`, LogLevel.INFO);
        log(`Eboot candidates: ${analysis.ebootCandidates.length}`, LogLevel.INFO);

        // Detailed output of key regions
        if (analysis.ebootCandidates.length > 0) {
            log("\n=== Potential Eboot Sections ===", LogLevel.SUCCESS);
            for (const m of analysis.ebootCandidates) {
                log(`  ${m.start.toString()} - ${m.end.toString()} [${m.prot}]`, LogLevel.INFO);
            }
        }

        if (analysis.iopCandidates.length > 0) {
            log("\n=== IOP RAM Mappings ===", LogLevel.SUCCESS);
            for (const m of analysis.iopCandidates) {
                log(`  ${m.start.toString()} - ${m.end.toString()} [${m.prot}]`, LogLevel.INFO);
            }
        }

        // Search for specific pointers
        await findIopRamPointer(k, analysis.writable);
        await findStatusBuffers(k, analysis.writable);
    }
}

/**
 * List all processes on the system
 */
async function listAllProcesses(k) {
    const allprocAddr = k.kdataBase.add32(OFFSET_KERNEL_ALLPROC - OFFSET_KERNEL_DATA);
    let proc = await k.read8(allprocAddr);

    log("=== All Processes ===", LogLevel.INFO);

    for (let i = 0; i < 200; i++) {
        if (proc.low === 0 && proc.hi === 0) break;

        try {
            const name = await kreadString(k, proc.add32(PROC_P_COMM));
            const pid = await k.read4(proc.add32(PROC_P_PID));
            log(`  [${pid}] ${name}`, LogLevel.DEBUG);

            proc = await k.read8(proc.add32(PROC_P_LIST_NEXT));
        } catch (e) {
            break;
        }
    }
}

// Export functions for use in main.js
// Usage: After exploit succeeds, call:
//   await findMast1coreAddresses(k);
// where k is the kernel primitives object returned by the exploit
