# APIC_OPS Scanner for PS5 FW 4.03

Scans kernel .data segment for the `apic_ops` structure by looking for
consecutive kernel .text pointers.

## What This Does

1. Scans kernel memory range `0xFFFFFFFF86400000` - `0xFFFFFFFF86900000`
2. Looks for 8+ consecutive pointers into kernel .text (`0xFFFFFFFF80XXXXXX`)
3. Reports candidates via TCP and saves to log file

## How To Use

### Option 1: Build with PS5 SDK

If you have the PS5 payload SDK set up:

```bash
# Adjust paths for your SDK
$PS5_TOOLCHAIN/bin/clang \
    -target x86_64-scei-ps5-elf \
    -o apic_scanner.elf \
    apic_scanner.c \
    -I$PS5_SDK/include \
    -L$PS5_SDK/lib \
    -lkernel
```

### Option 2: Use etaHEN SDK

If you have the etaHEN SDK:

```bash
cd /path/to/etaHEN-SDK
# Add apic_scanner.c to a payload project
# Build following SDK instructions
```

### Option 3: Adapt for John's elfldr

The scanner needs `kernel_copyout` to work. If your elfldr setup provides
kernel primitives differently, adjust the extern declaration.

## Running the Scanner

1. **Load etaHEN** on your PS5 (FW 4.03)

2. **Send the payload** via elfldr:
   ```bash
   # Using netcat or payload sender
   nc <PS5_IP> 9021 < apic_scanner.elf
   ```

3. **Connect to receive results**:
   ```bash
   nc <PS5_IP> 9999
   ```

4. **Wait for scan to complete** (~5MB of kernel memory)

5. **Check output** for candidates like:
   ```
   [CANDIDATE] addr=0xFFFFFFFF865XXXXX count=15 first_ptr=0xFFFFFFFF80XXXXXX
   ```

## Interpreting Results

### Good Candidate (likely apic_ops):
```
[CANDIDATE] addr=0xFFFFFFFF86512340 count=8 first_ptr=0xFFFFFFFF80123456
[UPDATE] addr=0xFFFFFFFF86512340 now has 15 consecutive ptrs
[END] addr=0xFFFFFFFF86512340 final_count=18
```

A structure with 15-20 consecutive function pointers is likely `apic_ops`.

### False Positives:
- vtables (usually have specific patterns)
- syscall tables (very large, 500+ entries)
- Other *_ops structures (also interesting!)

## After Finding apic_ops

Once you identify the address:

1. **Verify**: Read the first pointer, this should be `xapic_mode`

2. **Test (will crash!)**: Overwrite first pointer with garbage like `0x4141414141414141`,
   then trigger rest mode. If PS5 crashes on resume with that PC, you confirmed it.

3. **Next step**: CFI bypass research to actually execute code

## Files

- `apic_scanner.c` - The scanner source code
- `apic_scan.log` - Results saved to `/data/etaHEN/apic_scan.log` on PS5

## Adjusting Search Range

If you don't find it, try expanding the search range in the source:

```c
#define SEARCH_START  (KERNEL_BASE + 0x6000000)  /* Earlier */
#define SEARCH_END    (KERNEL_BASE + 0x7000000)  /* Later */
```

## Known FW 4.03 Offsets (for reference)

From etaHEN's offset tables:
- allproc: `0x27EDCB8`
- security_flags: `0x6505474`
- root_vnode: `0x66E74C0`

These are all in the range we're scanning.
