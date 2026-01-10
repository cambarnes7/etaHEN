/* APIC_OPS Scanner for etaHEN
 * Scans kernel .data for consecutive function pointers
 * Results logged to /data/etaHEN/apic_scan.log
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

extern "C" {
    int kernel_copyout(unsigned long kaddr, void *uaddr, unsigned long len);
}

extern uintptr_t kernel_base;

#define SEARCH_START_OFFSET  0x6400000
#define SEARCH_END_OFFSET    0x6A00000
#define CHUNK_SIZE           0x1000
#define MIN_CONSECUTIVE      6

static uint64_t scan_buffer[512];  // 4KB / 8

static inline int is_kernel_ptr(uint64_t val) {
    // Accept any kernel-space pointer
    return (val >= 0xFFFFFFFF80000000ULL && val <= 0xFFFFFFFFFFFFFFFFULL);
}

void scan_for_apic_ops(void) {
    FILE *log = fopen("/data/etaHEN/apic_scan.log", "w");
    if (!log) return;

    fprintf(log, "=== APIC_OPS Scanner ===\n");
    fprintf(log, "Kernel base: 0x%lx\n", (unsigned long)kernel_base);
    fprintf(log, "Search range: 0x%lx - 0x%lx\n\n",
            (unsigned long)(kernel_base + SEARCH_START_OFFSET),
            (unsigned long)(kernel_base + SEARCH_END_OFFSET));
    fflush(log);

    int candidates_found = 0;
    uint64_t best_addr = 0;
    int best_count = 0;

    for (uint64_t offset = SEARCH_START_OFFSET; offset < SEARCH_END_OFFSET; offset += CHUNK_SIZE) {
        uint64_t addr = kernel_base + offset;

        if (kernel_copyout(addr, scan_buffer, CHUNK_SIZE) != 0) {
            continue;
        }

        int consecutive = 0;
        uint64_t potential_start = 0;

        for (int i = 0; i < 512; i++) {
            uint64_t val = scan_buffer[i];

            if (is_kernel_ptr(val)) {
                if (consecutive == 0) {
                    potential_start = addr + (i * 8);
                }
                consecutive++;
            } else {
                if (consecutive >= MIN_CONSECUTIVE) {
                    fprintf(log, "[CANDIDATE] addr=0x%lx offset=0x%lx count=%d\n",
                            (unsigned long)potential_start,
                            (unsigned long)(potential_start - kernel_base),
                            consecutive);
                    fflush(log);
                    candidates_found++;

                    if (consecutive > best_count) {
                        best_count = consecutive;
                        best_addr = potential_start;
                    }
                }
                consecutive = 0;
            }
        }

        // Check end of buffer
        if (consecutive >= MIN_CONSECUTIVE) {
            fprintf(log, "[CANDIDATE] addr=0x%lx offset=0x%lx count=%d\n",
                    (unsigned long)potential_start,
                    (unsigned long)(potential_start - kernel_base),
                    consecutive);
            fflush(log);
            candidates_found++;

            if (consecutive > best_count) {
                best_count = consecutive;
                best_addr = potential_start;
            }
        }
    }

    fprintf(log, "\n=== Scan Complete ===\n");
    fprintf(log, "Total candidates: %d\n", candidates_found);

    if (best_addr) {
        fprintf(log, "\nMost likely apic_ops:\n");
        fprintf(log, "  Address: 0x%lx\n", (unsigned long)best_addr);
        fprintf(log, "  Offset:  0x%lx\n", (unsigned long)(best_addr - kernel_base));
        fprintf(log, "  Count:   %d consecutive pointers\n", best_count);

        // Dump the first 16 pointers at best candidate
        fprintf(log, "\nFirst 16 pointers at candidate:\n");
        uint64_t dump[16];
        if (kernel_copyout(best_addr, dump, sizeof(dump)) == 0) {
            for (int i = 0; i < 16; i++) {
                fprintf(log, "  [%02d] 0x%lx\n", i, (unsigned long)dump[i]);
            }
        }
    }

    fclose(log);
}
