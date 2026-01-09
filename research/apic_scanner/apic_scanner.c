/*
 * apic_scanner.c - Scan kernel .data for apic_ops structure
 *
 * For FW 4.03 - Send via elfldr (port 9021) after etaHEN loads
 *
 * Build with PS5 SDK or adapt to your toolchain
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Kernel R/W - these should be available after etaHEN jailbreak */
extern int kernel_copyout(unsigned long kaddr, void *uaddr, unsigned long len);

/* FW 4.03 specific values */
#define KERNEL_BASE         0xFFFFFFFF80000000ULL
#define KERNEL_TEXT_START   0xFFFFFFFF80000000ULL
#define KERNEL_TEXT_END     0xFFFFFFFF82000000ULL  /* Approximate */

/* Search range in .data - based on known 4.03 offsets */
#define SEARCH_START        (KERNEL_BASE + 0x6400000)  /* Start of .data region */
#define SEARCH_END          (KERNEL_BASE + 0x6900000)  /* End of search */
#define SEARCH_CHUNK        0x1000                      /* 4KB chunks */

/* Results server */
#define RESULT_PORT         9999

/* How many consecutive pointers to consider a match */
#define MIN_CONSECUTIVE     8

/* Buffer for kernel reads */
static uint64_t read_buffer[512];  /* 4KB / 8 bytes */

/* Check if value looks like a kernel .text pointer */
static int is_kernel_text_ptr(uint64_t val) {
    return (val >= KERNEL_TEXT_START && val < KERNEL_TEXT_END);
}

/* Log to file */
static FILE *logfile = NULL;

static void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    if (logfile) {
        vfprintf(logfile, fmt, args);
        fflush(logfile);
    }

    /* Also printf for klog if enabled */
    va_start(args, fmt);
    vprintf(fmt, args);

    va_end(args);
}

/* Scan a chunk of memory for consecutive kernel .text pointers */
static void scan_chunk(uint64_t base_addr, int client_sock) {
    int consecutive = 0;
    uint64_t potential_start = 0;
    char msg[256];

    /* Read chunk from kernel */
    if (kernel_copyout(base_addr, read_buffer, SEARCH_CHUNK) != 0) {
        return;  /* Read failed, skip this chunk */
    }

    /* Scan for consecutive pointers */
    for (int i = 0; i < 512; i++) {
        uint64_t val = read_buffer[i];

        if (is_kernel_text_ptr(val)) {
            if (consecutive == 0) {
                potential_start = base_addr + (i * 8);
            }
            consecutive++;

            /* Found a candidate! */
            if (consecutive == MIN_CONSECUTIVE) {
                snprintf(msg, sizeof(msg),
                    "[CANDIDATE] addr=0x%lx count=%d first_ptr=0x%lx\n",
                    potential_start, consecutive, read_buffer[i - consecutive + 1]);

                log_msg("%s", msg);

                if (client_sock >= 0) {
                    send(client_sock, msg, strlen(msg), 0);
                }
            }
            else if (consecutive > MIN_CONSECUTIVE) {
                /* Update count for ongoing sequence */
                snprintf(msg, sizeof(msg),
                    "[UPDATE] addr=0x%lx now has %d consecutive ptrs\n",
                    potential_start, consecutive);

                log_msg("%s", msg);

                if (client_sock >= 0) {
                    send(client_sock, msg, strlen(msg), 0);
                }
            }
        } else {
            /* Sequence ended - report if it was significant */
            if (consecutive >= MIN_CONSECUTIVE) {
                snprintf(msg, sizeof(msg),
                    "[END] addr=0x%lx final_count=%d\n\n",
                    potential_start, consecutive);

                log_msg("%s", msg);

                if (client_sock >= 0) {
                    send(client_sock, msg, strlen(msg), 0);
                }
            }
            consecutive = 0;
        }
    }
}

/* Main scanner function */
static void run_scanner(int client_sock) {
    char msg[256];
    uint64_t addr;
    int chunks_scanned = 0;
    int total_chunks = (SEARCH_END - SEARCH_START) / SEARCH_CHUNK;

    snprintf(msg, sizeof(msg),
        "=== APIC_OPS Scanner for FW 4.03 ===\n"
        "Search range: 0x%lx - 0x%lx\n"
        "Looking for %d+ consecutive kernel .text pointers\n"
        "Total chunks to scan: %d\n\n",
        SEARCH_START, SEARCH_END, MIN_CONSECUTIVE, total_chunks);

    log_msg("%s", msg);
    if (client_sock >= 0) {
        send(client_sock, msg, strlen(msg), 0);
    }

    /* Scan kernel .data */
    for (addr = SEARCH_START; addr < SEARCH_END; addr += SEARCH_CHUNK) {
        scan_chunk(addr, client_sock);
        chunks_scanned++;

        /* Progress update every 256 chunks (~1MB) */
        if (chunks_scanned % 256 == 0) {
            snprintf(msg, sizeof(msg),
                "[PROGRESS] %d/%d chunks (%.1f%%) - current: 0x%lx\n",
                chunks_scanned, total_chunks,
                (float)chunks_scanned / total_chunks * 100.0f, addr);

            log_msg("%s", msg);
            if (client_sock >= 0) {
                send(client_sock, msg, strlen(msg), 0);
            }
        }
    }

    snprintf(msg, sizeof(msg),
        "\n=== Scan Complete ===\n"
        "Scanned %d chunks (%lu bytes)\n"
        "Check candidates above for apic_ops\n",
        chunks_scanned, (unsigned long)(SEARCH_END - SEARCH_START));

    log_msg("%s", msg);
    if (client_sock >= 0) {
        send(client_sock, msg, strlen(msg), 0);
    }
}

/* Start TCP server to stream results */
static int start_result_server(void) {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        printf("Failed to create socket\n");
        return -1;
    }

    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(RESULT_PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to bind to port %d\n", RESULT_PORT);
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 1) < 0) {
        printf("Failed to listen\n");
        close(server_sock);
        return -1;
    }

    printf("[*] Waiting for connection on port %d...\n", RESULT_PORT);
    printf("[*] Connect with: nc <PS5_IP> %d\n", RESULT_PORT);

    client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0) {
        printf("Failed to accept connection\n");
        close(server_sock);
        return -1;
    }

    printf("[+] Client connected!\n");

    close(server_sock);  /* Don't need server socket anymore */
    return client_sock;
}

int main(int argc, char *argv[]) {
    int client_sock = -1;

    printf("\n");
    printf("========================================\n");
    printf("  APIC_OPS Scanner - FW 4.03\n");
    printf("========================================\n\n");

    /* Open log file */
    logfile = fopen("/data/etaHEN/apic_scan.log", "w");
    if (!logfile) {
        printf("[!] Warning: Could not open log file\n");
    }

    /* Start server and wait for connection */
    client_sock = start_result_server();

    /* Run the scanner */
    run_scanner(client_sock);

    /* Cleanup */
    if (client_sock >= 0) {
        close(client_sock);
    }

    if (logfile) {
        fclose(logfile);
    }

    printf("\n[*] Results saved to /data/etaHEN/apic_scan.log\n");
    printf("[*] Scanner complete. Check candidates for apic_ops.\n");

    return 0;
}
