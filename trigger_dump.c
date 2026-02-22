/*
 * trigger_dump.c - PS5 ELF to trigger etaHEN system SELF dump
 *
 * Compile with PS5 payload SDK:
 *   make trigger_dump.elf
 *
 * Send to PS5 (after etaHEN is loaded):
 *   nc <PS5_IP> 9021 < trigger_dump.elf
 *
 * Decrypted SELFs will be written to /data/etaHEN/system_dump/
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define CRIT_IPC_SOC "/system_tmp/etaHEN_crit_service"
#define DAEMON_BUFF_MAX 0x1000
#define IPC_MAGIC 0xDEADBABE

/* Must match etaHEN's DaemonCommands enum exactly */
#define BREW_DUMP_SYSTEM_SELFS 0x9000013

struct IPCMessage {
    int magic;
    int cmd;
    int error;
    char msg[DAEMON_BUFF_MAX];
};

int main(void) {
    struct sockaddr_un addr;
    struct IPCMessage ipc;
    int sock;

    printf("[trigger_dump] Connecting to etaHEN daemon...\n");

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[trigger_dump] Failed to create socket\n");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CRIT_IPC_SOC, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, SUN_LEN(&addr)) < 0) {
        printf("[trigger_dump] Failed to connect to daemon socket\n");
        close(sock);
        return 1;
    }

    printf("[trigger_dump] Connected. Sending BREW_DUMP_SYSTEM_SELFS...\n");

    memset(&ipc, 0, sizeof(ipc));
    ipc.magic = IPC_MAGIC;
    ipc.cmd = BREW_DUMP_SYSTEM_SELFS;
    /* Empty JSON object - daemon will use default output path */
    snprintf(ipc.msg, sizeof(ipc.msg), "{}");

    if (send(sock, &ipc, sizeof(ipc), 0) < 0) {
        printf("[trigger_dump] Failed to send IPC message\n");
        close(sock);
        return 1;
    }

    /* Wait for reply */
    struct IPCMessage reply;
    memset(&reply, 0, sizeof(reply));
    recv(sock, &reply, sizeof(reply), 0);

    printf("[trigger_dump] Daemon replied with error=%d\n", reply.error);
    printf("[trigger_dump] Dump triggered. Check PS5 notifications and\n");
    printf("               /data/etaHEN/system_dump/ via FTP on port 1337\n");

    close(sock);
    return 0;
}
