/* Minimal test payload - just sends a PS5 notification */
/* If this shows "Test OK" on the PS5 screen, the CRT and build infrastructure work */

#include <stdint.h>
#include <string.h>

typedef struct {
    int type;
    int req_id;
    int priority;
    int msg_id;
    int target_id;
    int user_id;
    int unk1;
    int unk2;
    int app_id;
    int error_num;
    int unk3;
    char use_icon_image_uri;
    char message[1024];
    char uri[1024];
    char unkstr[1024];
} OrbisNotificationRequest;

int sceKernelSendNotificationRequest(int device,
                                     OrbisNotificationRequest *req,
                                     unsigned long size,
                                     int blocking);

int main(void) {
    OrbisNotificationRequest req;
    memset(&req, 0, sizeof(req));

    req.type = 0;
    req.target_id = -1;

    const char *msg = "Test OK - CRT works!";
    int i;
    for (i = 0; msg[i]; i++) {
        req.message[i] = msg[i];
    }
    req.message[i] = 0;

    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);

    return 0;
}
