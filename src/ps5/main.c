/*
 * Garlic Worker - PS5 save processing worker for Garlic Saves
 * Polls HTOS-web server for jobs (decrypt, encrypt, resign, reregion)
 * and processes them using PS5 PFS operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdarg.h>

#include "config.h"
#include "worker.h"
#include "savedata.h"
#include "zip.h"
#include "util.h"

/* ── SDK imports ───────────────────────────────────────────────── */
int sceUserServiceInitialize(void *);

typedef struct { char unused[45]; char message[3075]; } notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

#include <ps5/kernel.h>
#include "log.h"
#include "killswitch.h"

/* ── Notification ──────────────────────────────────────────────── */
static void notify(const char *fmt, ...) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    va_list a;
    va_start(a, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, a);
    va_end(a);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
    garlic_log("[Garlic] %s\n", req.message);
}

/* ── Main ──────────────────────────────────────────────────────── */
int main(void) {
    /* Name this payload */
    syscall(SYS_thr_set_name, -1, "garlic-worker.elf");

    /* Initialize PS5 services */
    sceUserServiceInitialize(0);
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);
    signal(SIGPIPE, SIG_IGN);

    /* Initialize subsystems */
    savedata_init();
    zip_init_crc();

    /* Create work directories */
    mkdir("/data/garlic", 0777);
    mkdir("/data/garlic/work", 0777);
    mkdir("/data/save_files", 0777);

    /* Initialize file logging */
    log_init();

    /* Load config */
    worker_config_t cfg;
    config_load("/data/garlic/config.ini", &cfg);

    /* Notify */
    notify("Garlic Worker started (%s:%d)", cfg.server_host, cfg.server_port);

    /* Start kill switch listener */
    killswitch_start(8088);

    /* Start worker loop (never returns) */
    worker_loop(&cfg);

    return 0;
}
