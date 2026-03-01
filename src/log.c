#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

#define LOG_PATH "/data/garlic/log.txt"

static int g_log_fd = -1;

void log_init(void) {
    g_log_fd = open(LOG_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (g_log_fd < 0)
        printf("[Garlic] Warning: could not open log file %s\n", LOG_PATH);
}

void log_flush(void) {
    if (g_log_fd >= 0) fsync(g_log_fd);
}

void garlic_log(const char *fmt, ...) {
    char buf[4096];
    va_list a;
    va_start(a, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, a);
    va_end(a);

    /* Write to stdout */
    printf("%s", buf);

    /* Write to log file */
    if (g_log_fd >= 0 && n > 0)
        write(g_log_fd, buf, n);
}
