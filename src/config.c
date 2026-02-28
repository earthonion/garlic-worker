#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "config.h"

#ifndef WORKER_KEY
#define WORKER_KEY "changeme"
#endif

static int config_create_default(const char *path, worker_config_t *cfg) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("[Garlic] Failed to create config at %s\n", path);
        return -1;
    }

    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "serverHost=%s\n"
        "serverPort=%d\n"
        "workerKey=%s\n"
        "pollInterval=%d\n",
        cfg->server_host, cfg->server_port, cfg->worker_key, cfg->poll_interval);
    write(fd, buf, n);
    close(fd);

    printf("[Garlic] Created default config at %s\n", path);
    return 0;
}

int config_load(const char *path, worker_config_t *cfg) {
    /* Defaults */
    snprintf(cfg->server_host, sizeof(cfg->server_host), "garlicsaves.com");
    cfg->server_port = 80;
    snprintf(cfg->worker_key, sizeof(cfg->worker_key), "%s", WORKER_KEY);
    cfg->poll_interval = 60;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("[Garlic] Config not found at %s, creating default...\n", path);
        return config_create_default(path, cfg);
    }

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == ';' || line[0] == 0) {
            line = nl ? nl + 1 : NULL;
            continue;
        }

        char *eq = strchr(line, '=');
        if (eq) {
            *eq = 0;
            char *key = line;
            char *val = eq + 1;
            /* Trim leading spaces from value */
            while (*val == ' ' || *val == '\t') val++;
            /* Trim trailing \r */
            char *cr = strchr(val, '\r');
            if (cr) *cr = 0;

            if (strcmp(key, "serverHost") == 0)
                snprintf(cfg->server_host, sizeof(cfg->server_host), "%s", val);
            else if (strcmp(key, "serverPort") == 0)
                cfg->server_port = atoi(val);
            else if (strcmp(key, "workerKey") == 0)
                snprintf(cfg->worker_key, sizeof(cfg->worker_key), "%s", val);
            else if (strcmp(key, "pollInterval") == 0)
                cfg->poll_interval = atoi(val);
        }
        line = nl ? nl + 1 : NULL;
    }

    printf("[Garlic] Config: host=%s port=%d key=%s poll=%ds\n",
           cfg->server_host, cfg->server_port,
           cfg->worker_key[0] ? "(set)" : "(empty)",
           cfg->poll_interval);
    return 0;
}
