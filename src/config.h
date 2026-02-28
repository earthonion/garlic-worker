#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    char server_host[256];
    int  server_port;
    char worker_key[256];
    int  poll_interval;
} worker_config_t;

int config_load(const char *path, worker_config_t *cfg);

#endif
