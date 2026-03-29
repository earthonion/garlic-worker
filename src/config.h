#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    char server_host[256];
    int  server_port;
    char worker_key[256];
    int  poll_interval;
    int  connection_mode;  /* 0=http (default), 1=tcp */
    int  tcp_port;         /* default 9090 */
} worker_config_t;

int config_load(const char *path, worker_config_t *cfg);

#endif
