#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "util.h"
#include "log.h"
#include "http.h"  /* for http_tcp_connect */

/* ── Send/recv helpers ─────────────────────────────────────────── */

static int tcp_send_all(int sock, const void *buf, int len) {
    const char *p = buf;
    int remaining = len;
    while (remaining > 0) {
        ssize_t n = send(sock, p, remaining, 0);
        if (n <= 0) return -1;
        p += n;
        remaining -= n;
    }
    return 0;
}

static int tcp_recv_exact(int sock, void *buf, int n) {
    char *p = buf;
    int remaining = n;
    while (remaining > 0) {
        ssize_t r = recv(sock, p, remaining, 0);
        if (r <= 0) return -1;
        p += r;
        remaining -= r;
    }
    return 0;
}

/* ── Public API ────────────────────────────────────────────────── */

int tcp_connect_server(tcp_conn_t *conn, const char *host, int port) {
    conn->sock = http_tcp_connect(host, port);
    if (conn->sock < 0) {
        conn->connected = 0;
        return -1;
    }

    /* Longer timeouts for persistent connection (2 minutes) */
    struct timeval tv = {120, 0};
    setsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(conn->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    conn->connected = 1;
    return 0;
}

void tcp_disconnect(tcp_conn_t *conn) {
    if (conn->sock >= 0) {
        close(conn->sock);
        conn->sock = -1;
    }
    conn->connected = 0;
}

int tcp_send_msg(tcp_conn_t *conn, const char *json_str) {
    if (!conn->connected) return -1;
    uint32_t len = strlen(json_str);
    uint32_t net_len = htonl(len);
    if (tcp_send_all(conn->sock, &net_len, 4) < 0) return -1;
    if (tcp_send_all(conn->sock, json_str, len) < 0) return -1;
    return 0;
}

int tcp_recv_msg(tcp_conn_t *conn, char *buf, int buf_size) {
    if (!conn->connected) return -1;

    uint32_t net_len;
    if (tcp_recv_exact(conn->sock, &net_len, 4) < 0) return -1;
    uint32_t len = ntohl(net_len);

    if ((int)len >= buf_size) {
        garlic_log("[TCP] Message too large: %u bytes\n", len);
        return -1;
    }

    if (tcp_recv_exact(conn->sock, buf, len) < 0) return -1;
    buf[len] = '\0';
    return (int)len;
}

int tcp_recv_to_file(tcp_conn_t *conn, int fd, int64_t size) {
    char buf[BUF_SIZE];
    int64_t remaining = size;
    while (remaining > 0) {
        int to_read = remaining < (int64_t)sizeof(buf) ? (int)remaining : (int)sizeof(buf);
        if (tcp_recv_exact(conn->sock, buf, to_read) < 0) return -1;
        if (write(fd, buf, to_read) != to_read) return -1;
        remaining -= to_read;
    }
    return 0;
}

int tcp_send_file(tcp_conn_t *conn, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char buf[BUF_SIZE];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (tcp_send_all(conn->sock, buf, n) < 0) {
            close(fd);
            return -1;
        }
    }
    close(fd);
    return (n < 0) ? -1 : 0;
}
