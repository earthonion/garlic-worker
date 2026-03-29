#ifndef TCP_H
#define TCP_H

#include <stdint.h>

/* Persistent TCP connection to server */
typedef struct {
    int sock;
    int connected;
} tcp_conn_t;

/* Connect to server's TCP worker port. Returns 0 on success. */
int tcp_connect_server(tcp_conn_t *conn, const char *host, int port);

/* Close connection */
void tcp_disconnect(tcp_conn_t *conn);

/* Send a length-prefixed JSON message. Returns 0 on success. */
int tcp_send_msg(tcp_conn_t *conn, const char *json_str);

/* Receive a length-prefixed JSON message into buf (null-terminated).
 * Returns message length, or -1 on error. */
int tcp_recv_msg(tcp_conn_t *conn, char *buf, int buf_size);

/* Receive exactly 'size' bytes from TCP and write to file at fd.
 * Returns 0 on success. */
int tcp_recv_to_file(tcp_conn_t *conn, int fd, int64_t size);

/* Send file contents over TCP (raw bytes, no framing — caller sends
 * the size via a JSON message first). Returns 0 on success. */
int tcp_send_file(tcp_conn_t *conn, const char *path);

#endif
