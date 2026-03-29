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

#include "http.h"
#include "json.h"
#include "util.h"
#include "log.h"
#include <ctype.h>

/* PS4 libc doesn't have strcasestr */
static const char *my_strcasestr(const char *haystack, const char *needle) {
    if (!needle[0]) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++; n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

/* ── DNS resolution via getaddrinfo (no sceNetInit needed) ─────── */

#include <netdb.h>

static in_addr_t resolve_host(const char *host) {
    /* Try as IP address first */
    in_addr_t ip = inet_addr(host);
    if (ip != INADDR_NONE) return ip;

    /* DNS resolution via POSIX getaddrinfo */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, NULL, &hints, &res);
    if (err != 0 || !res) return INADDR_NONE;

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    in_addr_t result = addr->sin_addr.s_addr;
    freeaddrinfo(res);
    return result;
}

/* ── Internal helpers ──────────────────────────────────────────── */

int http_tcp_connect(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    /* 30 second timeouts */
    struct timeval tv = {30, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    in_addr_t ip = resolve_host(host);
    if (ip == INADDR_NONE) {
        close(sock);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ip;

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

static int send_all(int sock, const void *buf, int len) {
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

/* Read until \r\n\r\n, return header length (including \r\n\r\n).
 * Header is stored in buf (null-terminated). */
static int recv_headers(int sock, char *buf, int buf_size) {
    int total = 0;
    while (total < buf_size - 1) {
        ssize_t n = recv(sock, buf + total, 1, 0);
        if (n <= 0) break;
        total++;
        if (total >= 4 &&
            buf[total-4] == '\r' && buf[total-3] == '\n' &&
            buf[total-2] == '\r' && buf[total-1] == '\n') {
            buf[total] = 0;
            return total;
        }
    }
    buf[total] = 0;
    return total;
}

static int parse_status(const char *header) {
    /* HTTP/1.x NNN ... */
    const char *p = strchr(header, ' ');
    if (!p) return 0;
    return atoi(p + 1);
}

static int parse_content_length(const char *header) {
    const char *p = my_strcasestr(header, "Content-Length:");
    if (!p) return -1;
    return atoi(p + 15);
}

/* Read exactly n bytes from socket */
static int recv_exact(int sock, void *buf, int n) {
    char *p = buf;
    int remaining = n;
    while (remaining > 0) {
        ssize_t r = recv(sock, p, remaining, 0);
        if (r <= 0) break;
        p += r;
        remaining -= r;
    }
    return n - remaining;
}

/* Build and send an HTTP request */
static int send_request(int sock, const char *method, const char *host,
                        const char *path, const char *worker_key,
                        const char *content_type, int content_length) {
    char hdr[2048];
    int pos = 0;
    pos += snprintf(hdr + pos, sizeof(hdr) - pos,
                    "%s %s HTTP/1.0\r\n"
                    "Host: %s\r\n",
                    method, path, host);
    if (worker_key && worker_key[0])
        pos += snprintf(hdr + pos, sizeof(hdr) - pos,
                        "X-Worker-Key: %s\r\n", worker_key);
    if (content_type)
        pos += snprintf(hdr + pos, sizeof(hdr) - pos,
                        "Content-Type: %s\r\n", content_type);
    if (content_length >= 0)
        pos += snprintf(hdr + pos, sizeof(hdr) - pos,
                        "Content-Length: %d\r\n", content_length);
    pos += snprintf(hdr + pos, sizeof(hdr) - pos, "\r\n");

    return send_all(sock, hdr, pos);
}

/* ── Public API ────────────────────────────────────────────────── */

int http_get(const char *host, int port, const char *path,
             const char *worker_key, http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));

    int sock = http_tcp_connect(host, port);
    if (sock < 0) return -1;

    if (send_request(sock, "GET", host, path, worker_key, NULL, -1) < 0) {
        close(sock);
        return -1;
    }

    char hdr[4096];
    recv_headers(sock, hdr, sizeof(hdr));
    resp->status = parse_status(hdr);

    int cl = parse_content_length(hdr);
    if (cl > 0) {
        int to_read = cl < HTTP_BODY_MAX - 1 ? cl : HTTP_BODY_MAX - 1;
        resp->body_len = recv_exact(sock, resp->body, to_read);
    } else if (cl < 0) {
        /* No content-length, read until close */
        resp->body_len = 0;
        while (resp->body_len < HTTP_BODY_MAX - 1) {
            ssize_t n = recv(sock, resp->body + resp->body_len,
                             HTTP_BODY_MAX - 1 - resp->body_len, 0);
            if (n <= 0) break;
            resp->body_len += n;
        }
    }
    resp->body[resp->body_len] = 0;

    close(sock);
    return 0;
}

int http_post_json(const char *host, int port, const char *path,
                   const char *json_body, const char *worker_key,
                   http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));

    int sock = http_tcp_connect(host, port);
    if (sock < 0) return -1;

    int body_len = json_body ? strlen(json_body) : 0;
    if (send_request(sock, "POST", host, path, worker_key,
                     "application/json", body_len) < 0) {
        close(sock);
        return -1;
    }

    if (body_len > 0)
        send_all(sock, json_body, body_len);

    char hdr[4096];
    recv_headers(sock, hdr, sizeof(hdr));
    resp->status = parse_status(hdr);

    int cl = parse_content_length(hdr);
    if (cl > 0) {
        int to_read = cl < HTTP_BODY_MAX - 1 ? cl : HTTP_BODY_MAX - 1;
        resp->body_len = recv_exact(sock, resp->body, to_read);
    } else if (cl < 0) {
        resp->body_len = 0;
        while (resp->body_len < HTTP_BODY_MAX - 1) {
            ssize_t n = recv(sock, resp->body + resp->body_len,
                             HTTP_BODY_MAX - 1 - resp->body_len, 0);
            if (n <= 0) break;
            resp->body_len += n;
        }
    }
    resp->body[resp->body_len] = 0;

    close(sock);
    return 0;
}

int http_post_binary(const char *host, int port, const char *path,
                     const void *data, int data_len,
                     const char *worker_key, http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));

    int sock = http_tcp_connect(host, port);
    if (sock < 0) return -1;

    if (send_request(sock, "POST", host, path, worker_key,
                     "application/octet-stream", data_len) < 0) {
        close(sock);
        return -1;
    }

    if (data_len > 0)
        send_all(sock, data, data_len);

    char hdr[4096];
    recv_headers(sock, hdr, sizeof(hdr));
    resp->status = parse_status(hdr);

    int cl = parse_content_length(hdr);
    if (cl > 0) {
        int to_read = cl < HTTP_BODY_MAX - 1 ? cl : HTTP_BODY_MAX - 1;
        resp->body_len = recv_exact(sock, resp->body, to_read);
    } else if (cl < 0) {
        resp->body_len = 0;
        while (resp->body_len < HTTP_BODY_MAX - 1) {
            ssize_t n = recv(sock, resp->body + resp->body_len,
                             HTTP_BODY_MAX - 1 - resp->body_len, 0);
            if (n <= 0) break;
            resp->body_len += n;
        }
    }
    resp->body[resp->body_len] = 0;

    close(sock);
    return 0;
}

int http_download_to_file(const char *host, int port, const char *path,
                          const char *worker_key, const char *dest_path) {
    int sock = http_tcp_connect(host, port);
    if (sock < 0) return -1;

    if (send_request(sock, "GET", host, path, worker_key, NULL, -1) < 0) {
        close(sock);
        return -1;
    }

    char hdr[4096];
    recv_headers(sock, hdr, sizeof(hdr));
    int status = parse_status(hdr);
    if (status != 200) {
        close(sock);
        return status > 0 ? status : -1;
    }

    int fd = open(dest_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        close(sock);
        return -1;
    }

    int cl = parse_content_length(hdr);
    char buf[BUF_SIZE];

    if (cl > 0) {
        int remaining = cl;
        while (remaining > 0) {
            int to_read = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
            ssize_t n = recv(sock, buf, to_read, 0);
            if (n <= 0) break;
            write(fd, buf, n);
            remaining -= n;
        }
    } else {
        /* Read until close */
        ssize_t n;
        while ((n = recv(sock, buf, sizeof(buf), 0)) > 0)
            write(fd, buf, n);
    }

    close(fd);
    close(sock);
    return status;
}

int http_upload_file_chunked(const char *host, int port,
                             const char *base_path, const char *src_path,
                             const char *worker_key) {
    struct stat st;
    if (stat(src_path, &st) < 0) return -1;
    int64_t file_size = st.st_size;

    int fd = open(src_path, O_RDONLY);
    if (fd < 0) return -1;

    /* Step 1: Init chunked upload */
    char init_body[128];
    snprintf(init_body, sizeof(init_body), "{\"total_size\":%lld}", (long long)file_size);

    char init_path[MAX_PATH_LEN];
    snprintf(init_path, sizeof(init_path), "%s/init", base_path);

    http_response_t resp;
    if (http_post_json(host, port, init_path, init_body, worker_key, &resp) < 0 ||
        resp.status != 200) {
        close(fd);
        garlic_log("[Garlic] Chunk init failed (status=%d)\n", resp.status);
        return -1;
    }

    char upload_id[128];
    if (json_get_string(resp.body, "upload_id", upload_id, sizeof(upload_id)) < 0) {
        close(fd);
        garlic_log("[Garlic] No upload_id in init response\n");
        return -1;
    }

    /* Step 2: Upload chunks */
    int total_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    char *chunk_buf = malloc(CHUNK_SIZE);
    if (!chunk_buf) {
        close(fd);
        return -1;
    }

    for (int i = 0; i < total_chunks; i++) {
        int chunk_len = CHUNK_SIZE;
        if ((int64_t)(i + 1) * CHUNK_SIZE > file_size)
            chunk_len = file_size - (int64_t)i * CHUNK_SIZE;

        /* Read chunk from file */
        lseek(fd, (off_t)i * CHUNK_SIZE, SEEK_SET);
        int total_read = 0;
        while (total_read < chunk_len) {
            ssize_t n = read(fd, chunk_buf + total_read, chunk_len - total_read);
            if (n <= 0) break;
            total_read += n;
        }
        if (total_read != chunk_len) {
            garlic_log("[Garlic] Short read on chunk %d\n", i);
            free(chunk_buf);
            close(fd);
            return -1;
        }

        char chunk_path[MAX_PATH_LEN];
        snprintf(chunk_path, sizeof(chunk_path), "%s/chunk/%d?upload_id=%s",
                 base_path, i, upload_id);

        /* Retry up to 3 times */
        int success = 0;
        for (int attempt = 0; attempt < 3; attempt++) {
            if (http_post_binary(host, port, chunk_path, chunk_buf, chunk_len,
                                 worker_key, &resp) == 0 && resp.status == 200) {
                success = 1;
                break;
            }
            garlic_log("[Garlic] Chunk %d/%d attempt %d failed, retrying...\n",
                   i + 1, total_chunks, attempt + 1);
            sleep(1 << attempt);
        }

        if (!success) {
            garlic_log("[Garlic] Chunk %d/%d failed after 3 attempts\n", i + 1, total_chunks);
            free(chunk_buf);
            close(fd);
            return -1;
        }
        garlic_log("[Garlic] Chunk %d/%d uploaded (%d bytes)\n", i + 1, total_chunks, chunk_len);
    }

    free(chunk_buf);
    close(fd);

    /* Step 3: Complete */
    char complete_path[MAX_PATH_LEN];
    snprintf(complete_path, sizeof(complete_path), "%s/complete", base_path);

    char complete_body[256];
    snprintf(complete_body, sizeof(complete_body), "{\"upload_id\":\"%s\"}", upload_id);

    if (http_post_json(host, port, complete_path, complete_body, worker_key, &resp) < 0 ||
        resp.status != 200) {
        garlic_log("[Garlic] Chunk complete failed (status=%d)\n", resp.status);
        return -1;
    }

    garlic_log("[Garlic] Chunked upload complete (%lld bytes, %d chunks)\n",
           (long long)file_size, total_chunks);
    return 0;
}
