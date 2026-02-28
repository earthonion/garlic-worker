#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

#define HTTP_BODY_MAX  65536
#define CHUNK_SIZE     (5 * 1024 * 1024)  /* 5MB chunks for upload */

typedef struct {
    int  status;
    char body[HTTP_BODY_MAX];
    int  body_len;
} http_response_t;

/* GET request, response body in memory */
int http_get(const char *host, int port, const char *path,
             const char *worker_key, http_response_t *resp);

/* POST JSON body, response body in memory */
int http_post_json(const char *host, int port, const char *path,
                   const char *json_body, const char *worker_key,
                   http_response_t *resp);

/* POST raw binary body from buffer */
int http_post_binary(const char *host, int port, const char *path,
                     const void *data, int data_len,
                     const char *worker_key, http_response_t *resp);

/* GET, stream response body to file. Returns HTTP status or -1 on error. */
int http_download_to_file(const char *host, int port, const char *path,
                          const char *worker_key, const char *dest_path);

/* Chunked file upload: init -> chunks -> complete. Returns 0 on success. */
int http_upload_file_chunked(const char *host, int port,
                             const char *base_path, const char *src_path,
                             const char *worker_key);

#endif
