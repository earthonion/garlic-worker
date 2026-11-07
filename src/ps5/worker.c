#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <ps5/kernel.h>

#include "worker.h"
#include "http.h"
#include "json.h"
#include "zip.h"
#include "tcp.h"
#include "savedata.h"
#include "util.h"
#include "log.h"

/* Which platform tag to send when asking /api/worker/update for our
 * replacement.  PS5 build handles both PS5-native and PS4 saves, so it
 * pulls the PS5 ELF. */
#define WORKER_PLATFORM "ps5"
#define UPDATE_TMP_PATH "/data/garlic-worker-update.elf"

/* Forward decl */
static void worker_self_update(worker_config_t *cfg);

/* Download the latest garlic-worker ELF from the server, pipe it into the
 * local elfldr on 127.0.0.1:9021, then SIGKILL ourselves. If any step
 * fails we log and return so the caller can back off and retry.
 *
 * The server-side gate returns HTTP 426 to any worker below
 * MIN_WORKER_VERSION; that's what triggers this path. */
static void worker_self_update(worker_config_t *cfg) {
    garlic_log("[Garlic] self_update: downloading /api/worker/update?platform=%s\n",
               WORKER_PLATFORM);

    char update_path[64];
    snprintf(update_path, sizeof(update_path),
             "/api/worker/update?platform=%s", WORKER_PLATFORM);

    unlink(UPDATE_TMP_PATH);
    int rc = http_download_to_file(cfg->server_host, cfg->server_port,
                                    update_path, cfg->worker_key,
                                    UPDATE_TMP_PATH);
    if (rc != 200) {
        garlic_log("[Garlic] self_update: download failed (rc=%d)\n", rc);
        return;
    }

    struct stat st;
    if (stat(UPDATE_TMP_PATH, &st) < 0 || st.st_size < 4096) {
        garlic_log("[Garlic] self_update: downloaded ELF too small (%lld)\n",
                   (long long)st.st_size);
        return;
    }

    /* Verify ELF magic before piping to elfldr — a gzip-compressed or
     * otherwise corrupt download must not kill the worker. */
    {
        int vfd = open(UPDATE_TMP_PATH, O_RDONLY);
        if (vfd < 0) { garlic_log("[Garlic] self_update: can't verify ELF\n"); return; }
        unsigned char magic[4];
        if (read(vfd, magic, 4) != 4 ||
            magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
            close(vfd);
            garlic_log("[Garlic] self_update: bad ELF magic (%02x %02x %02x %02x), "
                       "download likely gzip-corrupted\n",
                       magic[0], magic[1], magic[2], magic[3]);
            unlink(UPDATE_TMP_PATH);
            return;
        }
        close(vfd);
    }

    garlic_log("[Garlic] self_update: got %lld bytes, piping to elfldr\n",
               (long long)st.st_size);

    int sfd = http_tcp_connect("127.0.0.1", 9021);
    if (sfd < 0) {
        garlic_log("[Garlic] self_update: cannot connect to local elfldr\n");
        return;
    }
    int ffd = open(UPDATE_TMP_PATH, O_RDONLY);
    if (ffd < 0) {
        garlic_log("[Garlic] self_update: cannot re-open %s\n", UPDATE_TMP_PATH);
        close(sfd);
        return;
    }
    char buf[8192];
    ssize_t n;
    while ((n = read(ffd, buf, sizeof(buf))) > 0) {
        ssize_t w = 0;
        while (w < n) {
            ssize_t r = write(sfd, buf + w, n - w);
            if (r <= 0) {
                garlic_log("[Garlic] self_update: short write to elfldr\n");
                close(ffd); close(sfd);
                return;
            }
            w += r;
        }
    }
    close(ffd);
    close(sfd);
    unlink(UPDATE_TMP_PATH);

    /* Give elfldr a moment to spawn the replacement so it can bind to
     * anything we release on exit. */
    garlic_log("[Garlic] self_update: ELF sent, exiting old worker in 3s\n");
    log_flush();
    sleep(3);
    kill(getpid(), SIGKILL);
    /* unreached */
}

#define WORK_BASE      "/data/garlic/work"
/* PS4 and PS5 save files use different param.sfo key tables, so the
 * ACCOUNT_ID byte offset differs. Pick by save type at patch time. */
#define SFO_AID_OFFSET     0x1B8  /* default: PS5 param.sfo */
#define SFO_AID_OFFSET_PS5 0x1B8
#define SFO_AID_OFFSET_PS4 0x15C
#define KEYSTONE_SIZE  0x400

static int account_id_to_sfo_bytes(const char *hex, uint8_t out[8]) {
    uint8_t be[8];
    if (hex_to_bytes(hex, be, 8) != 8) return -1;
    for (int i = 0; i < 8; i++) out[i] = be[7 - i];
    return 0;
}

/* ── Transport mode (0=HTTP, 1=TCP) ────────────────────────────── */

static int g_transport_mode = 0;
static tcp_conn_t *g_tcp = NULL;

/* ── Worker API helpers ────────────────────────────────────────── */

static char g_last_error[2048];

static void worker_log(worker_config_t *cfg, const char *job_id,
                       const char *level, const char *msg) {
    if (strcmp(level, "ERROR") == 0)
        snprintf(g_last_error, sizeof(g_last_error), "%s", msg);

    if (g_transport_mode == 1 && g_tcp) {
        char body[4096];
        snprintf(body, sizeof(body),
            "{\"type\":\"log\",\"job_id\":\"%s\",\"level\":\"%s\",\"msg\":\"%s\"}",
            job_id, level, msg);
        tcp_send_msg(g_tcp, body);
    } else {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "/api/worker/jobs/%s/log", job_id);
        char body[4096];
        snprintf(body, sizeof(body), "{\"level\":\"%s\",\"msg\":\"%s\"}", level, msg);
        http_response_t resp;
        http_post_json(cfg->server_host, cfg->server_port, path, body, cfg->worker_key, &resp);
    }
}

static void worker_logf(worker_config_t *cfg, const char *job_id,
                        const char *level, const char *fmt, ...) {
    char msg[2048];
    va_list a;
    va_start(a, fmt);
    vsnprintf(msg, sizeof(msg), fmt, a);
    va_end(a);
    worker_log(cfg, job_id, level, msg);
}

static void worker_set_status(worker_config_t *cfg, const char *job_id,
                              const char *status, const char *error) {
    if (g_transport_mode == 1 && g_tcp) {
        char body[4096];
        if (error)
            snprintf(body, sizeof(body),
                "{\"type\":\"status\",\"job_id\":\"%s\",\"status\":\"%s\",\"error\":\"%s\"}",
                job_id, status, error);
        else
            snprintf(body, sizeof(body),
                "{\"type\":\"status\",\"job_id\":\"%s\",\"status\":\"%s\"}",
                job_id, status);
        tcp_send_msg(g_tcp, body);
    } else {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "/api/worker/jobs/%s/status", job_id);
        char body[4096];
        if (error)
            snprintf(body, sizeof(body), "{\"status\":\"%s\",\"error\":\"%s\"}", status, error);
        else
            snprintf(body, sizeof(body), "{\"status\":\"%s\"}", status);
        http_response_t resp;
        http_post_json(cfg->server_host, cfg->server_port, path, body, cfg->worker_key, &resp);
    }
}

static int is_ps5_sidecar(const char *name) {
    return strcmp(name, "PS5PARAM") == 0 || strcmp(name, "PS5PARAM_SIZE") == 0 ||
           strcmp(name, "PS5KEY") == 0 || strcmp(name, "PS5IMAGE") == 0;
}

static int flatten_single_save_directory(const char *files_dir) {
    for (;;) {
        DIR *root = opendir(files_dir);
        if (!root) return -1;
        char only[MAX_PATH_LEN] = {0};
        int entries = 0;
        struct dirent *ent;
        while ((ent = readdir(root))) {
            if (ent->d_name[0] == '.' || is_ps5_sidecar(ent->d_name)) continue;
            entries++;
            snprintf(only, sizeof(only), "%s", ent->d_name);
        }
        closedir(root);
        if (entries != 1) return 0;

        char nested[MAX_PATH_LEN];
        snprintf(nested, sizeof(nested), "%s/%s", files_dir, only);
        struct stat st;
        if (stat(nested, &st) < 0 || !S_ISDIR(st.st_mode)) return 0;

        DIR *sub = opendir(nested);
        if (!sub) return -1;
        while ((ent = readdir(sub))) {
            if (ent->d_name[0] == '.') continue;
            char src[MAX_PATH_LEN], dst[MAX_PATH_LEN];
            snprintf(src, sizeof(src), "%s/%s", nested, ent->d_name);
            snprintf(dst, sizeof(dst), "%s/%s", files_dir, ent->d_name);
            if (rename(src, dst) < 0) {
                closedir(sub);
                return -1;
            }
        }
        closedir(sub);
        if (rmdir(nested) < 0) return -1;
    }
}

static int worker_download_files(worker_config_t *cfg, const char *job_id,
                                 const char *work_dir) {
    char zip_path[MAX_PATH_LEN];
    snprintf(zip_path, sizeof(zip_path), "%s/files.zip", work_dir);

    if (g_transport_mode == 1 && g_tcp) {
        char req[256];
        snprintf(req, sizeof(req), "{\"type\":\"file_request\",\"job_id\":\"%s\"}", job_id);
        if (tcp_send_msg(g_tcp, req) < 0) {
            garlic_log("[TCP] Failed to send file_request\n");
            return -1;
        }

        char resp_buf[4096];
        if (tcp_recv_msg(g_tcp, resp_buf, sizeof(resp_buf)) < 0) {
            garlic_log("[TCP] Failed to receive file_data header\n");
            return -1;
        }

        int64_t file_size = 0;
        json_get_int64(resp_buf, "size", &file_size);
        if (file_size <= 0) {
            garlic_log("[TCP] Server sent empty file (size=%lld)\n", (long long)file_size);
            return -1;
        }

        int fd = open(zip_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) return -1;
        if (tcp_recv_to_file(g_tcp, fd, file_size) < 0) {
            close(fd);
            garlic_log("[TCP] Failed to receive file data\n");
            return -1;
        }
        close(fd);
        garlic_log("[TCP] Downloaded %lld bytes\n", (long long)file_size);
    } else {
        char url[MAX_PATH_LEN];
        snprintf(url, sizeof(url), "/api/worker/jobs/%s/files", job_id);

        int status = http_download_to_file(cfg->server_host, cfg->server_port,
                                           url, cfg->worker_key, zip_path);
        if (status != 200) {
            garlic_log("[Garlic] Download files failed (status=%d)\n", status);
            return -1;
        }
    }

    char files_dir[MAX_PATH_LEN];
    snprintf(files_dir, sizeof(files_dir), "%s/files", work_dir);
    mkdir(files_dir, 0777);

    int count = zip_extract_file(zip_path, files_dir);
    if (count <= 0) {
        garlic_log("[Garlic] No files extracted from ZIP\n");
        return -1;
    }

    if (flatten_single_save_directory(files_dir) < 0) {
        garlic_log("[Garlic] Failed to flatten enclosing save directory\n");
        return -1;
    }
    garlic_log("[Garlic] Downloaded and extracted %d files\n", count);
    return 0;
}

static int worker_upload_result(worker_config_t *cfg, const char *job_id,
                                const char *zip_path) {
    if (g_transport_mode == 1 && g_tcp) {
        struct stat st;
        if (stat(zip_path, &st) < 0) return -1;

        char msg[512];
        snprintf(msg, sizeof(msg),
            "{\"type\":\"result_start\",\"job_id\":\"%s\",\"size\":%lld}",
            job_id, (long long)st.st_size);
        if (tcp_send_msg(g_tcp, msg) < 0) return -1;
        if (tcp_send_file(g_tcp, zip_path) < 0) return -1;

        char resp_buf[4096];
        if (tcp_recv_msg(g_tcp, resp_buf, sizeof(resp_buf)) < 0) return -1;

        garlic_log("[TCP] Upload complete (%lld bytes)\n", (long long)st.st_size);
        return 0;
    } else {
        char base_path[MAX_PATH_LEN];
        snprintf(base_path, sizeof(base_path), "/api/worker/jobs/%s/result", job_id);
        return http_upload_file_chunked(cfg->server_host, cfg->server_port,
                                        base_path, zip_path, cfg->worker_key);
    }
}

/* ── Copy all files from a mounted save to result dir ──────────── */
static int copy_mounted_to_result(const char *result_dir, const char *save_name,
                                  int include_sce_sys) {
    const char *mnt = save_get_mount_point();
    char dest[MAX_PATH_LEN];
    snprintf(dest, sizeof(dest), "%s/%s", result_dir, save_name);
    mkdir(dest, 0777);

    DIR *d = opendir(mnt);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        if (!include_sce_sys && strcmp(ent->d_name, "sce_sys") == 0) continue;

        char src_path[MAX_PATH_LEN], dst_path[MAX_PATH_LEN];
        snprintf(src_path, sizeof(src_path), "%s/%s", mnt, ent->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dest, ent->d_name);

        struct stat st;
        if (stat(src_path, &st) < 0) continue;
        if (S_ISDIR(st.st_mode))
            copy_dir_recursive(src_path, dst_path);
        else
            copy_file(src_path, dst_path);
    }
    closedir(d);
    return 0;
}

/* ── Find save files in extracted directory ────────────────────── */
/* PS5 saves are single files (often named `<base>.bin` — the .bin IS the
 * image). PS4 saves come as image + companion `<base>.bin` (sealed key,
 * exactly 96 bytes). Only skip a `.bin` if a non-.bin sibling with the
 * same base also exists in the same dir (true PS4 companion) — otherwise
 * keep it (it's a standalone PS5 image). */
static int find_save_files(const char *dir, char saves[][MAX_PATH_LEN], int max) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) && count < max) {
        if (ent->d_name[0] == '.') continue;

        size_t nlen = strlen(ent->d_name);
        if (nlen >= 4 && strcmp(ent->d_name + nlen - 4, ".bin") == 0) {
            /* Possible PS4 sealed-key companion: skip only if the matching
             * non-.bin sibling also exists at the same level. */
            char sibling[MAX_PATH_LEN];
            int blen = (int)nlen - 4;
            if (blen > 0 && blen < (int)sizeof(sibling)) {
                snprintf(sibling, sizeof(sibling), "%s/%.*s", dir, blen, ent->d_name);
                struct stat sst;
                if (stat(sibling, &sst) == 0 && S_ISREG(sst.st_mode)) {
                    continue;  /* PS4 companion — let save_mount handle the .bin */
                }
            }
            /* Sealed-key files are exactly 96 bytes on PS4; if the .bin is
             * tiny without a sibling, still skip it (corrupted upload). */
            char selfpath[MAX_PATH_LEN];
            snprintf(selfpath, sizeof(selfpath), "%s/%s", dir, ent->d_name);
            struct stat est;
            if (stat(selfpath, &est) == 0 && est.st_size <= 4096) continue;
        }

        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            snprintf(saves[count], MAX_PATH_LEN, "%s", path);
            count++;
        }
    }
    closedir(d);
    return count;
}

/* Find the PS4 sealed-key companion for an image. Real PS4 naming has
 * different basenames (image=`sdimg_<savename>`, key=`<savename>.bin`),
 * and HTOS may rename the image, so we can't assume <image>.bin. Strategy:
 *   1. Try <image>.bin (same-base — works for some uploads)
 *   2. Try stripping `sdimg_` from image stem + .bin (real PS4 hw)
 *   3. Fall back to scanning the dir for any small (<=4KB) .bin file,
 *      preferring one whose stem is a suffix of the image stem.
 * Returns 0 + writes path to `out` on success, -1 if none found. */
static int find_ps4_companion_bin(const char *image_path, char *out, size_t out_sz) {
    /* Step 1: <image>.bin */
    snprintf(out, out_sz, "%s.bin", image_path);
    if (access(out, R_OK) == 0) return 0;

    /* Decompose into dir + basename */
    char dir[MAX_PATH_LEN], base[MAX_PATH_LEN];
    strncpy(dir, image_path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = 0;
    char *sl = strrchr(dir, '/');
    if (sl) { *sl = 0; strncpy(base, sl + 1, sizeof(base) - 1); base[sizeof(base) - 1] = 0; }
    else { strncpy(base, dir, sizeof(base) - 1); base[sizeof(base) - 1] = 0; dir[0] = '.'; dir[1] = 0; }

    /* Step 2: strip sdimg_ prefix if present (real PS4 naming) */
    const char *stem = base;
    if (strncmp(stem, "sdimg_", 6) == 0) stem += 6;
    if (stem != base) {
        snprintf(out, out_sz, "%s/%s.bin", dir, stem);
        if (access(out, R_OK) == 0) return 0;
    }

    /* Step 3: scan dir for any small .bin (<=4KB; PS4 sealed key is 96 bytes).
     * Prefer one whose stem is a suffix of the image stem. */
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    char fallback[MAX_PATH_LEN] = {0};
    while ((e = readdir(d))) {
        size_t nl = strlen(e->d_name);
        if (nl < 5 || strcmp(e->d_name + nl - 4, ".bin") != 0) continue;
        char full[MAX_PATH_LEN];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (st.st_size == 0 || st.st_size > 4096) continue;

        /* Prefer matches: stem of this .bin is a suffix of image's stem */
        char bin_stem[MAX_PATH_LEN];
        snprintf(bin_stem, sizeof(bin_stem), "%.*s", (int)(nl - 4), e->d_name);
        size_t bs = strlen(bin_stem), is = strlen(stem);
        if (bs <= is && strcmp(stem + is - bs, bin_stem) == 0) {
            snprintf(out, out_sz, "%s", full);
            closedir(d);
            return 0;
        }
        /* Otherwise remember this as a fallback */
        if (!fallback[0]) snprintf(fallback, sizeof(fallback), "%s", full);
    }
    closedir(d);
    if (fallback[0]) {
        snprintf(out, out_sz, "%s", fallback);
        return 0;
    }
    return -1;
}

/* Copy a save image to /data/save_files/<dst_name>. For PS4 saves
 * (image header byte 0 == 0x01), also copy the companion sealed-key .bin
 * to <data_path>.bin. Returns 0 on success, -1 on copy failure. */
static int stage_save_to_data(const char *src_path, const char *data_path) {
    if (copy_file(src_path, data_path) < 0) return -1;

    /* If image is PS4, also stage the companion .bin */
    int hfd = open(src_path, O_RDONLY);
    if (hfd < 0) {
        garlic_log("[Garlic] PS4 stage: cannot re-open %s (errno %d)\n", src_path, errno);
        return -1;
    }
    uint8_t hdr = 0;
    int n = pread(hfd, &hdr, 1, 0);
    close(hfd);
    if (n != 1 || hdr != 0x01) return 0;  /* not PS4 — image-only is fine */

    char src_bin[MAX_PATH_LEN], dst_bin[MAX_PATH_LEN];
    if (find_ps4_companion_bin(src_path, src_bin, sizeof(src_bin)) < 0) {
        garlic_log("[Garlic] PS4 stage: no companion .bin found in dir of %s\n", src_path);
        return -1;
    }
    snprintf(dst_bin, sizeof(dst_bin), "%s.bin", data_path);
    if (copy_file(src_bin, dst_bin) < 0) {
        garlic_log("[Garlic] PS4 stage: copy %s -> %s failed (errno %d)\n",
                   src_bin, dst_bin, errno);
        return -1;
    }
    chmod(dst_bin, 0755);
    garlic_log("[Garlic] PS4 stage: copied sealed key %s -> %s\n", src_bin, dst_bin);
    return 0;
}

/* ── Job Processors ────────────────────────────────────────────── */

static pid_t ncdt_find_pid(const char *name) {
    int mib[4] = {1, 14, 8, 0};
    size_t size;
    if (sysctl(mib, 4, NULL, &size, NULL, 0)) return -1;
    unsigned char *buf = malloc(size);
    if (sysctl(mib, 4, buf, &size, NULL, 0)) {
        free(buf);
        return -1;
    }
    pid_t pid = -1;
    for (unsigned char *p = buf; p < buf + size;) {
        int len = *(int *)p;
        if (len <= 0) break;
        if (!strcmp((char *)(p + 447), name)) {
            pid = *(pid_t *)(p + 72);
            break;
        }
        p += len;
    }
    free(buf);
    return pid;
}

static int process_ppr_derive(worker_config_t *cfg, const char *job_id,
                              const char *params, const char *work_dir) {
    char client_hex[33] = {0}, server_hex[33] = {0};
    json_get_string(params, "client_value", client_hex, sizeof(client_hex));
    json_get_string(params, "server_value", server_hex, sizeof(server_hex));

    uint8_t request[0x4c] = {0};
    if (strlen(client_hex) != 32 || strlen(server_hex) != 32 ||
        hex_to_bytes(client_hex, request, 16) != 16 ||
        hex_to_bytes(server_hex, request + 16, 16) != 16) {
        worker_log(cfg, job_id, "ERROR", "client_value and server_value must be 16 bytes of hex");
        return -1;
    }

    pid_t shellcore = ncdt_find_pid("SceShellCore");
    pid_t self = getpid();
    if (shellcore < 0) {
        worker_log(cfg, job_id, "ERROR", "SceShellCore not found");
        return -1;
    }
    uint8_t caps[16], attrs[32];
    uint64_t authid = kernel_get_ucred_authid(shellcore);
    kernel_get_ucred_caps(shellcore, caps);
    kernel_get_ucred_attrs(shellcore, attrs);
    kernel_set_ucred_authid(self, authid);
    kernel_set_ucred_caps(self, caps);
    kernel_set_ucred_attrs(self, attrs);

    int device = open("/dev/ncdt", O_RDWR);
    if (device < 0) {
        worker_log(cfg, job_id, "ERROR", "Cannot open /dev/ncdt");
        return -1;
    }
    int result = ioctl(device, 0xc04c4e03, request);
    uint32_t status = *(uint32_t *)(request + 0x48);
    close(device);
    if (result != 0 || status != 0) {
        worker_logf(cfg, job_id, "ERROR", "PPR ioctl failed: result=%d status=0x%x", result, status);
        return -1;
    }

    char result_dir[MAX_PATH_LEN];
    snprintf(result_dir, sizeof(result_dir), "%s/result", work_dir);
    mkdir(result_dir, 0777);
    char json_path[MAX_PATH_LEN];
    snprintf(json_path, sizeof(json_path), "%s/ppr.json", result_dir);
    int fd = open(json_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        worker_log(cfg, job_id, "ERROR", "Cannot create PPR result");
        return -1;
    }
    char output[512];
    int output_len = snprintf(output, sizeof(output),
        "{\"key1\":\"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\","
        "\"key2\":\"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\","
        "\"nonce1\":\"%02x%02x%02x%02x\",\"nonce2\":\"%02x%02x%02x%02x\"}\n",
        request[0x20], request[0x21], request[0x22], request[0x23],
        request[0x24], request[0x25], request[0x26], request[0x27],
        request[0x28], request[0x29], request[0x2a], request[0x2b],
        request[0x2c], request[0x2d], request[0x2e], request[0x2f],
        request[0x30], request[0x31], request[0x32], request[0x33],
        request[0x34], request[0x35], request[0x36], request[0x37],
        request[0x38], request[0x39], request[0x3a], request[0x3b],
        request[0x3c], request[0x3d], request[0x3e], request[0x3f],
        request[0x40], request[0x41], request[0x42], request[0x43],
        request[0x44], request[0x45], request[0x46], request[0x47]);
    write(fd, output, output_len);
    close(fd);

    if (worker_upload_result(cfg, job_id, json_path) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to upload PPR result");
        return -1;
    }
    worker_log(cfg, job_id, "INFO", "PPR derivation complete");
    return 0;
}

static int process_decrypt(worker_config_t *cfg, const char *job_id,
                           const char *params, const char *work_dir) {
    worker_log(cfg, job_id, "INFO", "Downloading files...");
    if (worker_download_files(cfg, job_id, work_dir) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to download files");
        return -1;
    }

    int include_sce_sys = 0;
    json_get_bool(params, "include_sce_sys", &include_sce_sys);

    char files_dir[MAX_PATH_LEN];
    snprintf(files_dir, sizeof(files_dir), "%s/files", work_dir);
    char result_dir[MAX_PATH_LEN];
    snprintf(result_dir, sizeof(result_dir), "%s/result", work_dir);
    mkdir(result_dir, 0777);

    /* Find save files without exhausting the worker thread's stack. */
    static char saves[64][MAX_PATH_LEN];
    int save_count = find_save_files(files_dir, saves, 64);
    if (save_count == 0) {
        worker_log(cfg, job_id, "ERROR", "No save files found");
        return -1;
    }
    {
        /* Log what we picked up so users can see if a file got dropped */
        DIR *_d = opendir(files_dir);
        if (_d) {
            char picked[1024] = {0}, all[1024] = {0};
            struct dirent *e;
            for (int i = 0; i < save_count && strlen(picked) < sizeof(picked) - 64; i++) {
                const char *b = strrchr(saves[i], '/');
                b = b ? b + 1 : saves[i];
                snprintf(picked + strlen(picked), sizeof(picked) - strlen(picked),
                         "%s%s", picked[0] ? "," : "", b);
            }
            while ((e = readdir(_d)) && strlen(all) < sizeof(all) - 64) {
                if (e->d_name[0] == '.') continue;
                snprintf(all + strlen(all), sizeof(all) - strlen(all),
                         "%s%s", all[0] ? "," : "", e->d_name);
            }
            closedir(_d);
            worker_logf(cfg, job_id, "INFO",
                "Files: [%s], mounting: [%s]", all, picked);
        }
    }

    int processed = 0;
    for (int i = 0; i < save_count; i++) {
        const char *save_path = saves[i];
        const char *basename = strrchr(save_path, '/');
        basename = basename ? basename + 1 : save_path;

        worker_logf(cfg, job_id, "INFO", "Decrypting %s (%d/%d)...",
                    basename, i + 1, save_count);

        /* Copy to /data/ for mount */
        char data_path[MAX_PATH_LEN];
        snprintf(data_path, sizeof(data_path), "/data/save_files/_work_%s", basename);
        if (stage_save_to_data(save_path, data_path) < 0) {
            worker_logf(cfg, job_id, "WARNING", "Failed to stage %s", basename);
            continue;
        }

        /* PS5: capture real param.sfo from encrypted header blob before mount */
        if (!detect_is_ps4(data_path))
            ps5param_capture_for_image(data_path);

        int mret = save_mount(data_path);
        if (mret < 0) {
            if (mret == SAVE_ERR_CORRUPTED)
                worker_log(cfg, job_id, "ERROR", "Corrupted save! Is your FTP server set to binary mode?");
            else
                worker_logf(cfg, job_id, "WARNING",
                            "Failed to mount %s (rc=%d)", basename, mret);
            unlink(data_path);
            continue;
        }

        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo",
                 save_get_mount_point());
        if (sfo_all_zero_file(sfo_path)) {
            char sidecar[MAX_PATH_LEN];
            snprintf(sidecar, sizeof(sidecar), "%s/PS5PARAM", result_dir);
            if (ps5param_export_blob(data_path, sidecar) < 0) {
                worker_logf(cfg, job_id, "WARNING",
                            "Zeroed SFO has no PS5PARAM blob for %s", basename);
                save_unmount();
                unlink(data_path);
                continue;
            }
            struct stat image_st;
            if (stat(data_path, &image_st) == 0) {
                char size_path[MAX_PATH_LEN];
                snprintf(size_path, sizeof(size_path), "%s/PS5PARAM_SIZE", result_dir);
                int sfd = open(size_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                if (sfd >= 0) {
                    char size_text[32];
                    int size_len = snprintf(size_text, sizeof(size_text), "%llu",
                                            (unsigned long long)image_st.st_size);
                    write(sfd, size_text, size_len);
                    close(sfd);
                }
            }

            uint8_t key_data[0x100] = {0};
            int key_image = open(data_path, O_RDONLY);
            if (key_image >= 0 && pread(key_image, key_data, 0x60, 0x800) == 0x60) {
                int pfsmgr = open("/dev/pfsmgr", O_RDWR);
                if (pfsmgr >= 0) {
                    if (ioctl(pfsmgr, 0xc0845302, key_data) >= 0) {
                        char key_path[MAX_PATH_LEN];
                        snprintf(key_path, sizeof(key_path), "%s/PS5KEY", result_dir);
                        int out = open(key_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
                        if (out >= 0) {
                            write(out, key_data + 0x60, 0x20);
                            close(out);
                        }
                    }
                    close(pfsmgr);
                }
            }
            if (key_image >= 0) close(key_image);
            char original_image[MAX_PATH_LEN];
            snprintf(original_image, sizeof(original_image), "%s/PS5IMAGE", result_dir);
            if (copy_file(data_path, original_image) < 0) {
                worker_log(cfg, job_id, "ERROR", "Failed to preserve original PFS image");
                save_unmount();
                unlink(data_path);
                return -1;
            }
        }
        copy_mounted_to_result(result_dir, basename, include_sce_sys);
        save_unmount();
        unlink(data_path);
        processed++;
    }

    if (processed == 0) {
        worker_log(cfg, job_id, "ERROR", "No saves could be decrypted");
        return -1;
    }

    /* Zip and upload */
    worker_log(cfg, job_id, "INFO", "Uploading result...");
    char result_zip[MAX_PATH_LEN];
    snprintf(result_zip, sizeof(result_zip), "%s/result.zip", work_dir);
    if (zip_create_from_dir(result_dir, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to create result ZIP");
        return -1;
    }
    if (worker_upload_result(cfg, job_id, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to upload result");
        return -1;
    }

    worker_logf(cfg, job_id, "INFO", "Decrypted %d save(s)", processed);
    return 0;
}

static int sfo_format_is_ps4(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    static uint8_t buf[0x8000];
    ssize_t size = read(fd, buf, sizeof(buf));
    close(fd);
    if (size < 20 || buf[0] != 0 || buf[1] != 'P' || buf[2] != 'S' || buf[3] != 'F') return -1;
    uint32_t key_off, data_off, count;
    memcpy(&key_off, buf + 8, 4);
    memcpy(&data_off, buf + 12, 4);
    memcpy(&count, buf + 16, 4);
    for (uint32_t i = 0; i < count && 20 + (i + 1) * 16 <= (uint32_t)size; i++) {
        uint16_t key_rel, format;
        uint32_t data_rel;
        memcpy(&key_rel, buf + 20 + i * 16, 2);
        memcpy(&format, buf + 20 + i * 16 + 2, 2);
        memcpy(&data_rel, buf + 20 + i * 16 + 12, 4);
        if (format != 0x0204 || key_off + key_rel >= (uint32_t)size ||
            data_off + data_rel >= (uint32_t)size) continue;
        if (strcmp((char *)buf + key_off + key_rel, "FORMAT") != 0) continue;
        const char *value = (char *)buf + data_off + data_rel;
        if (strcmp(value, "obs") == 0) return 1;
        if (strcmp(value, "ppr") == 0) return 0;
    }
    return -1;
}

static int detect_upload_is_ps4(const char *files_dir) {
    char image_path[MAX_PATH_LEN];
    snprintf(image_path, sizeof(image_path), "%s/PS5IMAGE", files_dir);
    struct stat st;
    if (stat(image_path, &st) == 0) return detect_is_ps4(image_path);
    char sfo_path[MAX_PATH_LEN];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", files_dir);
    return sfo_format_is_ps4(sfo_path);
}

static int validate_copied_files(const char *src, const char *dst,
                                 const char *src_base, const char *dst_base,
                                 int preserve_sce_sys) {
    DIR *d = opendir(src);
    if (!d) return -1;
    int result = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.' || is_ps5_sidecar(ent->d_name)) continue;
        char sp[MAX_PATH_LEN], dp[MAX_PATH_LEN];
        snprintf(sp, sizeof(sp), "%s/%s", src, ent->d_name);
        snprintf(dp, sizeof(dp), "%s/%s", dst, ent->d_name);
        const char *relpath = sp + strlen(src_base);
        if (*relpath == '/') relpath++;
        if (preserve_sce_sys && strncmp(relpath, "sce_sys", 7) == 0 &&
            (relpath[7] == '/' || relpath[7] == '\0')) continue;
        struct stat source_st, dest_st;
        if (stat(sp, &source_st) < 0) {
            result = -1;
            break;
        }
        if (stat(dp, &dest_st) < 0 ||
            (S_ISDIR(source_st.st_mode) != S_ISDIR(dest_st.st_mode)) ||
            (!S_ISDIR(source_st.st_mode) && source_st.st_size != dest_st.st_size)) {
            result = -1;
            break;
        }
        if (S_ISDIR(source_st.st_mode) &&
            validate_copied_files(sp, dp, src_base, dst_base, preserve_sce_sys) < 0) {
            result = -1;
            break;
        }
    }
    closedir(d);
    return result;
}

static int process_encrypt(worker_config_t *cfg, const char *job_id,
                           const char *params, const char *work_dir,
                           int is_ps4_job) {
    worker_log(cfg, job_id, "INFO", "Downloading files...");
    if (worker_download_files(cfg, job_id, work_dir) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to download files");
        return -1;
    }

    char savename[256] = {0};
    int saveblocks = 0;
    char account_id[64] = {0};
    json_get_string(params, "savename", savename, sizeof(savename));
    json_get_int(params, "saveblocks", &saveblocks);
    json_get_string(params, "account_id", account_id, sizeof(account_id));

    if (!savename[0]) {
        snprintf(savename, sizeof(savename), "save_%s", job_id);
    }

    char files_dir[MAX_PATH_LEN];
    snprintf(files_dir, sizeof(files_dir), "%s/files", work_dir);

    int detected_ps4 = detect_upload_is_ps4(files_dir);
    if (detected_ps4 >= 0 && detected_ps4 != is_ps4_job) {
        worker_logf(cfg, job_id, "INFO", "Using %s container format from save metadata",
                    detected_ps4 ? "PS4" : "PS5");
        is_ps4_job = detected_ps4;
    }

    /* If saveblocks wasn't in job params, try reading from extracted param.sfo */
    if (saveblocks <= 0) {
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", files_dir);
        saveblocks = sfo_read_savedata_blocks(sfo_path);
    }

    uint64_t data_size;
    if (saveblocks > 0) {
        data_size = (uint64_t)saveblocks * 65536;
    } else {
        /* No SAVEDATA_BLOCKS — estimate from file sizes */
        data_size = 0;
        DIR *d = opendir(files_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d))) {
                if (ent->d_name[0] == '.') continue;
                char fp[MAX_PATH_LEN];
                snprintf(fp, sizeof(fp), "%s/%s", files_dir, ent->d_name);
                struct stat st;
                if (stat(fp, &st) == 0) data_size += st.st_size;
            }
            closedir(d);
        }
        if (data_size < 32 * 1024 * 1024) data_size = 32 * 1024 * 1024;
    }

    char img_path[MAX_PATH_LEN];
    snprintf(img_path, sizeof(img_path), "/data/save_files/_work_%s", savename);
    uint8_t original_key[0x20] = {0};
    int has_original_key = 0;
    {
        char key_path[MAX_PATH_LEN];
        snprintf(key_path, sizeof(key_path), "%s/PS5KEY", files_dir);
        int kfd = open(key_path, O_RDONLY);
        if (kfd >= 0) {
            ssize_t nr = read(kfd, original_key, sizeof(original_key));
            close(kfd);
            has_original_key = nr == (ssize_t)sizeof(original_key);
        }
        unlink(key_path);
    }

    int preserve_sidecar = 0;
    char sidecar[MAX_PATH_LEN];
    snprintf(sidecar, sizeof(sidecar), "%s/PS5PARAM", files_dir);
    char saved_sidecar[MAX_PATH_LEN];
    snprintf(saved_sidecar, sizeof(saved_sidecar), "%s/PS5PARAM.sidecar", work_dir);
    struct stat sidecar_st;
    int has_sidecar = stat(sidecar, &sidecar_st) == 0 && sidecar_st.st_size == 0x8000;
    if (has_sidecar && !has_original_key) {
        worker_log(cfg, job_id, "ERROR", "PS5PARAM preservation requires the original PS5KEY");
        return -1;
    }
    uint64_t original_size = 0;
    {
        char size_path[MAX_PATH_LEN];
        snprintf(size_path, sizeof(size_path), "%s/PS5PARAM_SIZE", files_dir);
        int sfd = open(size_path, O_RDONLY);
        if (sfd >= 0) {
            char size_text[32] = {0};
            ssize_t nr = read(sfd, size_text, sizeof(size_text) - 1);
            close(sfd);
            if (nr > 0) original_size = strtoull(size_text, NULL, 10);
        }
        if (original_size >= 0x10000 && original_size <= (1ULL << 40))
            data_size = original_size;
        unlink(size_path);
    }

    char original_image[MAX_PATH_LEN];
    snprintf(original_image, sizeof(original_image), "%s/PS5IMAGE", files_dir);
    struct stat original_st;
    int use_original = !is_ps4_job && has_original_key && original_size > 0 &&
        stat(original_image, &original_st) == 0 &&
        (uint64_t)original_st.st_size == original_size;

    if (use_original) {
        worker_log(cfg, job_id, "INFO", "Reusing original PS5 PFS image...");
        if (copy_file(original_image, img_path) < 0 ||
            save_mount_new(img_path, original_key) < 0) {
            worker_log(cfg, job_id, "ERROR", "Failed to mount original PFS image");
            unlink(img_path);
            return -1;
        }
        ps5param_capture_for_image(img_path);
    } else {
        worker_logf(cfg, job_id, "INFO", "Creating %s PFS image (%llu bytes)...",
                    is_ps4_job ? "PS4" : "PS5", (unsigned long long)data_size);
        if (is_ps4_job) {
            if (save_create_pfs_ps4(img_path, data_size) < 0) {
                worker_log(cfg, job_id, "ERROR", "Failed to create PS4 PFS image");
                return -1;
            }
            if (save_mount_new_ps4(img_path) < 0) {
                worker_log(cfg, job_id, "ERROR", "Failed to mount new PS4 PFS");
                unlink(img_path);
                char bin[MAX_PATH_LEN]; snprintf(bin, sizeof(bin), "%s.bin", img_path); unlink(bin);
                return -1;
            }
        } else {
            if (save_create_pfs(img_path, data_size, saveblocks > 0) < 0) {
                worker_log(cfg, job_id, "ERROR", "Failed to create PFS image");
                return -1;
            }
            if (save_mount_new(img_path, original_key) < 0) {
                worker_log(cfg, job_id, "ERROR", "Failed to mount new PFS");
                unlink(img_path);
                return -1;
            }
        }
    }
    unlink(original_image);

    /* Copy files into mounted PFS. Fail loudly if any file copy errors:
     * silent ENOSPC in the middle of copy_dir_recursive was the source of
     * the "encrypt appears to succeed but decrypt is missing files" bug. */
    worker_log(cfg, job_id, "INFO", "Copying files into PFS...");
    const char *mnt = save_get_mount_point();
    if (has_sidecar && rename(sidecar, saved_sidecar) < 0) {
        save_unmount();
        return -1;
    }
    char uploaded_sfo[MAX_PATH_LEN];
    snprintf(uploaded_sfo, sizeof(uploaded_sfo), "%s/sce_sys/param.sfo", files_dir);
    int upload_zero_sfo = sfo_all_zero_file(uploaded_sfo);
    if (upload_zero_sfo && (!has_sidecar || !use_original)) {
        worker_log(cfg, job_id, "ERROR",
                   "Zeroed param.sfo requires a compatible original image, PS5PARAM blob and PS5KEY");
        save_unmount();
        return -1;
    }
    preserve_sidecar = use_original && has_sidecar && upload_zero_sfo;
    int copy_result;
    if (!is_ps4_job) {
        copy_result = copy_dir_recursive(files_dir, mnt);
    } else if (use_original && !upload_zero_sfo) {
        copy_result = copy_dir_pfs_preserve_sce_sys(files_dir, mnt);
    } else {
        copy_result = copy_dir_pfs(files_dir, mnt);
    }
    if (copy_result < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to copy files into PFS (out of space?)");
        save_unmount();
        return -1;
    }
    sync();

    {
        int preserve_sce_sys = is_ps4_job && use_original && !upload_zero_sfo;
        if (validate_copied_files(files_dir, mnt, files_dir, mnt, preserve_sce_sys) < 0) {
            worker_log(cfg, job_id, "ERROR", "PFS payload validation failed: a copied file is missing or truncated");
            save_unmount();
            return -1;
        }
    }

    if (account_id[0] && !upload_zero_sfo) preserve_sidecar = 0;
    /* Patch account ID if provided */
    if (account_id[0] && !preserve_sidecar) {
        uint8_t new_aid[8];
        if (account_id_to_sfo_bytes(account_id, new_aid) == 0) {
            char sfo_path[MAX_PATH_LEN];
            snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", mnt);
            int sfo_fd = open(sfo_path, O_RDWR);
            if (sfo_fd >= 0) {
                pwrite(sfo_fd, new_aid, 8, is_ps4_job ? SFO_AID_OFFSET_PS4 : SFO_AID_OFFSET_PS5);
                close(sfo_fd);
                sync();
                worker_logf(cfg, job_id, "INFO", "Patched account ID (%02x%02x%02x%02x%02x%02x%02x%02x)",
                            new_aid[0], new_aid[1], new_aid[2], new_aid[3],
                            new_aid[4], new_aid[5], new_aid[6], new_aid[7]);
            }
        }
    }

    /* PS5: capture the final SFO (with any account patch) for the blob */
    uint8_t enc_sfo[0x8000];
    uint32_t enc_sfo_len = 0;
    if (!is_ps4_job) {
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", mnt);
        int rfd = open(sfo_path, O_RDONLY);
        if (rfd >= 0) {
            ssize_t rn = read(rfd, enc_sfo, sizeof(enc_sfo));
            close(rfd);
            if (rn > 0 && sfo_bytes_valid(enc_sfo, (size_t)rn))
                enc_sfo_len = (uint32_t)rn;
        }
    }

    save_unmount();

    if (preserve_sidecar) {
        if (ps5param_restore_blob(img_path, saved_sidecar) < 0) {
            unlink(saved_sidecar);
            worker_log(cfg, job_id, "ERROR", "Failed to restore original PS5PARAM blob");
            return -1;
        }
        unlink(saved_sidecar);
        worker_log(cfg, job_id, "INFO", "PS5PARAM: restored original encrypted blob for zeroed param.sfo");
    } else if (has_sidecar && enc_sfo_len) {
        int wr = ps5param_write_sfo(img_path, enc_sfo, enc_sfo_len);
        if (wr < 0) {
            unlink(saved_sidecar);
            unlink(img_path);
            worker_logf(cfg, job_id, "ERROR", "PS5PARAM blob write failed (%d)", wr);
            return -1;
        }
        worker_logf(cfg, job_id, "INFO",
                    "PS5PARAM: wrote param.sfo (%u B) into image blob", enc_sfo_len);
    } else {
        unlink(saved_sidecar);
    }

    /* Copy result to result dir and zip */
    char result_dir[MAX_PATH_LEN];
    snprintf(result_dir, sizeof(result_dir), "%s/result", work_dir);
    mkdir(result_dir, 0777);

    char result_save[MAX_PATH_LEN];
    snprintf(result_save, sizeof(result_save), "%s/%s", result_dir, savename);
    copy_file(img_path, result_save);
    unlink(img_path);

    /* PS4: include the companion sealed-key .bin in the result zip */
    if (is_ps4_job) {
        char src_bin[MAX_PATH_LEN], dst_bin[MAX_PATH_LEN];
        snprintf(src_bin, sizeof(src_bin), "%s.bin", img_path);
        snprintf(dst_bin, sizeof(dst_bin), "%s.bin", result_save);
        copy_file(src_bin, dst_bin);
        unlink(src_bin);
    }

    worker_log(cfg, job_id, "INFO", "Uploading result...");
    char result_zip[MAX_PATH_LEN];
    snprintf(result_zip, sizeof(result_zip), "%s/result.zip", work_dir);
    if (zip_create_from_dir(result_dir, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to create result ZIP");
        return -1;
    }
    if (worker_upload_result(cfg, job_id, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to upload result");
        return -1;
    }

    worker_log(cfg, job_id, "INFO", "Encrypt complete");
    return 0;
}

static int process_resign(worker_config_t *cfg, const char *job_id,
                          const char *params, const char *work_dir,
                          int is_ps4_job) {
    char account_id[64] = {0};
    json_get_string(params, "account_id", account_id, sizeof(account_id));
    if (!account_id[0]) {
        worker_log(cfg, job_id, "ERROR", "No account_id provided");
        return -1;
    }

    uint8_t new_aid[8];
    if (account_id_to_sfo_bytes(account_id, new_aid) != 0) {
        worker_log(cfg, job_id, "ERROR", "Invalid account_id format");
        return -1;
    }

    worker_log(cfg, job_id, "INFO", "Downloading files...");
    if (worker_download_files(cfg, job_id, work_dir) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to download files");
        return -1;
    }

    char files_dir[MAX_PATH_LEN];
    snprintf(files_dir, sizeof(files_dir), "%s/files", work_dir);
    char result_dir[MAX_PATH_LEN];
    snprintf(result_dir, sizeof(result_dir), "%s/result", work_dir);
    mkdir(result_dir, 0777);

    char saves[64][MAX_PATH_LEN];
    int save_count = find_save_files(files_dir, saves, 64);
    if (save_count == 0) {
        worker_log(cfg, job_id, "ERROR", "No save files found");
        return -1;
    }

    int processed = 0;
    for (int i = 0; i < save_count; i++) {
        const char *save_path = saves[i];
        const char *basename = strrchr(save_path, '/');
        basename = basename ? basename + 1 : save_path;

        worker_logf(cfg, job_id, "INFO", "Resigning %s (%d/%d)...",
                    basename, i + 1, save_count);

        char data_path[MAX_PATH_LEN];
        snprintf(data_path, sizeof(data_path), "/data/save_files/_work_%s", basename);
        if (stage_save_to_data(save_path, data_path) < 0) {
            worker_logf(cfg, job_id, "WARNING", "Failed to stage %s", basename);
            continue;
        }

        /* PS5: capture real SFO from blob before mount */
        int is_ps4_save = detect_is_ps4(data_path);
        if (is_ps4_save <= 0)
            ps5param_capture_for_image(data_path);

        int mret = save_mount(data_path);
        if (mret < 0) {
            if (mret == SAVE_ERR_CORRUPTED)
                worker_log(cfg, job_id, "ERROR", "Corrupted save! Is your FTP server set to binary mode?");
            else
                worker_logf(cfg, job_id, "WARNING", "Failed to mount %s", basename);
            unlink(data_path);
            continue;
        }

        /* Resigning updates the real metadata and writes a new PS5PARAM blob. */
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo",
                 save_get_mount_point());
        if (ps5param_get_cached_sfo_len()) {
            install_sfo_file(sfo_path, ps5param_get_cached_sfo(),
                             ps5param_get_cached_sfo_len());
        }

        /* Patch account ID */
        int sfo_fd = open(sfo_path, O_RDWR);
        if (sfo_fd >= 0) {
            pwrite(sfo_fd, new_aid, 8, is_ps4_job ? SFO_AID_OFFSET_PS4 : SFO_AID_OFFSET_PS5);
            close(sfo_fd);
            sync();
        } else {
            worker_logf(cfg, job_id, "WARNING", "Cannot open param.sfo for %s", basename);
        }

        /* PS5: read back the patched SFO for the blob write-back */
        uint8_t resign_sfo[0x8000];
        uint32_t resign_sfo_len = 0;
        if (is_ps4_save <= 0 && ps5param_get_cached_sfo_len()) {
            int rfd = open(sfo_path, O_RDONLY);
            if (rfd >= 0) {
                ssize_t rn = read(rfd, resign_sfo, sizeof(resign_sfo));
                close(rfd);
                if (rn > 0 && sfo_bytes_valid(resign_sfo, (size_t)rn))
                    resign_sfo_len = (uint32_t)rn;
            }
        }

        save_unmount();

        /* PS5: write the resigned SFO back into the header blob */
        if (resign_sfo_len) {
            int wr = ps5param_write_sfo(data_path, resign_sfo, resign_sfo_len);
            if (wr < 0)
                worker_logf(cfg, job_id, "WARNING",
                            "PS5PARAM blob write failed (%d); patched SFO in PFS only", wr);
            else
                worker_logf(cfg, job_id, "INFO",
                            "PS5PARAM: wrote resigned param.sfo (%u B) into blob", resign_sfo_len);
        }

        /* Copy resigned save to result. For PS4 saves, the companion .bin
         * is unchanged by resign (sealed key encodes console, not account)
         * but must travel with the image so the user can put both back. */
        char result_save[MAX_PATH_LEN];
        snprintf(result_save, sizeof(result_save), "%s/%s", result_dir, basename);
        copy_file(data_path, result_save);

        char src_bin[MAX_PATH_LEN];
        snprintf(src_bin, sizeof(src_bin), "%s.bin", data_path);
        if (access(src_bin, R_OK) == 0) {
            char dst_bin[MAX_PATH_LEN];
            snprintf(dst_bin, sizeof(dst_bin), "%s.bin", result_save);
            copy_file(src_bin, dst_bin);
            unlink(src_bin);
        }
        unlink(data_path);
        processed++;
    }

    if (processed == 0) {
        worker_log(cfg, job_id, "ERROR", "No saves could be resigned");
        return -1;
    }

    worker_log(cfg, job_id, "INFO", "Uploading result...");
    char result_zip[MAX_PATH_LEN];
    snprintf(result_zip, sizeof(result_zip), "%s/result.zip", work_dir);
    if (zip_create_from_dir(result_dir, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to create result ZIP");
        return -1;
    }
    if (worker_upload_result(cfg, job_id, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to upload result");
        return -1;
    }

    worker_logf(cfg, job_id, "INFO", "Resigned %d save(s)", processed);
    return 0;
}

static int process_reregion(worker_config_t *cfg, const char *job_id,
                            const char *params, const char *work_dir,
                            int is_ps4_job) {
    char account_id[64] = {0};
    json_get_string(params, "account_id", account_id, sizeof(account_id));
    if (!account_id[0]) {
        worker_log(cfg, job_id, "ERROR", "No account_id provided");
        return -1;
    }

    uint8_t new_aid[8];
    if (account_id_to_sfo_bytes(account_id, new_aid) != 0) {
        worker_log(cfg, job_id, "ERROR", "Invalid account_id format");
        return -1;
    }

    worker_log(cfg, job_id, "INFO", "Downloading files...");
    if (worker_download_files(cfg, job_id, work_dir) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to download files");
        return -1;
    }

    char files_dir[MAX_PATH_LEN];
    snprintf(files_dir, sizeof(files_dir), "%s/files", work_dir);

    /* Look for sample/ and saves/ subdirectories */
    char sample_dir[MAX_PATH_LEN], saves_dir[MAX_PATH_LEN];
    snprintf(sample_dir, sizeof(sample_dir), "%s/sample", files_dir);
    snprintf(saves_dir, sizeof(saves_dir), "%s/saves", files_dir);

    struct stat st;
    if (stat(sample_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        worker_log(cfg, job_id, "ERROR", "No sample/ directory found");
        return -1;
    }
    if (stat(saves_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        worker_log(cfg, job_id, "ERROR", "No saves/ directory found");
        return -1;
    }

    /* Step 1: Mount sample save and extract keystone */
    worker_log(cfg, job_id, "INFO", "Extracting keystone from sample...");
    uint8_t keystone[KEYSTONE_SIZE];
    int have_keystone = 0;

    char sample_saves[16][MAX_PATH_LEN];
    int sample_count = find_save_files(sample_dir, sample_saves, 16);
    if (sample_count == 0) {
        worker_log(cfg, job_id, "ERROR", "No sample save files found");
        return -1;
    }

    char data_path[MAX_PATH_LEN];
    const char *sb = strrchr(sample_saves[0], '/');
    sb = sb ? sb + 1 : sample_saves[0];
    snprintf(data_path, sizeof(data_path), "/data/save_files/_sample_%s", sb);
    copy_file(sample_saves[0], data_path);

    int mret = save_mount(data_path);
    if (mret == SAVE_ERR_CORRUPTED)
        worker_log(cfg, job_id, "ERROR", "Corrupted save! Is your FTP server set to binary mode?");
    if (mret == 0) {
        char ks_path[MAX_PATH_LEN];
        snprintf(ks_path, sizeof(ks_path), "%s/sce_sys/keystone", save_get_mount_point());
        int ks_fd = open(ks_path, O_RDONLY);
        if (ks_fd >= 0) {
            int r = read(ks_fd, keystone, KEYSTONE_SIZE);
            close(ks_fd);
            if (r == KEYSTONE_SIZE) {
                have_keystone = 1;
                worker_log(cfg, job_id, "INFO", "Keystone extracted OK");
            }
        }
        save_unmount();
    }
    unlink(data_path);

    if (!have_keystone) {
        worker_log(cfg, job_id, "ERROR", "Failed to extract keystone from sample");
        return -1;
    }

    /* Step 2: Process target saves */
    char result_dir[MAX_PATH_LEN];
    snprintf(result_dir, sizeof(result_dir), "%s/result", work_dir);
    mkdir(result_dir, 0777);

    char saves[64][MAX_PATH_LEN];
    int save_count = find_save_files(saves_dir, saves, 64);
    if (save_count == 0) {
        worker_log(cfg, job_id, "ERROR", "No target save files found");
        return -1;
    }

    int processed = 0;
    for (int i = 0; i < save_count; i++) {
        const char *save_path = saves[i];
        const char *basename = strrchr(save_path, '/');
        basename = basename ? basename + 1 : save_path;

        worker_logf(cfg, job_id, "INFO", "Reregioning %s (%d/%d)...",
                    basename, i + 1, save_count);

        snprintf(data_path, sizeof(data_path), "/data/save_files/_work_%s", basename);
        if (stage_save_to_data(save_path, data_path) < 0) {
            worker_logf(cfg, job_id, "WARNING", "Failed to stage %s", basename);
            continue;
        }

        /* PS5: capture real SFO from blob before mount */
        int is_ps4_save = detect_is_ps4(data_path);
        if (is_ps4_save <= 0)
            ps5param_capture_for_image(data_path);

        int mret = save_mount(data_path);
        if (mret < 0) {
            if (mret == SAVE_ERR_CORRUPTED)
                worker_log(cfg, job_id, "ERROR", "Corrupted save! Is your FTP server set to binary mode?");
            else
                worker_logf(cfg, job_id, "WARNING", "Failed to mount %s", basename);
            unlink(data_path);
            continue;
        }

        const char *mnt = save_get_mount_point();

        /* PS5: install real SFO into PFS */
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", mnt);
        if (ps5param_get_cached_sfo_len()) {
            install_sfo_file(sfo_path, ps5param_get_cached_sfo(),
                             ps5param_get_cached_sfo_len());
        }

        /* Patch account ID */
        int sfo_fd = open(sfo_path, O_RDWR);
        if (sfo_fd >= 0) {
            pwrite(sfo_fd, new_aid, 8, is_ps4_job ? SFO_AID_OFFSET_PS4 : SFO_AID_OFFSET_PS5);
            close(sfo_fd);
        }

        /* Write keystone */
        char ks_out[MAX_PATH_LEN];
        snprintf(ks_out, sizeof(ks_out), "%s/sce_sys/keystone", mnt);
        int ks_fd = open(ks_out, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (ks_fd >= 0) {
            write(ks_fd, keystone, KEYSTONE_SIZE);
            close(ks_fd);
        }
        sync();

        /* PS5: capture patched SFO for blob write-back */
        uint8_t rereg_sfo[0x8000];
        uint32_t rereg_sfo_len = 0;
        if (is_ps4_save <= 0 && ps5param_get_cached_sfo_len()) {
            int rfd = open(sfo_path, O_RDONLY);
            if (rfd >= 0) {
                ssize_t rn = read(rfd, rereg_sfo, sizeof(rereg_sfo));
                close(rfd);
                if (rn > 0 && sfo_bytes_valid(rereg_sfo, (size_t)rn))
                    rereg_sfo_len = (uint32_t)rn;
            }
        }

        save_unmount();

        /* PS5: write patched SFO back to blob */
        if (rereg_sfo_len) {
            int wr = ps5param_write_sfo(data_path, rereg_sfo, rereg_sfo_len);
            if (wr < 0)
                worker_logf(cfg, job_id, "WARNING",
                            "PS5PARAM blob write failed (%d)", wr);
        }

        char result_save[MAX_PATH_LEN];
        snprintf(result_save, sizeof(result_save), "%s/%s", result_dir, basename);
        copy_file(data_path, result_save);
        unlink(data_path);
        processed++;
    }

    if (processed == 0) {
        worker_log(cfg, job_id, "ERROR", "No saves could be reregioned");
        return -1;
    }

    worker_log(cfg, job_id, "INFO", "Uploading result...");
    char result_zip[MAX_PATH_LEN];
    snprintf(result_zip, sizeof(result_zip), "%s/result.zip", work_dir);
    if (zip_create_from_dir(result_dir, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to create result ZIP");
        return -1;
    }
    if (worker_upload_result(cfg, job_id, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to upload result");
        return -1;
    }

    worker_logf(cfg, job_id, "INFO", "Reregioned %d save(s)", processed);
    return 0;
}

static int process_keyset(worker_config_t *cfg, const char *job_id,
                          const char *params, const char *work_dir) {
    /* PS5 does not use sealed keys or keysets — return a fixed response */
    worker_log(cfg, job_id, "INFO", "PS5 uses zeroed keys, no keyset check needed");

    char result_dir[MAX_PATH_LEN];
    snprintf(result_dir, sizeof(result_dir), "%s/result", work_dir);
    mkdir(result_dir, 0777);

    char json_path[MAX_PATH_LEN];
    snprintf(json_path, sizeof(json_path), "%s/keyset.json", result_dir);
    int fd = open(json_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *json = "{\"platform\":\"ps5\",\"maxKeyset\":0,"
                           "\"note\":\"PS5 uses zeroed keys, no keyset check needed\"}";
        write(fd, json, strlen(json));
        close(fd);
    }

    char result_zip[MAX_PATH_LEN];
    snprintf(result_zip, sizeof(result_zip), "%s/result.zip", work_dir);
    if (zip_create_from_dir(result_dir, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to create result ZIP");
        return -1;
    }
    if (worker_upload_result(cfg, job_id, result_zip) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to upload result");
        return -1;
    }

    return 0;
}

/* ── Main worker loop ──────────────────────────────────────────── */

#define CLEANUP_INTERVAL 25  /* Run periodic cleanup every N jobs */

void worker_loop(worker_config_t *cfg) {
    mkdir_p(WORK_BASE);

    garlic_log("[Garlic] Worker loop started (poll every %ds)\n", cfg->poll_interval);

    int jobs_since_cleanup = 0;

    /* Poll PS5 jobs first, then PS4 jobs. The PS5 worker can now process
     * both formats natively via /dev/pfsmgr ioctl 0xc0845302 (PS5 keys
     * embedded in image at 0x800; PS4 keys read from companion .bin file). */
    static const char *poll_paths[] = {
        "/api/worker/next?platform=ps5",
        "/api/worker/next?platform=ps4",
    };
    int next_platform_idx = 0;

    while (1) {
        http_response_t resp;
        const char *poll_path = poll_paths[next_platform_idx];
        int rc = http_get(cfg->server_host, cfg->server_port,
                          poll_path, cfg->worker_key, &resp);

        if (rc < 0) {
            garlic_log("[Garlic] Server unreachable, retrying in %ds\n", cfg->poll_interval);
            sleep(cfg->poll_interval);
            continue;
        }

        if (resp.status == 204 || resp.status == 404) {
            /* No jobs for this platform — try the other platform on next tick.
             * Sleep only after we've polled BOTH and gotten nothing. */
            next_platform_idx = (next_platform_idx + 1) % 2;
            if (next_platform_idx == 0) sleep(cfg->poll_interval);
            continue;
        }

        if (resp.status == 426) {
            /* Server says we're below MIN_WORKER_VERSION. Self-update:
             * download the latest ELF from /api/worker/update, pipe it into
             * local elfldr on 127.0.0.1:9021, then SIGKILL ourselves. The
             * new binary elfldr just loaded takes over from here. */
            garlic_log("[Garlic] Server rejected worker as outdated (426). "
                       "Body: %.200s\n", resp.body);
            worker_self_update(cfg);
            /* If self_update returned we couldn't update; back off and retry */
            sleep(cfg->poll_interval * 4);
            continue;
        }

        if (resp.status != 200) {
            garlic_log("[Garlic] Unexpected status %d from /next (%s)\n",
                       resp.status, poll_path);
            next_platform_idx = (next_platform_idx + 1) % 2;
            if (next_platform_idx == 0) sleep(cfg->poll_interval);
            continue;
        }

        /* Got a job — remember which platform queue it came from, then reset
         * rotation so the next poll prefers PS5 again. */
        int job_platform_idx = next_platform_idx;
        garlic_log("[Garlic] Got job from %s\n", poll_path);
        next_platform_idx = 0;

        /* Parse job */
        char job_id[64] = {0}, operation[32] = {0}, params[8192] = {0};
        json_get_string(resp.body, "id", job_id, sizeof(job_id));
        json_get_string(resp.body, "operation", operation, sizeof(operation));
        json_get_object(resp.body, "params", params, sizeof(params));

        if (!job_id[0] || !operation[0]) {
            garlic_log("[Garlic] Invalid job response\n");
            sleep(cfg->poll_interval);
            continue;
        }

        garlic_log("[Garlic] Job %s: %s\n", job_id, operation);

        /* Set status running */
        g_last_error[0] = '\0';
        worker_set_status(cfg, job_id, "running", NULL);

        /* Create work directory */
        char work_dir[MAX_PATH_LEN];
        snprintf(work_dir, sizeof(work_dir), "%s/%.8s", WORK_BASE, job_id);
        mkdir_p(work_dir);

        /* Dispatch. PS5 worker handles both PS5 and PS4 jobs natively via
         * /dev/pfsmgr (mount, decrypt + encrypt both formats). */
        int is_ps4_job = (job_platform_idx != 0); /* job came from ps4 queue */
        int result = -1;
        if (strcmp(operation, "ppr_derive") == 0)
            result = process_ppr_derive(cfg, job_id, params, work_dir);
        else if (strcmp(operation, "decrypt") == 0)
            result = process_decrypt(cfg, job_id, params, work_dir);
        else if (strcmp(operation, "encrypt") == 0 || strcmp(operation, "createsave") == 0)
            result = process_encrypt(cfg, job_id, params, work_dir, is_ps4_job);
        else if (strcmp(operation, "resign") == 0)
            result = process_resign(cfg, job_id, params, work_dir, is_ps4_job);
        else if (strcmp(operation, "reregion") == 0)
            result = process_reregion(cfg, job_id, params, work_dir, is_ps4_job);
        else if (strcmp(operation, "keyset") == 0)
            result = process_keyset(cfg, job_id, params, work_dir);
        else {
            worker_logf(cfg, job_id, "ERROR", "Unknown operation: %s", operation);
        }

        /* Set final status */
        if (result == 0)
            worker_set_status(cfg, job_id, "done", NULL);
        else if (result < 0)
            /* Status may already be set to failed by the processor */
            worker_set_status(cfg, job_id, "failed",
                              g_last_error[0] ? g_last_error : NULL);

        /* Force unmount if still mounted */
        if (save_is_mounted())
            save_unmount();

        /* Cleanup work directory */
        delete_recursive(work_dir);

        garlic_log("[Garlic] Job %s complete (result=%d)\n", job_id, result);

        /* Periodic cleanup to prevent kernel resource exhaustion */
        jobs_since_cleanup++;
        if (jobs_since_cleanup >= CLEANUP_INTERVAL) {
            garlic_log("[Garlic] Running periodic cleanup after %d jobs...\n", jobs_since_cleanup);
            save_periodic_cleanup();
            http_reset_pool();
            jobs_since_cleanup = 0;
        }

        sleep(2); /* Brief pause before next poll */
    }
}

/* ── TCP direct-connect worker loop ────────────────────────────── */

void worker_loop_tcp(worker_config_t *cfg) {
    mkdir_p(WORK_BASE);

    g_transport_mode = 1;
    tcp_conn_t conn;
    g_tcp = &conn;

    int backoff = 2;
    int jobs_since_cleanup = 0;

    garlic_log("[TCP] Worker loop started (server %s:%d)\n",
               cfg->server_host, cfg->tcp_port);

    while (1) {
        garlic_log("[TCP] Connecting to %s:%d...\n", cfg->server_host, cfg->tcp_port);
        if (tcp_connect_server(&conn, cfg->server_host, cfg->tcp_port) < 0) {
            garlic_log("[TCP] Connection failed, retry in %ds\n", backoff);
            sleep(backoff);
            if (backoff < 60) backoff *= 2;
            continue;
        }
        garlic_log("[TCP] Connected\n");

        /* Authenticate */
        char auth_msg[512];
        snprintf(auth_msg, sizeof(auth_msg),
            "{\"type\":\"auth\",\"key\":\"%s\",\"platform\":\"ps5\"}",
            cfg->worker_key);
        if (tcp_send_msg(&conn, auth_msg) < 0) {
            tcp_disconnect(&conn);
            sleep(backoff);
            if (backoff < 60) backoff *= 2;
            continue;
        }

        char resp[8192];
        if (tcp_recv_msg(&conn, resp, sizeof(resp)) < 0) {
            tcp_disconnect(&conn);
            sleep(backoff);
            if (backoff < 60) backoff *= 2;
            continue;
        }

        char auth_type[32] = {0};
        json_get_string(resp, "type", auth_type, sizeof(auth_type));
        if (strcmp(auth_type, "auth_ok") != 0) {
            garlic_log("[TCP] Auth failed\n");
            tcp_disconnect(&conn);
            sleep(30);
            continue;
        }

        garlic_log("[TCP] Authenticated\n");
        backoff = 2;

        while (conn.connected) {
            if (tcp_send_msg(&conn, "{\"type\":\"ready\"}") < 0) break;

            if (tcp_recv_msg(&conn, resp, sizeof(resp)) < 0) {
                garlic_log("[TCP] Connection lost while waiting\n");
                break;
            }

            char msg_type[32] = {0};
            json_get_string(resp, "type", msg_type, sizeof(msg_type));

            if (strcmp(msg_type, "no_job") == 0) {
                sleep(cfg->poll_interval > 0 ? cfg->poll_interval : 10);
                continue;
            }

            if (strcmp(msg_type, "job") != 0) {
                garlic_log("[TCP] Unexpected message type: %s\n", msg_type);
                continue;
            }

            char job_id[64] = {0}, operation[32] = {0}, params[8192] = {0};
            json_get_string(resp, "id", job_id, sizeof(job_id));
            json_get_string(resp, "operation", operation, sizeof(operation));
            json_get_object(resp, "params", params, sizeof(params));

            if (!job_id[0] || !operation[0]) continue;

            garlic_log("[TCP] Job %s: %s\n", job_id, operation);
            g_last_error[0] = '\0';

            char work_dir[MAX_PATH_LEN];
            snprintf(work_dir, sizeof(work_dir), "%s/%.8s", WORK_BASE, job_id);
            mkdir_p(work_dir);

            int result = -1;
            if (strcmp(operation, "ppr_derive") == 0)
                result = process_ppr_derive(cfg, job_id, params, work_dir);
            else if (strcmp(operation, "decrypt") == 0)
                result = process_decrypt(cfg, job_id, params, work_dir);
            else if (strcmp(operation, "encrypt") == 0 || strcmp(operation, "createsave") == 0)
                /* TCP path is PS5-only (auth advertises ps5); pass is_ps4_job=0 */
                result = process_encrypt(cfg, job_id, params, work_dir, 0);
            else if (strcmp(operation, "resign") == 0)
                result = process_resign(cfg, job_id, params, work_dir, 0);
            else if (strcmp(operation, "reregion") == 0)
                result = process_reregion(cfg, job_id, params, work_dir, 0);
            else if (strcmp(operation, "keyset") == 0)
                result = process_keyset(cfg, job_id, params, work_dir);
            else
                worker_logf(cfg, job_id, "ERROR", "Unknown operation: %s", operation);

            if (result == 0)
                worker_set_status(cfg, job_id, "done", NULL);
            else if (result < 0)
                worker_set_status(cfg, job_id, "failed",
                                  g_last_error[0] ? g_last_error : NULL);

            if (save_is_mounted())
                save_unmount();

            delete_recursive(work_dir);
            garlic_log("[TCP] Job %s complete (result=%d)\n", job_id, result);

            jobs_since_cleanup++;
            if (jobs_since_cleanup >= CLEANUP_INTERVAL) {
                garlic_log("[TCP] Running periodic cleanup after %d jobs...\n",
                           jobs_since_cleanup);
                save_periodic_cleanup();
                http_reset_pool();
                jobs_since_cleanup = 0;
            }

            sleep(1);
        }

        tcp_disconnect(&conn);
        garlic_log("[TCP] Disconnected, reconnecting in %ds...\n", backoff);
        sleep(backoff);
        if (backoff < 60) backoff *= 2;
    }
}
