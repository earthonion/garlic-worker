#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "worker.h"
#include "http.h"
#include "json.h"
#include "zip.h"
#include "tcp.h"
#include "savedata.h"
#include "util.h"
#include "log.h"

#define WORK_BASE      "/data/garlic/work"
#define SFO_AID_OFFSET 0x1B8   /* PS5 account ID offset in param.sfo */
#define KEYSTONE_SIZE  0x400

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
/* PS5 saves are single files (no .bin companion). Returns count. */
static int find_save_files(const char *dir, char saves[][MAX_PATH_LEN], int max) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) && count < max) {
        if (ent->d_name[0] == '.') continue;
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

/* ── Job Processors ────────────────────────────────────────────── */

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

    /* Find save files */
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

        worker_logf(cfg, job_id, "INFO", "Decrypting %s (%d/%d)...",
                    basename, i + 1, save_count);

        /* Copy to /data/ for mount */
        char data_path[MAX_PATH_LEN];
        snprintf(data_path, sizeof(data_path), "/data/save_files/_work_%s", basename);
        if (copy_file(save_path, data_path) < 0) {
            worker_logf(cfg, job_id, "WARNING", "Failed to copy %s", basename);
            continue;
        }

        int mret = save_mount(data_path);
        if (mret < 0) {
            if (mret == SAVE_ERR_CORRUPTED)
                worker_log(cfg, job_id, "ERROR", "Corrupted save! Is your FTP server set to binary mode?");
            else
                worker_logf(cfg, job_id, "WARNING", "Failed to mount %s", basename);
            unlink(data_path);
            continue;
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

static int process_encrypt(worker_config_t *cfg, const char *job_id,
                           const char *params, const char *work_dir) {
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

    /* Calculate data size from uploaded files */
    uint64_t data_size = 0;
    if (saveblocks > 0) {
        data_size = (uint64_t)saveblocks * 32768;
    } else {
        /* Estimate from file sizes */
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

    worker_logf(cfg, job_id, "INFO", "Creating PFS image (%llu bytes)...",
                (unsigned long long)data_size);

    char img_path[MAX_PATH_LEN];
    snprintf(img_path, sizeof(img_path), "/data/save_files/_work_%s", savename);

    if (save_create_pfs(img_path, data_size) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to create PFS image");
        return -1;
    }

    if (save_mount_new(img_path) < 0) {
        worker_log(cfg, job_id, "ERROR", "Failed to mount new PFS");
        unlink(img_path);
        return -1;
    }

    /* Copy files into mounted PFS */
    worker_log(cfg, job_id, "INFO", "Copying files into PFS...");
    const char *mnt = save_get_mount_point();
    copy_dir_recursive(files_dir, mnt);
    sync();

    /* Patch account ID if provided */
    if (account_id[0]) {
        uint8_t new_aid[8];
        if (hex_to_bytes(account_id, new_aid, 8) == 8) {
            char sfo_path[MAX_PATH_LEN];
            snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", mnt);
            int sfo_fd = open(sfo_path, O_RDWR);
            if (sfo_fd >= 0) {
                pwrite(sfo_fd, new_aid, 8, SFO_AID_OFFSET);
                close(sfo_fd);
                sync();
                worker_log(cfg, job_id, "INFO", "Patched account ID");
            }
        }
    }

    save_unmount();

    /* Copy result to result dir and zip */
    char result_dir[MAX_PATH_LEN];
    snprintf(result_dir, sizeof(result_dir), "%s/result", work_dir);
    mkdir(result_dir, 0777);

    char result_save[MAX_PATH_LEN];
    snprintf(result_save, sizeof(result_save), "%s/%s", result_dir, savename);
    copy_file(img_path, result_save);
    unlink(img_path);

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
                          const char *params, const char *work_dir) {
    char account_id[64] = {0};
    json_get_string(params, "account_id", account_id, sizeof(account_id));
    if (!account_id[0]) {
        worker_log(cfg, job_id, "ERROR", "No account_id provided");
        return -1;
    }

    uint8_t new_aid[8];
    if (hex_to_bytes(account_id, new_aid, 8) != 8) {
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
        if (copy_file(save_path, data_path) < 0) {
            worker_logf(cfg, job_id, "WARNING", "Failed to copy %s", basename);
            continue;
        }

        int mret = save_mount(data_path);
        if (mret < 0) {
            if (mret == SAVE_ERR_CORRUPTED)
                worker_log(cfg, job_id, "ERROR", "Corrupted save! Is your FTP server set to binary mode?");
            else
                worker_logf(cfg, job_id, "WARNING", "Failed to mount %s", basename);
            unlink(data_path);
            continue;
        }

        /* Patch account ID */
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo",
                 save_get_mount_point());
        int sfo_fd = open(sfo_path, O_RDWR);
        if (sfo_fd >= 0) {
            pwrite(sfo_fd, new_aid, 8, SFO_AID_OFFSET);
            close(sfo_fd);
            sync();
        } else {
            worker_logf(cfg, job_id, "WARNING", "Cannot open param.sfo for %s", basename);
        }

        save_unmount();

        /* Copy resigned save to result */
        char result_save[MAX_PATH_LEN];
        snprintf(result_save, sizeof(result_save), "%s/%s", result_dir, basename);
        copy_file(data_path, result_save);
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
                            const char *params, const char *work_dir) {
    char account_id[64] = {0};
    json_get_string(params, "account_id", account_id, sizeof(account_id));
    if (!account_id[0]) {
        worker_log(cfg, job_id, "ERROR", "No account_id provided");
        return -1;
    }

    uint8_t new_aid[8];
    if (hex_to_bytes(account_id, new_aid, 8) != 8) {
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
        if (copy_file(save_path, data_path) < 0) {
            worker_logf(cfg, job_id, "WARNING", "Failed to copy %s", basename);
            continue;
        }

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

        /* Patch account ID */
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", mnt);
        int sfo_fd = open(sfo_path, O_RDWR);
        if (sfo_fd >= 0) {
            pwrite(sfo_fd, new_aid, 8, SFO_AID_OFFSET);
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

        save_unmount();

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

    while (1) {
        http_response_t resp;
        int rc = http_get(cfg->server_host, cfg->server_port,
                          "/api/worker/next?platform=ps5", cfg->worker_key, &resp);

        if (rc < 0) {
            garlic_log("[Garlic] Server unreachable, retrying in %ds\n", cfg->poll_interval);
            sleep(cfg->poll_interval);
            continue;
        }

        if (resp.status == 204) {
            /* No jobs available */
            sleep(cfg->poll_interval);
            continue;
        }

        if (resp.status != 200) {
            garlic_log("[Garlic] Unexpected status %d from /next\n", resp.status);
            sleep(cfg->poll_interval);
            continue;
        }

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

        /* Dispatch */
        int result = -1;
        if (strcmp(operation, "decrypt") == 0)
            result = process_decrypt(cfg, job_id, params, work_dir);
        else if (strcmp(operation, "encrypt") == 0 || strcmp(operation, "createsave") == 0)
            result = process_encrypt(cfg, job_id, params, work_dir);
        else if (strcmp(operation, "resign") == 0)
            result = process_resign(cfg, job_id, params, work_dir);
        else if (strcmp(operation, "reregion") == 0)
            result = process_reregion(cfg, job_id, params, work_dir);
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
            if (strcmp(operation, "decrypt") == 0)
                result = process_decrypt(cfg, job_id, params, work_dir);
            else if (strcmp(operation, "encrypt") == 0 || strcmp(operation, "createsave") == 0)
                result = process_encrypt(cfg, job_id, params, work_dir);
            else if (strcmp(operation, "resign") == 0)
                result = process_resign(cfg, job_id, params, work_dir);
            else if (strcmp(operation, "reregion") == 0)
                result = process_reregion(cfg, job_id, params, work_dir);
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
