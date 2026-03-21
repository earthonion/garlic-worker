#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#include "util.h"

void delete_recursive(const char *path) {
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char fp[MAX_PATH_LEN];
        snprintf(fp, sizeof(fp), "%s/%s", path, ent->d_name);
        struct stat st;
        if (stat(fp, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            delete_recursive(fp);
            rmdir(fp);
        } else {
            unlink(fp);
        }
    }
    closedir(d);
    rmdir(path);
}

int copy_file(const char *src, const char *dst) {
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) return -1;
    int dfd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (dfd < 0) { close(sfd); return -2; }
    char buf[BUF_SIZE];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dfd, buf + written, n - written);
            if (w <= 0) { close(sfd); close(dfd); return -3; }
            written += w;
        }
    }
    fsync(dfd);
    close(sfd);
    close(dfd);
    return 0;
}

int copy_dir_recursive(const char *src, const char *dst) {
    mkdir(dst, 0777);
    DIR *d = opendir(src);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char sp[MAX_PATH_LEN], dp[MAX_PATH_LEN];
        snprintf(sp, sizeof(sp), "%s/%s", src, ent->d_name);
        snprintf(dp, sizeof(dp), "%s/%s", dst, ent->d_name);
        struct stat st;
        if (stat(sp, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            copy_dir_recursive(sp, dp);
        } else {
            copy_file(sp, dp);
        }
    }
    closedir(d);
    return 0;
}

int mkdir_p(const char *path) {
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    }
    return mkdir(tmp, 0777);
}

static int _is_sce_sys_path(const char *relpath) {
    return strncmp(relpath, "sce_sys", 7) == 0 &&
           (relpath[7] == '/' || relpath[7] == '\0');
}

static int _copy_pfs_recursive(const char *src, const char *dst,
                                const char *src_base) {
    mkdir(dst, 0777);
    DIR *d = opendir(src);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char sp[MAX_PATH_LEN], dp[MAX_PATH_LEN];
        snprintf(sp, sizeof(sp), "%s/%s", src, ent->d_name);
        snprintf(dp, sizeof(dp), "%s/%s", dst, ent->d_name);

        /* Compute relative path from source base for uid decision */
        const char *relpath = sp + strlen(src_base);
        if (*relpath == '/') relpath++;

        /* sce_sys and memory.dat → uid 0, everything else → uid 1 */
        if (_is_sce_sys_path(relpath) || strcmp(ent->d_name, "memory.dat") == 0)
            setuid(0);
        else
            setuid(1);

        struct stat st;
        if (stat(sp, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            _copy_pfs_recursive(sp, dp, src_base);
        } else {
            /* Create file first (like cecie.nim does) */
            int fd = open(dp, O_CREAT | O_TRUNC, 0777);
            if (fd >= 0) close(fd);
            copy_file(sp, dp);
        }
    }
    closedir(d);
    setuid(0);
    return 0;
}

int copy_dir_pfs(const char *src, const char *dst) {
    return _copy_pfs_recursive(src, dst, src);
}

int hex_to_bytes(const char *hex, uint8_t *out, int max_bytes) {
    const char *s = hex;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    int len = strlen(s);
    int bytes = len / 2;
    if (bytes > max_bytes) bytes = max_bytes;
    for (int i = 0; i < bytes; i++) {
        char bh[3] = {s[i * 2], s[i * 2 + 1], 0};
        out[i] = (uint8_t)strtol(bh, NULL, 16);
    }
    return bytes;
}

uint64_t hex_to_u64(const char *hex) {
    const char *s = hex;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    return strtoull(s, NULL, 16);
}
