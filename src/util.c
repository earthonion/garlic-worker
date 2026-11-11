#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>

#include "util.h"
#include "../ps5/chives.h"

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
    int dfd = open(dst, O_CREAT | O_WRONLY, 0777);
    if (dfd < 0) { close(sfd); return -2; }
    char buf[BUF_SIZE];
    off_t total = 0;
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dfd, buf + written, n - written);
            if (w <= 0) { close(sfd); close(dfd); return -3; }
            written += w;
        }
        total += n;
    }
    if (n < 0 || ftruncate(dfd, total) < 0) { close(sfd); close(dfd); return -4; }
    fsync(dfd);
    /* Force mode 0777 regardless of umask — the game verifies save file mode
     * and flags 0775 (world-write stripped by default umask=022) as corrupt. */
    fchmod(dfd, 0777);
    close(sfd);
    close(dfd);
    return 0;
}

int copy_dir_recursive(const char *src, const char *dst) {
    umask(0);
    mkdir(dst, 0777);
    DIR *d = opendir(src);
    if (!d) return -1;

    int rc = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char sp[MAX_PATH_LEN], dp[MAX_PATH_LEN];
        snprintf(sp, sizeof(sp), "%s/%s", src, ent->d_name);
        snprintf(dp, sizeof(dp), "%s/%s", dst, ent->d_name);
        struct stat st;
        if (stat(sp, &st) < 0) continue;
        int r;
        if (S_ISDIR(st.st_mode)) r = copy_dir_recursive(sp, dp);
        else                     r = copy_file(sp, dp);
        if (r < 0) {
            fprintf(stderr, "[copy_dir_recursive] %s -> %s failed (rc=%d errno=%d)\n",
                    sp, dp, r, errno);
            rc = r;
            break;
        }
    }
    closedir(d);
    return rc;
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

typedef struct {
    uid_t uid;
    gid_t gid;
    mode_t mode;
} pfs_metadata_t;

static pfs_metadata_t pfs_metadata_for_path(const char *relpath,
                                             const chives_geometry_t *geometry) {
    pfs_metadata_t metadata = {.uid = 1, .gid = 0, .mode = 0777};
    if (_is_sce_sys_path(relpath) || !strcmp(relpath, "memory.dat")) metadata.uid = 0;
    if (geometry) {
        for (uint32_t i = 0; i < geometry->ownership_count; i++) {
            if (!strcmp(relpath, geometry->ownership[i].path)) {
                metadata.uid = geometry->ownership[i].uid;
                metadata.gid = geometry->ownership[i].gid;
                metadata.mode = geometry->ownership[i].mode;
                break;
            }
        }
    }
    return metadata;
}

static int _copy_pfs_recursive(const char *src, const char *dst,
                                const char *src_base, int preserve_sce_sys,
                                const chives_geometry_t *geometry) {
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

        const char *relpath = sp + strlen(src_base);
        if (*relpath == '/') relpath++;
        if (preserve_sce_sys && _is_sce_sys_path(relpath)) continue;

        pfs_metadata_t metadata = pfs_metadata_for_path(relpath, geometry);
        struct stat st;
        if (stat(sp, &st) < 0) continue;
        int r;
        if (S_ISDIR(st.st_mode)) {
            r = _copy_pfs_recursive(sp, dp, src_base, preserve_sce_sys, geometry);
        } else {
            int fd = open(dp, O_CREAT | O_TRUNC, 0777);
            if (fd >= 0) close(fd);
            r = copy_file(sp, dp);
        }
        if (r >= 0 && (chown(dp, metadata.uid, metadata.gid) < 0 ||
                       chmod(dp, metadata.mode) < 0)) r = -4;
        if (r < 0) {
            fprintf(stderr, "[_copy_pfs_recursive] %s -> %s failed (rc=%d errno=%d)\n",
                    sp, dp, r, errno);
            closedir(d);
            return r;
        }
    }
    closedir(d);
    return 0;
}

int copy_dir_pfs(const char *src, const char *dst) {
    umask(0);
    return _copy_pfs_recursive(src, dst, src, 0, NULL);
}

int copy_dir_pfs_with_geometry(const char *src, const char *dst,
                               const chives_geometry_t *geometry) {
    umask(0);
    return _copy_pfs_recursive(src, dst, src, 0, geometry);
}

int copy_dir_pfs_preserve_sce_sys(const char *src, const char *dst) {
    umask(0);
    return _copy_pfs_recursive(src, dst, src, 1, NULL);
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

/* Recursively count files + subdirs under `dir`. Used to verify that a
 * PFS copy landed all entries — Sony's PS5 kernel silently drops
 * directory entries past a per-container ceiling without failing the
 * write() call, so counting after copy is the only way to catch it. */
static uint64_t _count_pfs_recursive(const char *dir, const char *base,
                                      int preserve_sce_sys) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    uint64_t n = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char p[MAX_PATH_LEN];
        snprintf(p, sizeof(p), "%s/%s", dir, ent->d_name);
        const char *relpath = p + strlen(base);
        if (*relpath == '/') relpath++;
        if (preserve_sce_sys && _is_sce_sys_path(relpath)) continue;
        n++;
        struct stat st;
        if (stat(p, &st) == 0 && S_ISDIR(st.st_mode))
            n += _count_pfs_recursive(p, base, preserve_sce_sys);
    }
    closedir(d);
    return n;
}

uint64_t count_entries_recursive(const char *dir) {
    return _count_pfs_recursive(dir, dir, 0);
}

uint64_t count_entries_pfs_preserve_sce_sys(const char *dir) {
    return _count_pfs_recursive(dir, dir, 1);
}
