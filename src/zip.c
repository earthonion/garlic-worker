#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "zip.h"
#include "util.h"
#include "log.h"

/* ── CRC32 ─────────────────────────────────────────────────────── */
static uint32_t crc_tab[256];

void zip_init_crc(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (c & 1 ? 0xEDB88320 : 0);
        crc_tab[i] = c;
    }
}

static uint32_t calc_crc(const uint8_t *buf, size_t len) {
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) c = crc_tab[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

/* ── ZIP extract (from file, streaming) ────────────────────────── */
int zip_extract_file(const char *zip_path, const char *dest_dir) {
    int zfd = open(zip_path, O_RDONLY);
    if (zfd < 0) {
        garlic_log("[Garlic] zip_extract: cannot open %s\n", zip_path);
        return -1;
    }

    struct stat zst;
    fstat(zfd, &zst);
    size_t file_size = zst.st_size;
    garlic_log("[Garlic] zip_extract: %s (%zu bytes)\n", zip_path, file_size);

    int count = 0;
    uint8_t hdr[30];

    while (1) {
        /* Read local file header */
        ssize_t n = read(zfd, hdr, 30);
        if (n < 30) break;
        if (hdr[0] != 0x50 || hdr[1] != 0x4b || hdr[2] != 0x03 || hdr[3] != 0x04) break;

        uint16_t compression = 0, name_len = 0, extra_len = 0;
        uint32_t comp_size = 0, uncomp_size = 0;
        memcpy(&compression, hdr + 8, 2);
        memcpy(&comp_size, hdr + 18, 4);
        memcpy(&uncomp_size, hdr + 22, 4);
        memcpy(&name_len, hdr + 26, 2);
        memcpy(&extra_len, hdr + 28, 2);

        char name[MAX_PATH_LEN] = {0};
        uint16_t copy_len = name_len < MAX_PATH_LEN - 1 ? name_len : (uint16_t)(MAX_PATH_LEN - 1);
        if (read(zfd, name, copy_len) < copy_len) break;
        if (name_len > copy_len) lseek(zfd, name_len - copy_len, SEEK_CUR);
        if (extra_len > 0) lseek(zfd, extra_len, SEEK_CUR);

        if (compression != 0) {
            garlic_log("[Garlic] Skipping compressed entry: %s\n", name);
            lseek(zfd, comp_size, SEEK_CUR);
            continue;
        }

        if (name[0] && name[strlen(name) - 1] == '/') {
            /* Directory entry */
            char dirpath[MAX_PATH_LEN];
            snprintf(dirpath, sizeof(dirpath), "%s/%s", dest_dir, name);
            mkdir_p(dirpath);
            if (comp_size > 0) lseek(zfd, comp_size, SEEK_CUR);
        } else {
            /* File entry — stream to disk */
            char filepath[MAX_PATH_LEN];
            snprintf(filepath, sizeof(filepath), "%s/%s", dest_dir, name);

            /* Create parent directories */
            char *slash = filepath;
            while ((slash = strchr(slash + 1, '/')) != NULL) {
                *slash = 0;
                mkdir(filepath, 0777);
                *slash = '/';
            }

            int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd >= 0) {
                uint8_t buf[65536];
                size_t remaining = uncomp_size;
                while (remaining > 0) {
                    size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                    ssize_t r = read(zfd, buf, chunk);
                    if (r <= 0) break;
                    write(fd, buf, r);
                    remaining -= r;
                }
                close(fd);
                count++;
            } else {
                lseek(zfd, comp_size, SEEK_CUR);
            }
        }
    }

    close(zfd);
    garlic_log("[Garlic] Extracted %d files from %s\n", count, zip_path);
    return count;
}

/* ── ZIP create helpers ────────────────────────────────────────── */
typedef struct {
    char name[512];
    uint32_t crc;
    uint32_t size;
    uint32_t offset;
} zip_entry_t;

#define MAX_ZIP_ENTRIES 4096

static void collect_files(const char *base, const char *prefix,
                          zip_entry_t *entries, int *count) {
    char dirpath[MAX_PATH_LEN];
    if (prefix[0])
        snprintf(dirpath, sizeof(dirpath), "%s/%s", base, prefix);
    else
        snprintf(dirpath, sizeof(dirpath), "%s", base);

    DIR *d = opendir(dirpath);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) && *count < MAX_ZIP_ENTRIES) {
        if (ent->d_name[0] == '.') continue;
        char relpath[MAX_PATH_LEN];
        if (prefix[0])
            snprintf(relpath, sizeof(relpath), "%s/%s", prefix, ent->d_name);
        else
            snprintf(relpath, sizeof(relpath), "%s", ent->d_name);
        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", base, relpath);
        struct stat st;
        if (stat(fullpath, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            collect_files(base, relpath, entries, count);
        } else if (S_ISREG(st.st_mode)) {
            zip_entry_t *e = &entries[*count];
            snprintf(e->name, sizeof(e->name), "%s", relpath);
            e->size = (uint32_t)st.st_size;
            e->crc = 0;
            e->offset = 0;
            (*count)++;
        }
    }
    closedir(d);
}

int zip_create_from_dir(const char *src_dir, const char *zip_path) {
    zip_entry_t *entries = malloc(MAX_ZIP_ENTRIES * sizeof(zip_entry_t));
    if (!entries) return -1;

    int count = 0;
    collect_files(src_dir, "", entries, &count);
    if (count == 0) {
        free(entries);
        return -1;
    }

    int zfd = open(zip_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (zfd < 0) {
        free(entries);
        return -1;
    }

    uint8_t buf[65536];
    uint32_t offset = 0;

    for (int i = 0; i < count; i++) {
        zip_entry_t *e = &entries[i];
        e->offset = offset;
        uint16_t nlen = strlen(e->name);

        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", src_dir, e->name);

        /* First pass: compute CRC by streaming */
        uint32_t crc = 0xFFFFFFFF;
        int fd = open(fullpath, O_RDONLY);
        if (fd >= 0 && e->size > 0) {
            size_t remaining = e->size;
            while (remaining > 0) {
                size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                ssize_t r = read(fd, buf, chunk);
                if (r <= 0) break;
                for (ssize_t j = 0; j < r; j++)
                    crc = crc_tab[(crc ^ buf[j]) & 0xFF] ^ (crc >> 8);
                remaining -= r;
            }
            close(fd);
        } else if (fd >= 0) {
            close(fd);
        }
        e->crc = (e->size > 0) ? (crc ^ 0xFFFFFFFF) : 0;

        /* Write local file header */
        uint8_t lh[30];
        memset(lh, 0, 30);
        lh[0] = 0x50; lh[1] = 0x4b; lh[2] = 0x03; lh[3] = 0x04;
        lh[4] = 20; /* version needed */
        memcpy(lh + 14, &e->crc, 4);
        memcpy(lh + 18, &e->size, 4);
        memcpy(lh + 22, &e->size, 4);
        memcpy(lh + 26, &nlen, 2);
        write(zfd, lh, 30);
        write(zfd, e->name, nlen);

        /* Second pass: stream file data to zip */
        fd = open(fullpath, O_RDONLY);
        if (fd >= 0 && e->size > 0) {
            size_t remaining = e->size;
            while (remaining > 0) {
                size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                ssize_t r = read(fd, buf, chunk);
                if (r <= 0) break;
                write(zfd, buf, r);
                remaining -= r;
            }
            close(fd);
        } else if (fd >= 0) {
            close(fd);
        }
        offset += 30 + nlen + e->size;
    }

    /* Central directory */
    uint32_t cd_offset = offset;
    for (int i = 0; i < count; i++) {
        zip_entry_t *e = &entries[i];
        uint16_t nlen = strlen(e->name);
        uint8_t cd[46];
        memset(cd, 0, 46);
        cd[0] = 0x50; cd[1] = 0x4b; cd[2] = 0x01; cd[3] = 0x02;
        cd[4] = 20; cd[6] = 20;
        memcpy(cd + 16, &e->crc, 4);
        memcpy(cd + 20, &e->size, 4);
        memcpy(cd + 24, &e->size, 4);
        memcpy(cd + 28, &nlen, 2);
        memcpy(cd + 42, &e->offset, 4);
        write(zfd, cd, 46);
        write(zfd, e->name, nlen);
        offset += 46 + nlen;
    }
    uint32_t cd_size = offset - cd_offset;

    /* End of central directory */
    uint8_t ecd[22];
    memset(ecd, 0, 22);
    ecd[0] = 0x50; ecd[1] = 0x4b; ecd[2] = 0x05; ecd[3] = 0x06;
    uint16_t cnt16 = (uint16_t)count;
    memcpy(ecd + 8, &cnt16, 2);
    memcpy(ecd + 10, &cnt16, 2);
    memcpy(ecd + 12, &cd_size, 4);
    memcpy(ecd + 16, &cd_offset, 4);
    write(zfd, ecd, 22);

    close(zfd);
    free(entries);
    garlic_log("[Garlic] Created ZIP %s (%d files)\n", zip_path, count);
    return 0;
}
