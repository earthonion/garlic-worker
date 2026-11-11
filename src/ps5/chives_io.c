#include "chives_io.h"
#include "savedata.h"
#include "util.h"
#include "log.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int chives_read_image(const char *image, chives_geometry_t *geometry) {
    uint8_t header[0x370];
    struct stat st;
    int fd = open(image, O_RDONLY);
    if (fd < 0) return -1;
    int ok = fstat(fd, &st) == 0 && st.st_size >= (off_t)sizeof(header) &&
        pread(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header) &&
        chives_from_header(header, sizeof(header), (uint64_t)st.st_size, geometry) == 0;
    close(fd);
    return ok ? 0 : -1;
}

int chives_verify_created(const char *image, const chives_geometry_t *expected) {
    chives_geometry_t actual;
    if (!expected || chives_read_image(image, &actual) < 0) return -1;
    garlic_log("[Garlic] Created PFS: version=%llu block=%u blocks=%llu mode=0x%x backup=%u\n",
               (unsigned long long)actual.version, actual.block_size_bytes,
               (unsigned long long)actual.block_count, actual.mode_raw,
               actual.backup_header_count);
    if (actual.version != expected->version ||
        actual.block_size_bytes != expected->block_size_bytes ||
        actual.block_count != expected->block_count ||
        (expected->has_fs_ext && (!actual.has_fs_ext || actual.fs_ext != expected->fs_ext))) {
        garlic_log("[Garlic] Formatter did not preserve requested PFS geometry\n");
        return -1;
    }
    return 0;
}

int chives_read_file(const char *base, chives_geometry_t *geometry) {
    char path[MAX_PATH_LEN], json[CHIVES_MAX_JSON + 1];
    snprintf(path, sizeof(path), "%s/chives.json", base);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat st;
    int ok = fstat(fd, &st) == 0 && st.st_size > 0 && st.st_size <= CHIVES_MAX_JSON;
    ssize_t size = ok ? read(fd, json, (size_t)st.st_size) : -1;
    close(fd);
    return ok && size == st.st_size && chives_parse(json, (size_t)size, geometry) == 0 ? 1 : -1;
}

static int sfo_field(const uint8_t *sfo, size_t size, const char *wanted,
                     const uint8_t **value, uint32_t *length, uint16_t *format) {
    if (!sfo_bytes_valid(sfo, size)) return 0;
    uint32_t keys, data, count;
    memcpy(&keys, sfo + 8, 4);
    memcpy(&data, sfo + 12, 4);
    memcpy(&count, sfo + 16, 4);
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *entry = sfo + 20 + i * 16;
        uint16_t key;
        uint32_t value_offset;
        memcpy(&key, entry, 2);
        memcpy(&value_offset, entry + 12, 4);
        if (strcmp((const char *)sfo + keys + key, wanted) != 0) continue;
        memcpy(length, entry + 4, 4);
        memcpy(format, entry + 2, 2);
        *value = sfo + data + value_offset;
        return 1;
    }
    return 0;
}

static uint64_t sfo_blocks(const uint8_t *sfo, size_t size, const char *field) {
    const uint8_t *value;
    uint32_t length;
    uint16_t format;
    if (!sfo_field(sfo, size, field, &value, &length, &format)) return 0;
    if (length >= 8) return chives_le64(value);
    if (length >= 4) return chives_le32(value);
    return 0;
}

int chives_sfo_geometry(const char *base, chives_geometry_t *geometry) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/sce_sys/param.sfo", base);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    static uint8_t sfo[0x8000];
    struct stat st;
    size_t size = 0;
    int ok = fstat(fd, &st) == 0 && st.st_size >= 20 && st.st_size <= (off_t)sizeof(sfo);
    while (ok && size < (size_t)st.st_size) {
        ssize_t n = read(fd, sfo + size, (size_t)st.st_size - size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = 0; break; }
        size += (size_t)n;
    }
    close(fd);
    if (!ok || !sfo_bytes_valid(sfo, size)) return 0;
    uint64_t saved_blocks = sfo_blocks(sfo, size, "SAVEDATA_BLOCKS");
    uint64_t system_blocks = sfo_blocks(sfo, size, "SYSTEM_BLOCKS");
    if (!saved_blocks || system_blocks > UINT64_MAX - saved_blocks) return 0;
    memset(geometry, 0, sizeof(*geometry));
    geometry->version = 2;
    geometry->block_size_bytes = 65536;
    geometry->block_count = saved_blocks + system_blocks;
    geometry->original_image_size_bytes = geometry->block_count * 65536;
    geometry->backup_header_count = 1;
    geometry->mode_raw = 0x000d;
    geometry->has_fs_ext = 1;
    geometry->fs_ext = system_blocks;
    return chives_geometry_valid(geometry) ? 1 : 0;
}

static void sfo_text(const uint8_t *sfo, size_t size, const char *field,
                     char *output, size_t capacity, const char *fallback) {
    const uint8_t *value;
    uint32_t length;
    uint16_t format;
    if (!sfo_field(sfo, size, field, &value, &length, &format)) {
        snprintf(output, capacity, "%s", fallback);
        return;
    }
    size_t copied = length < capacity - 1 ? length : capacity - 1;
    memcpy(output, value, copied);
    output[copied] = 0;
}

static size_t json_escape(const char *input, char *output, size_t capacity) {
    size_t used = 0;
    while (*input && used + 2 < capacity) {
        unsigned char c = (unsigned char)*input++;
        if (c == '"' || c == '\\') output[used++] = '\\';
        if (c >= 32) output[used++] = (char)c;
    }
    output[used] = 0;
    return used;
}

static int chives_collect_ownership(const char *base, const char *relative,
                                    chives_geometry_t *g) {
    char directory[MAX_PATH_LEN];
    if (relative[0]) snprintf(directory,sizeof(directory),"%s/%s",base,relative);
    else snprintf(directory,sizeof(directory),"%s",base);
    DIR *d = opendir(directory);
    if (!d) return -1;
    struct dirent *ent;
    int result = 0;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.' && (!ent->d_name[1] ||
            (ent->d_name[1] == '.' && !ent->d_name[2]))) continue;
        char child[MAX_PATH_LEN], full[MAX_PATH_LEN];
        if (relative[0]) snprintf(child,sizeof(child),"%s/%s",relative,ent->d_name);
        else snprintf(child,sizeof(child),"%s",ent->d_name);
        if (!chives_path_safe(child) ||
            snprintf(full,sizeof(full),"%s/%s",directory,ent->d_name) >= (int)sizeof(full)) {
            result = -1;
            break;
        }
        struct stat st;
        if (lstat(full,&st) < 0 || g->ownership_count >= CHIVES_MAX_OWNERSHIP) {
            result = -1;
            break;
        }
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) continue;
        chives_ownership_t *entry = &g->ownership[g->ownership_count++];
        snprintf(entry->path,sizeof(entry->path),"%s",child);
        entry->uid = st.st_uid;
        entry->gid = st.st_gid;
        entry->mode = st.st_mode & 07777;
        if (S_ISDIR(st.st_mode) && chives_collect_ownership(directory,child,g) < 0) {
            result = -1;
            break;
        }
    }
    closedir(d);
    return result;
}
static int chives_append_ownership(char *json, size_t cap, int n, const chives_geometry_t *g) {
    if (n < 2 || (size_t)n >= cap || !g->ownership_count) return n;
    n -= 2;
    int written = snprintf(json+n,cap-n,",\n  \"ownership\": [\n");
    if (written < 0 || (size_t)written >= cap-n) return -1;
    n += written;
    for (uint32_t i = 0; i < g->ownership_count; i++) {
        char escaped[MAX_PATH_LEN * 2];
        json_escape(g->ownership[i].path,escaped,sizeof(escaped));
        written = snprintf(json+n,cap-n,
            "    {\"path\":\"%s\",\"uid\":%u,\"gid\":%u,\"mode\":%u}%s\n",
            escaped,g->ownership[i].uid,g->ownership[i].gid,g->ownership[i].mode,
            i + 1 == g->ownership_count ? "" : ",");
        if (written < 0 || (size_t)written >= cap-n) return -1;
        n += written;
    }
    written = snprintf(json+n,cap-n,"  ]\n}\n");
    if (written < 0 || (size_t)written >= cap-n) return -1;
    return n + written;
}
int chives_write_export(const char *image, const char *mount, const char *dest,
                        const char *encrypted_name) {
    chives_geometry_t geometry;
    if (chives_read_image(image, &geometry) < 0) return -1;
    char sfo_path[MAX_PATH_LEN];
    snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", mount);
    static uint8_t sfo[0x8000];
    int sfo_size = read_effective_param_sfo(sfo_path, sfo, sizeof(sfo), NULL);
    if (sfo_size < 0) sfo_size = 0;

    char title_id[96] = {0}, directory[768] = {0}, format[96] = {0};
    char title_esc[192], directory_esc[1536], format_esc[192], name_esc[512];
    sfo_text(sfo, (size_t)sfo_size, "TITLE_ID", title_id, sizeof(title_id), "");
    sfo_text(sfo, (size_t)sfo_size, "SAVEDATA_DIRECTORY", directory, sizeof(directory), "");
    sfo_text(sfo, (size_t)sfo_size, "FORMAT", format, sizeof(format), "ppr");
    json_escape(title_id, title_esc, sizeof(title_esc));
    json_escape(directory, directory_esc, sizeof(directory_esc));
    json_escape(format, format_esc, sizeof(format_esc));
    json_escape(encrypted_name, name_esc, sizeof(name_esc));
    uint64_t saved_blocks = sfo_blocks(sfo, (size_t)sfo_size, "SAVEDATA_BLOCKS");
    uint64_t system_blocks = sfo_blocks(sfo, (size_t)sfo_size, "SYSTEM_BLOCKS");
    if (chives_collect_ownership(mount,"",&geometry) < 0) return -1;
    char json[CHIVES_MAX_JSON];
    int length = snprintf(json, sizeof(json),
        "{\n  \"schema_version\": 1,\n  \"platform\": \"PS5\",\n"
        "  \"title_id\": \"%s\",\n  \"save_directory\": \"%s\",\n"
        "  \"save_format\": \"%s\",\n  \"encrypted_name\": \"%s\",\n"
        "  \"original_image_size_bytes\": %llu,\n"
        "  \"pfs\": {\n    \"version\": %llu,\n    \"block_size_bytes\": %u,\n"
        "    \"block_count\": %llu,\n    \"mode_raw\": %u,\n"
        "    \"backup_header_count\": %u, \"fs_ext\": %u\n  },\n"
        "  \"sfo\": {\"savedata_blocks\": %llu, \"system_blocks\": %llu}\n}\n",
        title_esc, directory_esc, format_esc, name_esc,
        (unsigned long long)geometry.original_image_size_bytes,
        (unsigned long long)geometry.version, geometry.block_size_bytes,
        (unsigned long long)geometry.block_count, geometry.mode_raw,
        geometry.backup_header_count, geometry.fs_ext,
        (unsigned long long)saved_blocks, (unsigned long long)system_blocks);
    length = chives_append_ownership(json,sizeof(json),length,&geometry);
    if (length <= 0 || (size_t)length >= sizeof(json)) return -1;
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/chives.json", dest);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    int ok = write(fd, json, (size_t)length) == length;
    if (close(fd) < 0) ok = 0;
    return ok ? 0 : -1;
}
