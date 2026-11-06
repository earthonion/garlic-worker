#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

#define MAX_PATH_LEN 1024
#define BUF_SIZE     65536

void delete_recursive(const char *path);
int  copy_file(const char *src, const char *dst);
int  copy_dir_recursive(const char *src, const char *dst);
int  copy_dir_pfs(const char *src, const char *dst);
int  copy_dir_pfs_preserve_sce_sys(const char *src, const char *dst);
int  mkdir_p(const char *path);
uint64_t count_entries_recursive(const char *dir);
uint64_t count_entries_pfs_preserve_sce_sys(const char *dir);
int  hex_to_bytes(const char *hex, uint8_t *out, int max_bytes);
uint64_t hex_to_u64(const char *hex);

#endif
