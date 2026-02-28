#ifndef ZIP_H
#define ZIP_H

#include <stdint.h>
#include <stddef.h>

/* Initialize CRC32 table — must be called once at startup */
void zip_init_crc(void);

/* Extract a ZIP_STORED archive from file to directory.
 * Returns number of files extracted, or -1 on error. */
int zip_extract_file(const char *zip_path, const char *dest_dir);

/* Create a ZIP_STORED archive from a directory.
 * Returns 0 on success, -1 on error. */
int zip_create_from_dir(const char *src_dir, const char *zip_path);

#endif
