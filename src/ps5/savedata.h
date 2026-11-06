#ifndef SAVEDATA_H
#define SAVEDATA_H

#include <stdint.h>

/* ── SDK type definitions ──────────────────────────────────────── */
typedef struct { uint8_t reserved; char *budgetid; } MountOpt;
typedef struct { uint8_t dummy; } UmountOpt;
typedef struct { int blockSize; uint8_t flags[2]; } CreateOpt;

/* sceFsCreatePprPfsSaveDataImage - loaded via dlsym */
typedef int (*PprCreateFn)(CreateOpt *opt, const char *path, int x, uint64_t size, uint8_t *key);

extern PprCreateFn g_pprCreate;

/* SDK functions (linked via libSceFsInternalForVsh) */
int sceFsInitMountSaveDataOpt(MountOpt *opt);
int sceFsMountSaveData(MountOpt *opt, const char *path, const char *mount, uint8_t *key);
int sceFsInitUmountSaveDataOpt(UmountOpt *opt);
int sceFsUmountSaveData(UmountOpt *opt, const char *mount, int handle, int ignore);
int sceFsInitCreatePfsSaveDataOpt(CreateOpt *opt);
int sceFsCreatePfsSaveDataImage(CreateOpt *opt, const char *path, int x, uint64_t size, uint8_t *key);
int sceFsUfsAllocateSaveData(int fd, uint64_t size, uint64_t flags, int ext);
int sceFsTransactionSaveDataReadParam(const char *path, void *buf, uint32_t size);
int sceFsTransactionSaveDataWriteParam(const char *path, const void *buf, uint32_t size);

/* ── Mount point ───────────────────────────────────────────────── */
#define GARLIC_MOUNT_POINT "/data/garlic_mnt"

/* ── Error codes ───────────────────────────────────────────────── */
#define SAVE_ERR_CORRUPTED  (-100)  /* Save file corrupted (e.g. FTP ASCII mode) */

/* ── Public API ────────────────────────────────────────────────── */

/* Detect PS4 vs PS5 by image header byte 0 (0x01=PS4, 0x02=PS5).
 * Returns 1 for PS4, 0 for PS5, -1 on error. */
int detect_is_ps4(const char *image_path);

/* Initialize savedata subsystem: dlopen + dlsym for PprCreate, force unmount stale mounts */
void savedata_init(void);

/* Mount a save image file. Copies to /data/ if not already there.
 * Returns 0 on success, negative on error. */
int save_mount(const char *save_path);

/* Unmount current save. Returns 0 on success. */
int save_unmount(void);

/* Create a new PFS image file.
 * exact=1: size is the final image size (from SAVEDATA_BLOCKS).
 * exact=0: size is estimated data; overhead + alignment added.
 * Returns 0 on success. */
int save_create_pfs(const char *image_path, uint64_t size, int exact);

/* Create a new PS4-format PFS image with sealed-key companion .bin.
 * Uses /dev/pfsmgr ioctls 0x40845303 (generate) + 0xc0845302 (decrypt)
 * and sceFsCreatePfsSaveDataImage (non-Ppr) so the image is PS4-format.
 * Writes <image_path>.bin alongside with the 96-byte sealed key.
 * Returns 0 on success. */
int save_create_pfs_ps4(const char *image_path, uint64_t data_size);

/* Mount a freshly created PFS image with zeroed key.
 * Returns 0 on success. */
int save_mount_new(const char *image_path, const uint8_t *key);

/* Mount a freshly created PS4 PFS image (key comes from companion .bin).
 * Returns 0 on success. */
int save_mount_new_ps4(const char *image_path);

/* Is a save currently mounted? */
int save_is_mounted(void);

/* Get mount point path */
const char *save_get_mount_point(void);

/* Periodic cleanup: force unmount, delete temp files in /data/save_files/ */
void save_periodic_cleanup(void);

/* Read SAVEDATA_BLOCKS from a param.sfo file. Returns 0 if not found. */
int sfo_read_savedata_blocks(const char *sfo_path);

/* ── PS5PARAM blob support ────────────────────────────────────── */

/* Read blob SFO before mounting (caches the real param.sfo in memory).
 * Call on PS5 images only — PS4 images have no blob. */
void ps5param_capture_for_image(const char *image_path);

/* Read the decrypted SFO from the image's PS5PARAM blob.
 * Returns SFO size > 0, 0 = no blob, < 0 = error. */
int ps5param_read_sfo(const char *image_path, uint8_t *sfo, uint32_t sfomax);

/* Write an SFO into the image's PS5PARAM blob (uses the native FS transaction API).
 * Returns 0 on success, < 0 on error. */
int ps5param_write_sfo(const char *image_path, const uint8_t *sfo, uint32_t sz);

/* Validate SFO header magic and table bounds. Returns 1 if valid, 0 otherwise. */
int sfo_bytes_valid(const uint8_t *buf, size_t size);
int sfo_all_zero_file(const char *path);
int ps5param_export_blob(const char *image_path, const char *dest);
int ps5param_restore_blob(const char *image_path, const char *sidecar);

/* Write an SFO buffer to a file path (restores real SFO into mounted PFS). */
int install_sfo_file(const char *path, const uint8_t *buf, uint32_t len);

/* Return the best available param.sfo: cached blob first, PFS file fallback.
 * *from_blob is set to 1 if the data came from the blob. Returns bytes copied,
 * 0 when neither is usable. */
int read_effective_param_sfo(const char *sfo_path, uint8_t *buf,
                             uint32_t bufsize, int *from_blob);

/* In-memory SAVEDATA_BLOCKS parser. Returns block count or 0 if not found. */
int sfo_read_savedata_blocks_mem(const uint8_t *buf, size_t size);

/* Access the cached blob SFO from the last ps5param_capture_for_image() call. */
uint32_t ps5param_get_cached_sfo_len(void);
const uint8_t *ps5param_get_cached_sfo(void);

#endif
