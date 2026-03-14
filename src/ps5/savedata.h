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

/* ── Mount point ───────────────────────────────────────────────── */
#define GARLIC_MOUNT_POINT "/data/garlic_mnt"

/* ── Error codes ───────────────────────────────────────────────── */
#define SAVE_ERR_CORRUPTED  (-100)  /* Save file corrupted (e.g. FTP ASCII mode) */

/* ── Public API ────────────────────────────────────────────────── */

/* Initialize savedata subsystem: dlopen + dlsym for PprCreate, force unmount stale mounts */
void savedata_init(void);

/* Mount a save image file. Copies to /data/ if not already there.
 * Returns 0 on success, negative on error. */
int save_mount(const char *save_path);

/* Unmount current save. Returns 0 on success. */
int save_unmount(void);

/* Create a new PFS image file with the given data capacity.
 * The actual file will be larger (overhead + alignment).
 * Returns 0 on success. */
int save_create_pfs(const char *image_path, uint64_t data_size);

/* Mount a freshly created PFS image with zeroed key.
 * Returns 0 on success. */
int save_mount_new(const char *image_path);

/* Is a save currently mounted? */
int save_is_mounted(void);

/* Get mount point path */
const char *save_get_mount_point(void);

/* Periodic cleanup: force unmount, delete temp files in /data/save_files/ */
void save_periodic_cleanup(void);

#endif
