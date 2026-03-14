#ifndef SAVEDATA_H
#define SAVEDATA_H

#include <stdint.h>

/* ── Mount point ───────────────────────────────────────────────── */
#define GARLIC_MOUNT_POINT "/data/garlic_mnt"

/* ── Public API ────────────────────────────────────────────────── */

/* Initialize savedata subsystem:
 * - Jailbreak credentials for library loading
 * - Create device nodes (sbl_srv, pfsctldev, lvdctl)
 * - Load libSceFsInternalForVsh.sprx and resolve functions via dlsym
 */
void savedata_init(void);

/* Mount a PS4 save image file.
 * save_path should be the PFS image (not the .bin).
 * Automatically looks for save_path + ".bin" as sealed key.
 * Returns 0 on success, negative on error. */
int save_mount(const char *save_path);

/* Unmount current save. Returns 0 on success. */
int save_unmount(void);

/* Create a new PFS image file with the given data capacity.
 * Also creates a .bin companion file with the sealed key.
 * Returns 0 on success. */
int save_create_pfs(const char *image_path, uint64_t data_size);

/* Mount a freshly created PFS image with zeroed key.
 * Returns 0 on success. */
int save_mount_new(const char *image_path);

/* Is a save currently mounted? */
int save_is_mounted(void);

/* Get mount point path */
const char *save_get_mount_point(void);

/* Get max keyset this console can decrypt */
int save_get_max_keyset(void);

/* Periodic cleanup: force unmount, delete temp files in /data/save_files/ */
void save_periodic_cleanup(void);

#endif
