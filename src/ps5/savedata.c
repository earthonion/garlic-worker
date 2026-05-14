#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dlfcn.h>

#include <ps5/kernel.h>

#include "savedata.h"
#include "util.h"
#include "log.h"

/* ── Globals ───────────────────────────────────────────────────── */
PprCreateFn g_pprCreate = NULL;
static int g_mounted = 0;
static char g_local_copy[MAX_PATH_LEN] = {0};

/* ── Init ──────────────────────────────────────────────────────── */
void savedata_init(void) {
    /* Load PprCreate via dlsym */
    void *vsh = dlopen("libSceFsInternalForVsh.sprx", RTLD_LAZY);
    if (vsh) {
        g_pprCreate = (PprCreateFn)dlsym(vsh, "sceFsCreatePprPfsSaveDataImage");
        garlic_log("[Garlic] PprCreate: %s\n", g_pprCreate ? "available" : "not found");
    } else {
        garlic_log("[Garlic] Failed to dlopen libSceFsInternalForVsh.sprx\n");
    }

    /* Force unmount any stale mounts from previous runs */
    UmountOpt u0;
    memset(&u0, 0, sizeof(u0));
    sceFsInitUmountSaveDataOpt(&u0);
    sceFsUmountSaveData(&u0, GARLIC_MOUNT_POINT, 0, 0);

    mkdir(GARLIC_MOUNT_POINT, 0777);
    mkdir("/data/save_files", 0777);
}

/* ── Detect PS4 vs PS5 by image header byte 0 (0x01=PS4, 0x02=PS5) ── */
static int detect_is_ps4(const char *image_path) {
    int hfd = open(image_path, O_RDONLY);
    if (hfd < 0) return -1;
    uint8_t hdr = 0;
    int n = pread(hfd, &hdr, 1, 0);
    close(hfd);
    if (n != 1) return -1;
    return (hdr == 0x01) ? 1 : 0;
}

/* ── Mount existing save (PS4 + PS5) ──────────────────────────────
 * PS5 images: sealed key magic `pfsSKKey` embedded at offset 0x800.
 * PS4 images (sdimg_*): sealed key in companion .bin file (savename.bin).
 * Both decrypted via /dev/pfsmgr ioctl 0xc0845302.
 */
int save_mount(const char *save_path) {
    if (g_mounted) save_unmount();

    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    int is_ps4 = detect_is_ps4(save_path);
    if (is_ps4 < 0) {
        garlic_log("[Garlic] Cannot read save header: %s\n", save_path);
        return -2;
    }
    garlic_log("[Garlic] %s detected as %s\n",
               strrchr(save_path, '/') ? strrchr(save_path, '/') + 1 : save_path,
               is_ps4 ? "PS4" : "PS5");

    /* If save is NOT on /data/, copy there first (mount from other paths causes EPIPE).
     * For PS4 saves we also need to copy the companion .bin (sealed key). */
    const char *mount_src = save_path;
    g_local_copy[0] = 0;
    int is_on_data = (strncmp(save_path, "/data/", 6) == 0);

    const char *basename = strrchr(save_path, '/');
    basename = basename ? basename + 1 : save_path;

    if (!is_on_data) {
        snprintf(g_local_copy, sizeof(g_local_copy), "/data/save_files/%s", basename);
        garlic_log("[Garlic] Copying %s -> %s\n", save_path, g_local_copy);
        if (copy_file(save_path, g_local_copy) < 0) {
            garlic_log("[Garlic] Copy failed (errno %d)\n", errno);
            return -1;
        }
        chmod(g_local_copy, 0755);
        mount_src = g_local_copy;
    }

    /* PS4: ensure the companion .bin (sealed key) is at /data/save_files/<basename>.bin.
     * Companion is always at <save_path>.bin regardless of naming convention
     * (HTOS uploads use plain names, real PS4 hw uses sdimg_<name>). Runs whether
     * or not the image was already in /data — the .bin may still be elsewhere. */
    if (is_ps4) {
        char src_bin[MAX_PATH_LEN], dst_bin[MAX_PATH_LEN];
        snprintf(src_bin, sizeof(src_bin), "%s.bin", save_path);
        snprintf(dst_bin, sizeof(dst_bin), "%s.bin", mount_src);
        if (strcmp(src_bin, dst_bin) != 0) {
            if (copy_file(src_bin, dst_bin) < 0) {
                garlic_log("[Garlic] PS4: companion .bin missing at %s (errno %d)\n",
                           src_bin, errno);
                return -2;
            }
            chmod(dst_bin, 0755);
            garlic_log("[Garlic] PS4: copied sealed key %s -> %s\n", src_bin, dst_bin);
        }
    }

    /* Heap-allocate ioctl buffer — ioctl may corrupt stack beyond buffer bounds */
    struct {
        uint8_t key[0x60];
        uint8_t hash[0x20];
        uint32_t result;
    } *pfsbuf = malloc(sizeof(*pfsbuf));
    if (!pfsbuf) return -2;
    memset(pfsbuf, 0, sizeof(*pfsbuf));

    int ret;
    if (is_ps4) {
        /* PS4: read 0x60 sealed-key bytes from companion .bin at <image>.bin */
        char bin_path[MAX_PATH_LEN];
        snprintf(bin_path, sizeof(bin_path), "%s.bin", mount_src);

        garlic_log("[Garlic] Opening PS4 sealed key %s\n", bin_path);
        int fd = open(bin_path, O_RDONLY);
        if (fd < 0) {
            garlic_log("[Garlic] Cannot open .bin %s (errno %d)\n", bin_path, errno);
            free(pfsbuf);
            return -2;
        }
        ret = read(fd, pfsbuf->key, 0x60);
        close(fd);
        if (ret != 0x60) {
            garlic_log("[Garlic] Short read on .bin (got %d / 0x60)\n", ret);
            free(pfsbuf);
            return -3;
        }
        garlic_log("[Garlic] PS4 sealed key loaded (keyset=%d)\n",
                   (pfsbuf->key[9] << 8) | pfsbuf->key[8]);
    } else {
        /* PS5: read sealed key from offset 0x800 in image, scan for pfsSKKey magic */
        garlic_log("[Garlic] Opening %s for sealed key read\n", mount_src);
        int fd = open(mount_src, O_RDONLY);
        if (fd < 0) {
            garlic_log("[Garlic] Cannot open %s (errno %d)\n", mount_src, errno);
            free(pfsbuf);
            return -2;
        }
        struct stat st;
        fstat(fd, &st);
        garlic_log("[Garlic] File size: %lld\n", (long long)st.st_size);

        uint8_t keybuf[0x80];
        ret = pread(fd, keybuf, sizeof(keybuf), 0x800);
        close(fd);
        if (ret < 0x60) {
            garlic_log("[Garlic] Failed to read key region (ret=%d)\n", ret);
            free(pfsbuf);
            return -3;
        }

        /* Find pfsSKKey magic (8 bytes: 70 66 73 53 4b 4b 65 79) */
        static const uint8_t magic[] = {'p','f','s','S','K','K','e','y'};
        int key_off = -1;
        for (int i = 0; i <= ret - 0x60; i++) {
            if (memcmp(keybuf + i, magic, 8) == 0) {
                key_off = i;
                break;
            }
        }
        if (key_off < 0) {
            garlic_log("[Garlic] pfsSKKey magic not found — save file is corrupted\n");
            free(pfsbuf);
            return -3;
        }
        if (key_off != 0) {
            garlic_log("[Garlic] Corrupted save! pfsSKKey at 0x%x instead of 0x800. "
                       "Is your FTP server set to transfer in binary mode?\n", 0x800 + key_off);
            free(pfsbuf);
            return SAVE_ERR_CORRUPTED;
        }
        memcpy(pfsbuf->key, keybuf, 0x60);
    }

    int pfsmgr = open("/dev/pfsmgr", 2);
    if (pfsmgr < 0) {
        garlic_log("[Garlic] Cannot open /dev/pfsmgr\n");
        memset(pfsbuf->hash, 0, sizeof(pfsbuf->hash));
    } else {
        ret = ioctl(pfsmgr, 0xc0845302, pfsbuf);
        close(pfsmgr);
        if (ret < 0) {
            garlic_log("[Garlic] ioctl failed (ret=%d), using zeroed key\n", ret);
            memset(pfsbuf->hash, 0, sizeof(pfsbuf->hash));
        } else {
            garlic_log("[Garlic] ioctl OK (ret=%d)\n", ret);
        }
    }

    struct stat mnt_st;
    if (stat(GARLIC_MOUNT_POINT, &mnt_st) < 0) {
        garlic_log("[Garlic] Mount point %s missing, creating\n", GARLIC_MOUNT_POINT);
        mkdir(GARLIC_MOUNT_POINT, 0777);
    }

    struct stat src_st;
    if (stat(mount_src, &src_st) < 0) {
        garlic_log("[Garlic] Save file %s gone before mount! errno=%d\n", mount_src, errno);
    }

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    garlic_log("[Garlic] Mounting %s -> %s\n", mount_src, GARLIC_MOUNT_POINT);
    signal(SIGPIPE, SIG_DFL);
    ret = sceFsMountSaveData(&mopt, mount_src, GARLIC_MOUNT_POINT, pfsbuf->hash);
    signal(SIGPIPE, SIG_IGN);

    /* If mount failed with decrypted key, retry with zeroed key
       (save may be from a different console) */
    if (ret < 0) {
        garlic_log("[Garlic] Mount with decrypted key failed (0x%x), retrying with zeroed key\n", ret);
        uint8_t zkey[0x20] = {0};
        signal(SIGPIPE, SIG_DFL);
        ret = sceFsMountSaveData(&mopt, mount_src, GARLIC_MOUNT_POINT, zkey);
        signal(SIGPIPE, SIG_IGN);
    }
    free(pfsbuf);

    if (ret >= 0) {
        garlic_log("[Garlic] Mounted %s (handle=%d)\n", mount_src, ret);
        g_mounted = 1;
        return 0;
    }
    garlic_log("[Garlic] Mount failed (0x%x, errno=%d)\n", ret, errno);
    return ret;
}

/* ── Unmount ───────────────────────────────────────────────────── */
int save_unmount(void) {
    if (!g_mounted) return 0;

    UmountOpt uopt;
    memset(&uopt, 0, sizeof(uopt));
    sceFsInitUmountSaveDataOpt(&uopt);
    sceFsUmountSaveData(&uopt, GARLIC_MOUNT_POINT, 0, 0);
    sync();

    g_mounted = 0;
    g_local_copy[0] = 0;
    return 0;
}

/* ── Create new PFS image ──────────────────────────────────────── */
int save_create_pfs(const char *image_path, uint64_t data_size) {
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    /* Size: data + 25% overhead + 4MB, min 32MB, aligned to 32K */
    uint64_t img_size = data_size + (data_size / 4) + (4 * 1024 * 1024);
    if (img_size < 32 * 1024 * 1024)
        img_size = 32 * 1024 * 1024;
    img_size = ((img_size + 32767) / 32768) * 32768;

    /* Create file and allocate space */
    int fd = open(image_path, O_CREAT | O_TRUNC | O_RDWR, 0777);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot create image %s (errno %d)\n", image_path, errno);
        return -1;
    }

    int ret = sceFsUfsAllocateSaveData(fd, img_size, 0, 0);
    if (ret < 0) {
        garlic_log("[Garlic] UfsAllocate failed (0x%x), using ftruncate\n", ret);
        if (ftruncate(fd, img_size) < 0) {
            close(fd);
            unlink(image_path);
            return -2;
        }
    }
    close(fd);
    garlic_log("[Garlic] Created image %llu bytes\n", (unsigned long long)img_size);

    /* Format as PFS with compression */
    if (!g_pprCreate) {
        garlic_log("[Garlic] PprCreate not available\n");
        unlink(image_path);
        return -3;
    }

    CreateOpt copt;
    memset(&copt, 0, sizeof(copt));
    sceFsInitCreatePfsSaveDataOpt(&copt);
    copt.flags[1] = 0x02; /* compression */
    uint8_t ckey[0x20] = {0};

    ret = g_pprCreate(&copt, image_path, 0, img_size, ckey);
    if (ret < 0) {
        garlic_log("[Garlic] PprCreate failed (0x%x)\n", ret);
        unlink(image_path);
        return -4;
    }

    garlic_log("[Garlic] Formatted PFS image OK\n");
    return 0;
}

/* ── Create new PS4-format PFS image with sealed-key companion .bin ── */
int save_create_pfs_ps4(const char *image_path, uint64_t data_size) {
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    /* Save path early — ioctl calls may corrupt the stack. */
    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, image_path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = 0;

    /* Generate a fresh PS4 sealed key via pfsmgr ioctl 0x40845303 (96 bytes). */
    uint8_t *buf = malloc(0x100);
    if (!buf) return -1;
    memset(buf, 0, 0x100);

    int pfsmgr = open("/dev/pfsmgr", O_RDWR);
    if (pfsmgr < 0) {
        garlic_log("[Garlic] PS4 create: cannot open /dev/pfsmgr (errno %d)\n", errno);
        free(buf);
        return -1;
    }
    int ret = ioctl(pfsmgr, 0x40845303, buf);
    close(pfsmgr);
    if (ret < 0) {
        garlic_log("[Garlic] PS4 create: generate sealed key ioctl failed (ret=%d, errno=%d)\n",
                   ret, errno);
        free(buf);
        return -2;
    }

    uint8_t sealed_key[96];
    memcpy(sealed_key, buf, 96);
    garlic_log("[Garlic] PS4 create: sealed key generated (keyset=%d)\n",
               (sealed_key[9] << 8) | sealed_key[8]);

    /* Decrypt to get the 32-byte working key. */
    memset(buf, 0, 0x100);
    memcpy(buf, sealed_key, 96);
    pfsmgr = open("/dev/pfsmgr", O_RDWR);
    if (pfsmgr < 0) {
        garlic_log("[Garlic] PS4 create: cannot reopen pfsmgr for decrypt\n");
        free(buf);
        return -3;
    }
    ret = ioctl(pfsmgr, 0xc0845302, buf);
    close(pfsmgr);
    if (ret < 0) {
        garlic_log("[Garlic] PS4 create: decrypt sealed key ioctl failed (ret=%d)\n", ret);
        free(buf);
        return -3;
    }
    uint8_t decrypted_key[32];
    memcpy(decrypted_key, buf + 96, 32);
    free(buf);

    /* Size: PS4 expects exact blocks × 32KB. */
    uint64_t img_size = data_size;
    if (img_size < 32 * 1024 * 1024)
        img_size = 32 * 1024 * 1024;
    img_size = ((img_size + 32767) / 32768) * 32768;

    int fd = open(path_copy, O_CREAT | O_TRUNC | O_RDWR, 0777);
    if (fd < 0) {
        garlic_log("[Garlic] PS4 create: cannot create image %s (errno %d)\n",
                   path_copy, errno);
        return -4;
    }
    ret = sceFsUfsAllocateSaveData(fd, img_size, 0, 0);
    if (ret < 0) {
        garlic_log("[Garlic] PS4 create: UfsAllocate failed (0x%x), using ftruncate\n", ret);
        if (ftruncate(fd, img_size) < 0) {
            close(fd);
            unlink(path_copy);
            return -5;
        }
    }
    close(fd);

    /* Format as PS4-style PFS (non-Ppr CreatePfsSaveDataImage). */
    CreateOpt copt;
    memset(&copt, 0, sizeof(copt));
    sceFsInitCreatePfsSaveDataOpt(&copt);
    ret = sceFsCreatePfsSaveDataImage(&copt, path_copy, 0, img_size, decrypted_key);
    if (ret < 0) {
        garlic_log("[Garlic] PS4 create: CreatePfsSaveDataImage failed (0x%x)\n", ret);
        unlink(path_copy);
        return -6;
    }

    /* Sync image to disk. */
    fd = open(path_copy, O_RDONLY);
    if (fd >= 0) { fsync(fd); close(fd); }

    /* Write companion .bin (96-byte sealed key). */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", path_copy);
    fd = open(bin_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        garlic_log("[Garlic] PS4 create: cannot write %s (errno %d)\n", bin_path, errno);
        return -7;
    }
    if (write(fd, sealed_key, 96) != 96) {
        garlic_log("[Garlic] PS4 create: short write on .bin\n");
        close(fd);
        return -8;
    }
    close(fd);

    garlic_log("[Garlic] PS4 create: image + .bin written OK (%llu bytes)\n",
               (unsigned long long)img_size);
    return 0;
}

/* ── Mount a freshly created PS4 PFS image ────────────────────────
 * The sealed key lives in <image>.bin; decrypt it via pfsmgr then
 * mount with sceFsMountSaveData. */
int save_mount_new_ps4(const char *image_path) {
    if (g_mounted) save_unmount();

    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    /* Load + decrypt sealed key from .bin */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", image_path);

    uint8_t *buf = malloc(0x100);
    if (!buf) return -1;
    memset(buf, 0, 0x100);

    int fd = open(bin_path, O_RDONLY);
    if (fd < 0) {
        garlic_log("[Garlic] mount_new_ps4: cannot open %s (errno %d)\n", bin_path, errno);
        free(buf);
        return -2;
    }
    int r = read(fd, buf, 96);
    close(fd);
    if (r != 96) {
        garlic_log("[Garlic] mount_new_ps4: short read on .bin (%d)\n", r);
        free(buf);
        return -3;
    }

    int pfsmgr = open("/dev/pfsmgr", O_RDWR);
    uint8_t decrypted[32] = {0};
    if (pfsmgr >= 0) {
        int ret = ioctl(pfsmgr, 0xc0845302, buf);
        close(pfsmgr);
        if (ret >= 0) memcpy(decrypted, buf + 96, 32);
        else garlic_log("[Garlic] mount_new_ps4: decrypt ioctl failed (ret=%d)\n", ret);
    }
    free(buf);

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    signal(SIGPIPE, SIG_DFL);
    int ret = sceFsMountSaveData(&mopt, image_path, GARLIC_MOUNT_POINT, decrypted);
    signal(SIGPIPE, SIG_IGN);

    if (ret >= 0) {
        garlic_log("[Garlic] Mounted new PS4 PFS (handle=%d)\n", ret);
        g_mounted = 1;
        g_local_copy[0] = 0;
        return 0;
    }
    garlic_log("[Garlic] Mount new PS4 PFS failed (0x%x)\n", ret);
    return ret;
}

/* ── Mount freshly created PFS with zeroed key ─────────────────── */
int save_mount_new(const char *image_path) {
    if (g_mounted) save_unmount();

    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    uint8_t ckey[0x20] = {0};

    signal(SIGPIPE, SIG_DFL);
    int ret = sceFsMountSaveData(&mopt, image_path, GARLIC_MOUNT_POINT, ckey);
    signal(SIGPIPE, SIG_IGN);

    if (ret >= 0) {
        garlic_log("[Garlic] Mounted new PFS (handle=%d)\n", ret);
        g_mounted = 1;
        g_local_copy[0] = 0;
        return 0;
    }
    garlic_log("[Garlic] Mount new PFS failed (0x%x)\n", ret);
    return ret;
}

int save_is_mounted(void) { return g_mounted; }
const char *save_get_mount_point(void) { return GARLIC_MOUNT_POINT; }

/* ── Periodic cleanup ──────────────────────────────────────────── */
void save_periodic_cleanup(void) {
    /* Force unmount in case kernel state is stale */
    if (g_mounted) save_unmount();

    UmountOpt u0;
    memset(&u0, 0, sizeof(u0));
    sceFsInitUmountSaveDataOpt(&u0);
    sceFsUmountSaveData(&u0, GARLIC_MOUNT_POINT, 0, 0);
    g_mounted = 0;

    /* Clean up any leftover temp files in /data/save_files/ */
    DIR *d = opendir("/data/save_files");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (ent->d_name[0] == '.') continue;
            char fp[MAX_PATH_LEN];
            snprintf(fp, sizeof(fp), "/data/save_files/%s", ent->d_name);
            unlink(fp);
        }
        closedir(d);
    }

    garlic_log("[Garlic] Periodic cleanup done\n");
}
