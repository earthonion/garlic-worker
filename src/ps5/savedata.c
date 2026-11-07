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

/* Real param.sfo recovered from PS5PARAM blob (cached per mount) */
static uint8_t g_mount_real_sfo[0x8000];
static uint32_t g_mount_real_sfo_len = 0;

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
int detect_is_ps4(const char *image_path) {
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
    int ret = sceFsUmountSaveData(&uopt, GARLIC_MOUNT_POINT, 0, 0);
    sync();
    if (ret < 0)
        garlic_log("[Garlic] Unmount failed (0x%x, errno=%d)\n", ret, errno);

    g_mounted = 0;
    g_local_copy[0] = 0;
    g_mount_real_sfo_len = 0;
    return ret;
}

/* ── Create new PFS image ──────────────────────────────────────── */
int save_create_pfs(const char *image_path, uint64_t size, int exact) {
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    uint64_t img_size;
    if (exact) {
        img_size = ((size + 32767) / 32768) * 32768;
    } else {
        img_size = size + (size / 4) + (4 * 1024 * 1024);
        img_size = ((img_size + 32767) / 32768) * 32768;
    }

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

    /* Format as PFS */
    if (!g_pprCreate) {
        garlic_log("[Garlic] PprCreate not available\n");
        unlink(image_path);
        return -3;
    }

    CreateOpt copt;
    memset(&copt, 0, sizeof(copt));
    sceFsInitCreatePfsSaveDataOpt(&copt);
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
int save_mount_new(const char *image_path, const uint8_t *key) {
    if (g_mounted) save_unmount();

    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    uint8_t ckey[0x20] = {0};
    if (key) memcpy(ckey, key, sizeof(ckey));

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

/* ── PS5PARAM blob I/O ─────────────────────────────────────────────
 * PS5 (ppr) saves keep the real param.sfo in an encrypted 0x8000-byte blob
 * in the image header at 0xC00.  The kernel exposes the blob through
 * sceFsTransactionSaveDataReadParam/WriteParam, which handles its encryption.
 * Blob layout: 'PS5PARAM' u64 | u32 ver=0 | u32 sfo_size | u32 sfo_off=20 | SFO
 */
static void ps5param_elevate(void) {
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);
    uint8_t caps[16];
    kernel_get_ucred_caps(getpid(), caps);
    caps[7] |= 0x40;
    kernel_set_ucred_caps(getpid(), caps);
    setuid(0);
}

static int ps5param_enable_blob_mode(const char *img, uint64_t *saved) {
    if (!img || !img[0] || !saved) return -1;
    *saved = 0;
    int fd = open(img, O_RDWR);
    if (fd < 0) return -errno;
    uint8_t type = 0;
    uint8_t raw[8];
    if (pread(fd, &type, 1, 0) != 1 || type != 0x02 ||
        pread(fd, raw, 8, 0x368) != 8) {
        close(fd);
        return -1;
    }
    uint64_t cur;
    memcpy(&cur, raw, 8);
    *saved = cur;
    uint32_t lo;
    memcpy(&lo, raw, 4);
    if ((lo & 0xFF) == 0x60) { close(fd); return 0; }
    uint32_t mode32 = 0x60;
    if (pwrite(fd, &mode32, 4, 0x368) != 4) { close(fd); return -1; }
    fsync(fd);
    close(fd);
    garlic_log("[Garlic] PS5PARAM: enabled blob mode (0x368 lo=0x60, was 0x%08x)\n", lo);
    return 1;
}

int ps5param_read_sfo(const char *img, uint8_t *sfo, uint32_t sfomax) {
    if (!img || !img[0] || !sfo || sfomax < 20) return -1;
    static uint8_t blob[0x8000];
    memset(blob, 0, sizeof(blob));
    ps5param_elevate();
    int r = sceFsTransactionSaveDataReadParam(img, blob, sizeof(blob));
    if (r < 0) return r;

    uint64_t magic;
    uint32_t ver, sz, off;
    memcpy(&magic, blob, 8);
    memcpy(&ver, blob + 8, 4);
    memcpy(&sz, blob + 12, 4);
    memcpy(&off, blob + 16, 4);
    if (magic != 0x4D41524150355350ULL) return 0;
    if (ver != 0 || sz == 0 || sz > sfomax || off < 20 ||
        (uint64_t)off + sz > sizeof(blob)) {
        garlic_log("[Garlic] PS5PARAM: bad blob header ver=%u size=%u off=%u\n", ver, sz, off);
        return -1002;
    }
    memcpy(sfo, blob + off, sz);
    return (int)sz;
}

int ps5param_write_sfo(const char *img, const uint8_t *sfo, uint32_t sz) {
    if (!img || !img[0] || !sfo || sz < 20 || sz > 0x8000 - 20)
        return -1;
    static uint8_t blob[0x8000];
    memset(blob, 0, sizeof(blob));
    uint64_t magic = 0x4D41524150355350ULL;
    uint32_t ver = 0, off = 20;
    memcpy(blob, &magic, 8);
    memcpy(blob + 8, &ver, 4);
    memcpy(blob + 12, &sz, 4);
    memcpy(blob + 16, &off, 4);
    memcpy(blob + 20, sfo, sz);

    ps5param_elevate();
    int r = sceFsTransactionSaveDataWriteParam(img, blob, sizeof(blob));
    if (r < 0) {
        uint64_t saved = 0;
        int en = ps5param_enable_blob_mode(img, &saved);
        if (en == 1) {
            garlic_log("[Garlic] PS5PARAM: retrying blob write after enabling mode\n");
            r = sceFsTransactionSaveDataWriteParam(img, blob, sizeof(blob));
            if (r < 0) {
                int fd = open(img, O_RDWR);
                if (fd >= 0) {
                    pwrite(fd, &saved, 8, 0x368);
                    close(fd);
                }
            }
        }
    }
    return r;
}

void ps5param_capture_for_image(const char *img) {
    g_mount_real_sfo_len = 0;
    if (!img || !img[0]) return;
    struct stat st;
    if (stat(img, &st) < 0 || !S_ISREG(st.st_mode)) return;
    int r = ps5param_read_sfo(img, g_mount_real_sfo, sizeof(g_mount_real_sfo));
    if (r > 0) {
        g_mount_real_sfo_len = (uint32_t)r;
        garlic_log("[Garlic] PS5PARAM: cached real param.sfo (%d B)\n", r);
    } else if (r < 0) {
        garlic_log("[Garlic] PS5PARAM: no blob read (%d)\n", r);
    }
}

int sfo_all_zero_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint8_t buf[4096];
    ssize_t nr;
    int zero = 1;
    while ((nr = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < nr; i++) {
            if (buf[i]) { zero = 0; break; }
        }
        if (!zero) break;
    }
    close(fd);
    return zero;
}

int ps5param_export_blob(const char *img, const char *dest) {
    static uint8_t blob[0x8000];
    int sfd = open(img, O_RDONLY);
    if (sfd < 0) return -1;
    ssize_t nr = pread(sfd, blob, sizeof(blob), 0xC00);
    close(sfd);
    if (nr != (ssize_t)sizeof(blob)) return -1;
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(blob); i++) {
        if (blob[i]) { nonzero = 1; break; }
    }
    if (!nonzero) return -2;
    int dfd = open(dest, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (dfd < 0) return -1;
    ssize_t nw = write(dfd, blob, sizeof(blob));
    fsync(dfd);
    close(dfd);
    return nw == (ssize_t)sizeof(blob) ? 0 : -1;
}

int ps5param_restore_blob(const char *img, const char *sidecar) {
    static uint8_t blob[0x8000];
    int sfd = open(sidecar, O_RDONLY);
    if (sfd < 0) return -1;
    ssize_t nr = read(sfd, blob, sizeof(blob));
    close(sfd);
    if (nr != (ssize_t)sizeof(blob)) return -1;
    int dfd = open(img, O_RDWR);
    if (dfd < 0) return -1;
    ssize_t nw = pwrite(dfd, blob, sizeof(blob), 0xC00);
    fsync(dfd);
    close(dfd);
    return nw == (ssize_t)sizeof(blob) ? 0 : -1;
}

int sfo_bytes_valid(const uint8_t *buf, size_t size) {
    if (!buf || size < 20) return 0;
    if (buf[0] != 0x00 || buf[1] != 'P' || buf[2] != 'S' || buf[3] != 'F') return 0;
    int all_zero = 1;
    size_t check_len = size < 256 ? size : 256;
    for (size_t i = 0; i < check_len; i++)
        if (buf[i]) { all_zero = 0; break; }
    if (all_zero) return 0;
    uint32_t koff, doff, nent;
    memcpy(&koff, buf + 8, 4);
    memcpy(&doff, buf + 12, 4);
    memcpy(&nent, buf + 16, 4);
    if (nent == 0 || nent > 64) return 0;
    if (koff >= size || doff >= size) return 0;
    if (20 + (uint64_t)nent * 16 > size) return 0;
    return 1;
}

int install_sfo_file(const char *path, const uint8_t *buf, uint32_t len) {
    if (!path || !buf || !len) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t w = write(fd, buf, len);
    close(fd);
    if (w != (ssize_t)len) return -1;
    garlic_log("[Garlic] Installed real param.sfo (%u B) -> %s\n", len, path);
    return 0;
}

int read_effective_param_sfo(const char *sfo_path, uint8_t *buf,
                             uint32_t bufsize, int *from_blob) {
    if (from_blob) *from_blob = 0;
    if (g_mount_real_sfo_len &&
        sfo_bytes_valid(g_mount_real_sfo, g_mount_real_sfo_len)) {
        uint32_t n = g_mount_real_sfo_len <= bufsize ? g_mount_real_sfo_len : bufsize;
        memcpy(buf, g_mount_real_sfo, n);
        if (from_blob) *from_blob = 1;
        return (int)n;
    }
    if (!sfo_path) return 0;
    int fd = open(sfo_path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, bufsize);
    close(fd);
    if (n <= 0) return -1;
    if (!sfo_bytes_valid(buf, (size_t)n)) return 0;
    return (int)n;
}

/* In-memory SAVEDATA_BLOCKS parser (same logic as file-based version) */
int sfo_read_savedata_blocks_mem(const uint8_t *buf, size_t size) {
    if (!buf || size < 20) return 0;
    if (buf[0] != 0x00 || buf[1] != 'P' || buf[2] != 'S' || buf[3] != 'F') return 0;
    uint32_t key_off, data_off, count;
    memcpy(&key_off, buf + 8, 4);
    memcpy(&data_off, buf + 12, 4);
    memcpy(&count, buf + 16, 4);
    for (uint32_t i = 0; i < count; i++) {
        size_t eoff = 20 + (size_t)i * 16;
        if (eoff + 16 > size) break;
        uint16_t k_off;
        memcpy(&k_off, buf + eoff, 2);
        uint32_t d_off;
        memcpy(&d_off, buf + eoff + 12, 4);
        size_t kpos = key_off + k_off;
        if (kpos + 15 >= size) continue;
        if (memcmp(buf + kpos, "SAVEDATA_BLOCKS", 15) == 0 && buf[kpos + 15] == 0) {
            size_t dpos = data_off + d_off;
            if (dpos + 4 > size) continue;
            uint32_t blocks = 0;
            memcpy(&blocks, buf + dpos, 4);
            return (int)blocks;
        }
    }
    return 0;
}

uint32_t ps5param_get_cached_sfo_len(void) { return g_mount_real_sfo_len; }
const uint8_t *ps5param_get_cached_sfo(void) { return g_mount_real_sfo; }

int sfo_read_savedata_blocks(const char *sfo_path) {
    int fd = open(sfo_path, O_RDONLY);
    if (fd < 0) return 0;
    uint8_t hdr[20];
    if (read(fd, hdr, 20) != 20 ||
        hdr[0] != 0x00 || hdr[1] != 0x50 || hdr[2] != 0x53 || hdr[3] != 0x46) {
        close(fd);
        return 0;
    }
    uint32_t key_off, data_off, count;
    memcpy(&key_off, hdr + 8, 4);
    memcpy(&data_off, hdr + 12, 4);
    memcpy(&count, hdr + 16, 4);
    for (uint32_t i = 0; i < count; i++) {
        uint8_t entry[16];
        if (pread(fd, entry, 16, 20 + i * 16) != 16) break;
        uint16_t k_off;
        memcpy(&k_off, entry, 2);
        uint32_t d_off;
        memcpy(&d_off, entry + 12, 4);
        char key[32] = {0};
        if (pread(fd, key, sizeof(key) - 1, key_off + k_off) <= 0) continue;
        if (strcmp(key, "SAVEDATA_BLOCKS") == 0) {
            uint32_t blocks = 0;
            pread(fd, &blocks, 4, data_off + d_off);
            close(fd);
            return (int)blocks;
        }
    }
    close(fd);
    return 0;
}
