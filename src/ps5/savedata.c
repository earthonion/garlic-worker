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

/* ── Mount existing save ───────────────────────────────────────── */
int save_mount(const char *save_path) {
    if (g_mounted) save_unmount();

    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    /* If save is NOT on /data/, copy there first (mount from other paths causes EPIPE) */
    const char *mount_src = save_path;
    g_local_copy[0] = 0;
    int is_on_data = (strncmp(save_path, "/data/", 6) == 0);

    if (!is_on_data) {
        const char *basename = strrchr(save_path, '/');
        basename = basename ? basename + 1 : save_path;
        snprintf(g_local_copy, sizeof(g_local_copy), "/data/save_files/%s", basename);
        garlic_log("[Garlic] Copying %s -> %s\n", save_path, g_local_copy);
        if (copy_file(save_path, g_local_copy) < 0) {
            garlic_log("[Garlic] Copy failed (errno %d)\n", errno);
            return -1;
        }
        chmod(g_local_copy, 0755);
        mount_src = g_local_copy;
    }

    /* Find and read sealed key (search for pfsSKKey magic near 0x800) */
    /* Heap-allocate ioctl buffer — ioctl may corrupt stack beyond buffer bounds */
    struct {
        uint8_t key[0x60];
        uint8_t hash[0x20];
        uint32_t result;
    } *pfsbuf = malloc(sizeof(*pfsbuf));
    if (!pfsbuf) return -2;
    memset(pfsbuf, 0, sizeof(*pfsbuf));

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

    /* Read wider region and search for pfsSKKey magic */
    uint8_t keybuf[0x80];
    int ret = pread(fd, keybuf, sizeof(keybuf), 0x800);
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
