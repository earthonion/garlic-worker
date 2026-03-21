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
#include <sys/syscall.h>

#include <ps4/kernel.h>

#include "savedata.h"
#include "util.h"
#include "log.h"

/* ── Credential helpers for PFS operations ─────────────────────── */
static uint64_t g_orig_authid = 0;
static uint8_t  g_orig_caps[16];
static int      g_cred_saved = 0;

static void elevate_creds(void) {
    pid_t pid = getpid();
    garlic_log("[Garlic] elevate: pid=%d, getting authid...\n", pid);
    g_orig_authid = kernel_get_ucred_authid(pid);
    garlic_log("[Garlic] elevate: orig authid=0x%llx, getting caps...\n",
               (unsigned long long)g_orig_authid);
    kernel_get_ucred_caps(pid, g_orig_caps);
    garlic_log("[Garlic] elevate: got caps, setting authid...\n");
    g_cred_saved = 1;

    kernel_set_ucred_authid(pid, 0x3801000000000013ULL);
    garlic_log("[Garlic] elevate: authid set, setting caps...\n");
    uint8_t caps[16];
    memcpy(caps, g_orig_caps, 16);
    caps[7] |= 0x40;
    kernel_set_ucred_caps(pid, caps);
    garlic_log("[Garlic] elevate: caps set, calling setuid(0)...\n");
    setuid(0);
    garlic_log("[Garlic] elevate: done\n");
}

static void restore_creds(void) {
    if (!g_cred_saved) return;
    pid_t pid = getpid();
    kernel_set_ucred_authid(pid, g_orig_authid);
    kernel_set_ucred_caps(pid, g_orig_caps);
    g_cred_saved = 0;
}

/* ── SDK type definitions ──────────────────────────────────────── */
typedef struct { uint8_t reserved; char *budgetid; } MountOpt;
typedef struct { uint8_t dummy; } UmountOpt;
typedef struct { int blockSize; uint8_t flags[2]; } CreateOpt;

/* ── Function pointers (resolved via dlsym) ────────────────────── */
static int (*fn_InitMountOpt)(MountOpt *opt);
static int (*fn_MountSaveData)(MountOpt *opt, const char *path, const char *mount, uint8_t *key);
static int (*fn_InitUmountOpt)(UmountOpt *opt);
static int (*fn_UmountSaveData)(UmountOpt *opt, const char *mount, int handle, int ignore);
static int (*fn_InitCreateOpt)(CreateOpt *opt);
static int (*fn_CreatePfsSaveDataImage)(CreateOpt *opt, const char *path, int x, uint64_t size, uint8_t *key);
static int (*fn_UfsAllocateSaveData)(int fd, uint64_t size, uint64_t flags, int ext);

/* ── SDK imports ───────────────────────────────────────────────── */
int sceKernelLoadStartModule(const char *path, size_t args, const void *argp,
                              unsigned int flags, void *opt, int *res);
int sceKernelDlsym(int handle, const char *symbol, void **addr);
int sceUserServiceInitialize(void *);

/* ── Globals ───────────────────────────────────────────────────── */
static int g_mounted = 0;
static int g_max_keyset = -1;

/* ── Sealed key operations via /dev/sbl_srv ────────────────────── */

static int generate_sealed_key(uint8_t key[96]) {
    /* Heap-allocate ioctl buffer — ioctl corrupts stack beyond buffer bounds */
    uint8_t *buf = malloc(0x100);
    if (!buf) return -1;
    memset(buf, 0, 0x100);

    int fd = open("/dev/sbl_srv", O_RDWR);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot open /dev/sbl_srv (errno %d)\n", errno);
        free(buf);
        return -1;
    }
    if (ioctl(fd, 0x40845303, buf) < 0) {
        close(fd);
        free(buf);
        garlic_log("[Garlic] Generate sealed key ioctl failed\n");
        return -1;
    }
    close(fd);
    memcpy(key, buf, 96);
    free(buf);
    return 0;
}

static int decrypt_sealed_key(const uint8_t sealed[96], uint8_t decrypted[32]) {
    /* Heap-allocate ioctl buffer — ioctl corrupts stack beyond buffer bounds */
    uint8_t *data = malloc(0x100);
    if (!data) return -1;
    memset(data, 0, 0x100);

    int fd = open("/dev/sbl_srv", O_RDWR);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot open /dev/sbl_srv for decrypt (errno %d)\n", errno);
        free(data);
        return -1;
    }
    memcpy(data, sealed, 96);
    if (ioctl(fd, 0xc0845302, data) < 0) {
        close(fd);
        free(data);
        garlic_log("[Garlic] Decrypt sealed key ioctl failed\n");
        return -1;
    }
    close(fd);
    memcpy(decrypted, data + 96, 32);
    free(data);
    return 0;
}

static int get_keyset_from_sealed_key(const uint8_t sealed[96]) {
    return (sealed[9] << 8) | sealed[8];
}

/* ── Device node check ─────────────────────────────────────────── */

static void check_dev_nodes(void) {
    struct stat st;
    const char *devs[] = { "pfsctldev", "lvdctl", "sbl_srv" };

    for (int i = 0; i < 3; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/%s", devs[i]);
        if (stat(path, &st) == 0) {
            garlic_log("[Garlic] /dev/%s OK (dev=%llu)\n",
                       devs[i], (unsigned long long)st.st_dev);
        } else {
            garlic_log("[Garlic] /dev/%s not found (errno %d)\n", devs[i], errno);
        }
    }
}

/* ── Library loading ───────────────────────────────────────────── */

static int load_priv_libs(void) {
    /* elfldr gives us direct filesystem access — load from real path */
    int handle = sceKernelLoadStartModule("/system/priv/lib/libSceFsInternalForVsh.sprx",
                                           0, NULL, 0, NULL, NULL);

    if (handle < 0) {
        garlic_log("[Garlic] Failed to load libSceFsInternalForVsh (0x%x)\n", handle);
        return -1;
    }

    /* Resolve all function pointers */
    sceKernelDlsym(handle, "sceFsInitMountSaveDataOpt", (void **)&fn_InitMountOpt);
    sceKernelDlsym(handle, "sceFsMountSaveData", (void **)&fn_MountSaveData);
    sceKernelDlsym(handle, "sceFsInitUmountSaveDataOpt", (void **)&fn_InitUmountOpt);
    sceKernelDlsym(handle, "sceFsUmountSaveData", (void **)&fn_UmountSaveData);
    sceKernelDlsym(handle, "sceFsInitCreatePfsSaveDataOpt", (void **)&fn_InitCreateOpt);
    sceKernelDlsym(handle, "sceFsCreatePfsSaveDataImage", (void **)&fn_CreatePfsSaveDataImage);
    sceKernelDlsym(handle, "sceFsUfsAllocateSaveData", (void **)&fn_UfsAllocateSaveData);

    int ok = fn_InitMountOpt && fn_MountSaveData && fn_InitUmountOpt &&
             fn_UmountSaveData && fn_InitCreateOpt && fn_CreatePfsSaveDataImage &&
             fn_UfsAllocateSaveData;

    garlic_log("[Garlic] libSceFsInternalForVsh: %s\n", ok ? "all symbols resolved" : "MISSING SYMBOLS");
    return ok ? 0 : -1;
}

/* ── Init ──────────────────────────────────────────────────────── */
void savedata_init(void) {
    /* Elevate credentials first (Apollo pattern: creds → libs → devices) */
    elevate_creds();

    /* Check device nodes are accessible */
    check_dev_nodes();

    /* Load private libraries */
    if (load_priv_libs() < 0) {
        garlic_log("[Garlic] FATAL: Cannot load save data libraries\n");
    }

    /* Force unmount any stale mounts from previous runs */
    if (fn_InitUmountOpt && fn_UmountSaveData) {
        uint8_t u0_buf[256];
        memset(u0_buf, 0, sizeof(u0_buf));
        fn_InitUmountOpt((UmountOpt *)u0_buf);
        fn_UmountSaveData((UmountOpt *)u0_buf, GARLIC_MOUNT_POINT, 0, 0);
    }

    mkdir(GARLIC_MOUNT_POINT, 0777);
    mkdir("/data/save_files", 0777);

    /* Keep creds elevated — PFS operations require them */
    garlic_log("[Garlic] savedata_init complete\n");
}

/* ── Mount existing save ───────────────────────────────────────── */
int save_mount(const char *save_path) {
    if (g_mounted) save_unmount();

    if (!fn_InitMountOpt || !fn_MountSaveData) {
        garlic_log("[Garlic] Mount functions not loaded\n");
        return -1;
    }

    /* Save path early — ioctl/init calls corrupt the stack */
    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, save_path, MAX_PATH_LEN - 1);
    path_copy[MAX_PATH_LEN - 1] = 0;

    /* Read sealed key from .bin companion file */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", path_copy);

    uint8_t sealed_key[96];
    int fd = open(bin_path, O_RDONLY);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot open sealed key %s (errno %d)\n", bin_path, errno);
        return -1;
    }
    int r = read(fd, sealed_key, 96);
    close(fd);
    if (r != 96) {
        garlic_log("[Garlic] Short read on sealed key (%d bytes)\n", r);
        return -2;
    }
    garlic_log("[Garlic] Read sealed key OK (%d bytes, keyset=%d)\n",
               r, get_keyset_from_sealed_key(sealed_key));

    /* Decrypt sealed key */
    garlic_log("[Garlic] Decrypting sealed key...\n");
    uint8_t decrypted_key[32];
    if (decrypt_sealed_key(sealed_key, decrypted_key) < 0) {
        garlic_log("[Garlic] Failed to decrypt sealed key\n");
        return -3;
    }
    garlic_log("[Garlic] Sealed key decrypted OK\n"); log_flush();

    /* Use InitMountOpt but with path already saved in path_copy */
    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    fn_InitMountOpt(&mopt);
    mopt.budgetid = "system";

    garlic_log("[Garlic] Calling MountSaveData(%s)...\n", path_copy); log_flush();
    int ret = fn_MountSaveData(&mopt, path_copy, GARLIC_MOUNT_POINT, decrypted_key);
    garlic_log("[Garlic] MountSaveData returned 0x%x\n", ret); log_flush();

    if (ret >= 0) {
        garlic_log("[Garlic] Mounted (handle=%d)\n", ret);
        g_mounted = 1;
        return 0;
    }
    garlic_log("[Garlic] Mount failed (0x%x, errno=%d)\n", ret, errno);
    return ret;
}

/* ── Unmount ───────────────────────────────────────────────────── */
int save_unmount(void) {
    if (!g_mounted) return 0;

    uint8_t uopt_buf[256];
    memset(uopt_buf, 0, sizeof(uopt_buf));
    fn_InitUmountOpt((UmountOpt *)uopt_buf);
    fn_UmountSaveData((UmountOpt *)uopt_buf, GARLIC_MOUNT_POINT, 0, 0);
    sync();

    g_mounted = 0;
    return 0;
}

/* ── Create new PFS image ──────────────────────────────────────── */
int save_create_pfs(const char *image_path, uint64_t data_size) {
    if (!fn_InitCreateOpt || !fn_CreatePfsSaveDataImage || !fn_UfsAllocateSaveData) {
        garlic_log("[Garlic] PFS create functions not loaded\n");
        return -1;
    }

    /* Save path early — ioctl calls corrupt the stack */
    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, image_path, MAX_PATH_LEN - 1);
    path_copy[MAX_PATH_LEN - 1] = 0;

    /* Generate sealed key */
    garlic_log("[Garlic] create_pfs: generating sealed key...\n"); log_flush();
    uint8_t sealed_key[96];
    if (generate_sealed_key(sealed_key) < 0) {
        garlic_log("[Garlic] Failed to generate sealed key\n");
        return -1;
    }
    garlic_log("[Garlic] create_pfs: sealed key generated OK\n"); log_flush();

    /* Decrypt sealed key */
    uint8_t decrypted_key[32];
    if (decrypt_sealed_key(sealed_key, decrypted_key) < 0) {
        garlic_log("[Garlic] Failed to decrypt new sealed key\n");
        return -2;
    }
    garlic_log("[Garlic] create_pfs: sealed key decrypted OK\n"); log_flush();

    /* Use exact size from SAVEDATA_BLOCKS — no overhead needed.
     * The PS4 expects the image to be exactly blocks * 32KB. */
    uint64_t img_size = data_size;
    if (img_size < 32 * 1024 * 1024)
        img_size = 32 * 1024 * 1024;
    img_size = ((img_size + 32767) / 32768) * 32768;

    /* Create and allocate image file */
    int fd = open(path_copy, O_CREAT | O_TRUNC | O_RDWR, 0777);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot create image %s (errno %d)\n", path_copy, errno);
        return -3;
    }

    elevate_creds();
    int ret = fn_UfsAllocateSaveData(fd, img_size, 0, 0);
    if (ret < 0) {
        garlic_log("[Garlic] UfsAllocate failed (0x%x), using ftruncate\n", ret);
        if (ftruncate(fd, img_size) < 0) {
            restore_creds();
            close(fd);
            unlink(path_copy);
            return -4;
        }
    }
    close(fd);
    garlic_log("[Garlic] Created image %llu bytes\n", (unsigned long long)img_size);

    /* Format as PFS */
    CreateOpt copt;
    memset(&copt, 0, sizeof(copt));
    fn_InitCreateOpt(&copt);

    ret = fn_CreatePfsSaveDataImage(&copt, path_copy, 0, img_size, decrypted_key);
    restore_creds();
    if (ret < 0) {
        garlic_log("[Garlic] CreatePfsSaveDataImage failed (0x%x)\n", ret);
        unlink(path_copy);
        return -5;
    }

    /* Sync the image */
    fd = open(path_copy, O_RDONLY);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }

    /* Write .bin companion with sealed key */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", path_copy);
    fd = open(bin_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, sealed_key, 96);
        close(fd);
    } else {
        garlic_log("[Garlic] Warning: failed to write sealed key .bin\n");
    }

    garlic_log("[Garlic] Formatted PFS image OK\n");
    return 0;
}

/* ── Mount freshly created PFS with decrypted key ──────────────── */
int save_mount_new(const char *image_path) {
    if (g_mounted) save_unmount();

    if (!fn_InitMountOpt || !fn_MountSaveData) {
        garlic_log("[Garlic] Mount functions not loaded\n");
        return -1;
    }

    /* Save path early — ioctl calls corrupt the stack */
    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, image_path, MAX_PATH_LEN - 1);
    path_copy[MAX_PATH_LEN - 1] = 0;

    /* Read back the sealed key from .bin and decrypt it */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", path_copy);

    uint8_t sealed_key[96];
    int fd = open(bin_path, O_RDONLY);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot open .bin for new mount\n");
        return -2;
    }
    read(fd, sealed_key, 96);
    close(fd);

    uint8_t decrypted_key[32];
    if (decrypt_sealed_key(sealed_key, decrypted_key) < 0) {
        garlic_log("[Garlic] Failed to decrypt key for new mount\n");
        return -3;
    }

    /* Use InitMountOpt with path already saved */
    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    fn_InitMountOpt(&mopt);
    mopt.budgetid = "system";

    garlic_log("[Garlic] Calling MountSaveData(%s) [new]...\n", path_copy); log_flush();
    int ret = fn_MountSaveData(&mopt, path_copy, GARLIC_MOUNT_POINT, decrypted_key);
    garlic_log("[Garlic] MountSaveData returned 0x%x\n", ret); log_flush();

    if (ret >= 0) {
        garlic_log("[Garlic] Mounted new PFS (handle=%d)\n", ret);
        g_mounted = 1;
        return 0;
    }
    garlic_log("[Garlic] Mount new PFS failed (0x%x)\n", ret);
    return ret;
}

int save_is_mounted(void) { return g_mounted; }
const char *save_get_mount_point(void) { return GARLIC_MOUNT_POINT; }

void save_periodic_cleanup(void) {
    /* Force unmount in case kernel state is stale */
    if (g_mounted) save_unmount();

    if (fn_InitUmountOpt && fn_UmountSaveData) {
        uint8_t u0_buf[256];
        memset(u0_buf, 0, sizeof(u0_buf));
        fn_InitUmountOpt((UmountOpt *)u0_buf);
        fn_UmountSaveData((UmountOpt *)u0_buf, GARLIC_MOUNT_POINT, 0, 0);
    }
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

int save_get_max_keyset(void) {
    if (g_max_keyset >= 0) return g_max_keyset;
    uint8_t sealed[96];
    if (generate_sealed_key(sealed) < 0) return 0;
    g_max_keyset = get_keyset_from_sealed_key(sealed);
    return g_max_keyset;
}
