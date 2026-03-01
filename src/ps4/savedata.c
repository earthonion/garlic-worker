#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <ps4/kernel.h>

#include "savedata.h"
#include "util.h"
#include "log.h"

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
    /* Extra stack buffer — ioctl damages stack (known PS4 quirk) */
    uint8_t dummy[0x30];
    uint8_t buf[0x60];
    (void)dummy;

    int fd = open("/dev/sbl_srv", O_RDWR);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot open /dev/sbl_srv (errno %d)\n", errno);
        return -1;
    }
    if (ioctl(fd, 0x40845303, buf) < 0) {
        close(fd);
        garlic_log("[Garlic] Generate sealed key ioctl failed\n");
        return -1;
    }
    close(fd);
    memcpy(key, buf, 96);
    return 0;
}

static int decrypt_sealed_key(const uint8_t sealed[96], uint8_t decrypted[32]) {
    /* Extra stack buffer — ioctl damages first 4 bytes (known PS4 quirk) */
    uint8_t dummy[0x10];
    uint8_t data[96 + 32];
    (void)dummy;

    int fd = open("/dev/sbl_srv", O_RDWR);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot open /dev/sbl_srv for decrypt (errno %d)\n", errno);
        return -1;
    }
    memcpy(data, sealed, 96);
    if (ioctl(fd, 0xc0845302, data) < 0) {
        close(fd);
        garlic_log("[Garlic] Decrypt sealed key ioctl failed\n");
        return -1;
    }
    close(fd);
    memcpy(decrypted, data + 96, 32);
    return 0;
}

static int get_keyset_from_sealed_key(const uint8_t sealed[96]) {
    return (sealed[9] << 8) | sealed[8];
}

/* ── Device node creation ──────────────────────────────────────── */

static void create_dev_nodes(void) {
    struct stat st;

    /* elfldr gives us access to /dev/ directly — create nodes if missing */
    const char *devs[] = { "pfsctldev", "lvdctl", "sbl_srv" };
    for (int i = 0; i < 3; i++) {
        char src[64];
        snprintf(src, sizeof(src), "/dev/%s", devs[i]);
        /* Check if already accessible */
        if (stat(src, &st) == 0) {
            garlic_log("[Garlic] /dev/%s already accessible (dev=%llu)\n",
                       devs[i], (unsigned long long)st.st_dev);
            continue;
        }
        /* Not accessible in sandbox — nothing we can do without jbc */
        garlic_log("[Garlic] /dev/%s not found, may need manual setup\n", devs[i]);
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
    /* Create device nodes */
    create_dev_nodes();

    /* Load private libraries */
    if (load_priv_libs() < 0) {
        garlic_log("[Garlic] FATAL: Cannot load save data libraries\n");
    }

    /* Force unmount any stale mounts from previous runs */
    if (fn_InitUmountOpt && fn_UmountSaveData) {
        UmountOpt u0;
        memset(&u0, 0, sizeof(u0));
        fn_InitUmountOpt(&u0);
        fn_UmountSaveData(&u0, GARLIC_MOUNT_POINT, 0, 0);
    }

    mkdir(GARLIC_MOUNT_POINT, 0777);
    mkdir("/data/save_files", 0777);
}

/* ── Mount existing save ───────────────────────────────────────── */
int save_mount(const char *save_path) {
    if (g_mounted) save_unmount();

    if (!fn_InitMountOpt || !fn_MountSaveData) {
        garlic_log("[Garlic] Mount functions not loaded\n");
        return -1;
    }

    /* Read sealed key from .bin companion file */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", save_path);

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

    /* Decrypt sealed key */
    uint8_t decrypted_key[32];
    if (decrypt_sealed_key(sealed_key, decrypted_key) < 0) {
        garlic_log("[Garlic] Failed to decrypt sealed key\n");
        return -3;
    }

    /* Mount */
    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    fn_InitMountOpt(&mopt);
    mopt.budgetid = "system";

    signal(SIGPIPE, SIG_DFL);
    int ret = fn_MountSaveData(&mopt, save_path, GARLIC_MOUNT_POINT, decrypted_key);
    signal(SIGPIPE, SIG_IGN);

    if (ret >= 0) {
        garlic_log("[Garlic] Mounted %s (handle=%d)\n", save_path, ret);
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
    fn_InitUmountOpt(&uopt);
    fn_UmountSaveData(&uopt, GARLIC_MOUNT_POINT, 0, 0);
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

    /* Generate sealed key */
    uint8_t sealed_key[96];
    if (generate_sealed_key(sealed_key) < 0) {
        garlic_log("[Garlic] Failed to generate sealed key\n");
        return -1;
    }

    /* Decrypt sealed key */
    uint8_t decrypted_key[32];
    if (decrypt_sealed_key(sealed_key, decrypted_key) < 0) {
        garlic_log("[Garlic] Failed to decrypt new sealed key\n");
        return -2;
    }

    /* Size: data + 25% overhead + 4MB, min 32MB, aligned to 32K */
    uint64_t img_size = data_size + (data_size / 4) + (4 * 1024 * 1024);
    if (img_size < 32 * 1024 * 1024)
        img_size = 32 * 1024 * 1024;
    img_size = ((img_size + 32767) / 32768) * 32768;

    /* Create and allocate image file */
    int fd = open(image_path, O_CREAT | O_TRUNC | O_RDWR, 0777);
    if (fd < 0) {
        garlic_log("[Garlic] Cannot create image %s (errno %d)\n", image_path, errno);
        return -3;
    }

    int ret = fn_UfsAllocateSaveData(fd, img_size, 0, 0);
    if (ret < 0) {
        garlic_log("[Garlic] UfsAllocate failed (0x%x), using ftruncate\n", ret);
        if (ftruncate(fd, img_size) < 0) {
            close(fd);
            unlink(image_path);
            return -4;
        }
    }
    close(fd);
    garlic_log("[Garlic] Created image %llu bytes\n", (unsigned long long)img_size);

    /* Format as PFS */
    CreateOpt copt;
    memset(&copt, 0, sizeof(copt));
    fn_InitCreateOpt(&copt);

    ret = fn_CreatePfsSaveDataImage(&copt, image_path, 0, img_size, decrypted_key);
    if (ret < 0) {
        garlic_log("[Garlic] CreatePfsSaveDataImage failed (0x%x)\n", ret);
        unlink(image_path);
        return -5;
    }

    /* Sync the image */
    fd = open(image_path, O_RDONLY);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }

    /* Write .bin companion with sealed key */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", image_path);
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

    /* Read back the sealed key from .bin and decrypt it */
    char bin_path[MAX_PATH_LEN];
    snprintf(bin_path, sizeof(bin_path), "%s.bin", image_path);

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

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    fn_InitMountOpt(&mopt);
    mopt.budgetid = "system";

    signal(SIGPIPE, SIG_DFL);
    int ret = fn_MountSaveData(&mopt, image_path, GARLIC_MOUNT_POINT, decrypted_key);
    signal(SIGPIPE, SIG_IGN);

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

int save_get_max_keyset(void) {
    if (g_max_keyset >= 0) return g_max_keyset;
    uint8_t sealed[96];
    if (generate_sealed_key(sealed) < 0) return 0;
    g_max_keyset = get_keyset_from_sealed_key(sealed);
    return g_max_keyset;
}
