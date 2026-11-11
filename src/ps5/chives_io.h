#ifndef GARLIC_CHIVES_IO_H
#define GARLIC_CHIVES_IO_H

#include "chives.h"

int chives_read_image(const char *image, chives_geometry_t *geometry);
int chives_verify_created(const char *image, const chives_geometry_t *expected);
int chives_read_file(const char *base, chives_geometry_t *geometry);
int chives_sfo_geometry(const char *base, chives_geometry_t *geometry);
int chives_write_export(const char *image, const char *mount, const char *dest,
                        const char *encrypted_name);

#endif
