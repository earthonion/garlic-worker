#ifndef JSON_H
#define JSON_H

#include <stdint.h>

/* Minimal JSON field extractors for well-formed server responses */
int json_get_string(const char *json, const char *key, char *out, int out_size);
int json_get_int(const char *json, const char *key, int *out);
int json_get_int64(const char *json, const char *key, int64_t *out);
int json_get_object(const char *json, const char *key, char *out, int out_size);
int json_get_bool(const char *json, const char *key, int *out);

#endif
