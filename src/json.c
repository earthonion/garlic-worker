#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "json.h"

/* Find the value position for a given key in JSON.
 * Returns pointer to start of value (after colon + whitespace), or NULL. */
static const char *find_key(const char *json, const char *key) {
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *p = json;
    while ((p = strstr(p, needle)) != NULL) {
        p += strlen(needle);
        /* Skip whitespace and colon */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == ':') {
            p++;
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
            return p;
        }
    }
    return NULL;
}

int json_get_string(const char *json, const char *key, char *out, int out_size) {
    const char *val = find_key(json, key);
    if (!val || *val != '"') return -1;

    val++; /* skip opening quote */
    int i = 0;
    while (*val && *val != '"' && i < out_size - 1) {
        if (*val == '\\' && val[1]) {
            val++;
            switch (*val) {
                case '"':  out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                case '/':  out[i++] = '/'; break;
                case 'n':  out[i++] = '\n'; break;
                case 't':  out[i++] = '\t'; break;
                default:   out[i++] = *val; break;
            }
        } else {
            out[i++] = *val;
        }
        val++;
    }
    out[i] = 0;
    return i;
}

int json_get_int(const char *json, const char *key, int *out) {
    const char *val = find_key(json, key);
    if (!val) return -1;
    if (*val == '"') {
        /* Quoted integer */
        val++;
        *out = atoi(val);
    } else {
        *out = atoi(val);
    }
    return 0;
}

int json_get_int64(const char *json, const char *key, int64_t *out) {
    const char *val = find_key(json, key);
    if (!val) return -1;
    if (*val == '"') val++;
    *out = strtoll(val, NULL, 10);
    return 0;
}

int json_get_bool(const char *json, const char *key, int *out) {
    const char *val = find_key(json, key);
    if (!val) return -1;
    if (strncmp(val, "true", 4) == 0) { *out = 1; return 0; }
    if (strncmp(val, "false", 5) == 0) { *out = 0; return 0; }
    return -1;
}

int json_get_object(const char *json, const char *key, char *out, int out_size) {
    const char *val = find_key(json, key);
    if (!val) return -1;

    if (*val == '{') {
        int depth = 0;
        const char *start = val;
        while (*val) {
            if (*val == '{') depth++;
            else if (*val == '}') { depth--; if (depth == 0) { val++; break; } }
            else if (*val == '"') {
                val++;
                while (*val && *val != '"') {
                    if (*val == '\\') val++;
                    val++;
                }
            }
            val++;
        }
        int len = val - start;
        if (len >= out_size) len = out_size - 1;
        memcpy(out, start, len);
        out[len] = 0;
        return len;
    } else if (*val == 'n' && strncmp(val, "null", 4) == 0) {
        snprintf(out, out_size, "{}");
        return 2;
    }
    return -1;
}
