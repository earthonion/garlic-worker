#ifndef LOG_H
#define LOG_H

/* Initialize file logging — opens /data/garlic/log.txt for append */
void log_init(void);

/* Write to both stdout and log file */
void garlic_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
