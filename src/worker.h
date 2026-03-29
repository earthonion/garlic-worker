#ifndef WORKER_H
#define WORKER_H

#include "config.h"

/* Start the HTTP polling worker loop (never returns) */
void worker_loop(worker_config_t *cfg);

/* Start the TCP direct-connect worker loop (never returns) */
void worker_loop_tcp(worker_config_t *cfg);

#endif
