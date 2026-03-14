#ifndef KILLSWITCH_H
#define KILLSWITCH_H

/* Start a background thread listening on the given port.
 * When "kill" is received, SIGKILL the process. */
void killswitch_start(int port);

#endif
