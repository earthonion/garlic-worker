#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "killswitch.h"
#include "log.h"

static void *killswitch_thread(void *arg) {
    int port = (int)(intptr_t)arg;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return NULL;

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv);
        garlic_log("[Garlic] Kill switch: bind failed on port %d\n", port);
        return NULL;
    }

    listen(srv, 1);
    garlic_log("[Garlic] Kill switch listening on port %d\n", port);

    while (1) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) continue;

        char buf[16] = {0};
        ssize_t n = read(cli, buf, sizeof(buf) - 1);
        close(cli);

        if (n <= 0) continue;

        /* Strip trailing whitespace */
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' '))
            buf[--n] = '\0';

        if (strcmp(buf, "kill") == 0) {
            garlic_log("[Garlic] Kill switch activated!\n");
            kill(getpid(), SIGKILL);
        }
    }

    return NULL;
}

void killswitch_start(int port) {
    pthread_t tid;
    pthread_create(&tid, NULL, killswitch_thread, (void *)(intptr_t)port);
    pthread_detach(tid);
}
