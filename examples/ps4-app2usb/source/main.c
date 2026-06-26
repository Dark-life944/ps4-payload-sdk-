#include "ps4.h"

#define POLLIN 0x0001

struct pollfd {
    int fd;
    short events;
    short revents;
};


int (*poll)(struct pollfd *fds, unsigned long nfds, int timeout);



void initPoll()
{
    RESOLVE(libKernelHandle, poll);
}



static int sockfd;


void *poll_thread(void *arg)
{
    int sock = (int)(long)arg;

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;

    printf_notification("poll enter");

    int ret = poll(&pfd, 1, -1);

    printf_debug("poll returned %d revents %x",
                 ret,
                 pfd.revents);

    return NULL;
}


void *close_thread(void *arg)
{
    int sock = (int)(long)arg;

    sceKernelSleep(1);

    printf_notification("closing");

    sceNetSocketClose(sock);

    return NULL;
}


int _main(struct thread *td)
{
    UNUSED(td);

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initPoll();

    jailbreak();

    sockfd = sceNetSocket(
        "polltest",
        AF_INET,
        SOCK_STREAM,
        0
    );


    ScePthread pollTh;
    ScePthread closeTh;


    scePthreadCreate(
        &pollTh,
        NULL,
        poll_thread,
        (void *)(long)sockfd,
        "poll"
    );


    scePthreadCreate(
        &closeTh,
        NULL,
        close_thread,
        (void *)(long)sockfd,
        "close"
    );


    scePthreadJoin(closeTh,NULL);
    scePthreadJoin(pollTh,NULL);


    printf_debug("done");

    return 0;
}