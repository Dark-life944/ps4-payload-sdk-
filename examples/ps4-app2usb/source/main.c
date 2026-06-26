#include "ps4.h"

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
    pfd.events = 1;     // POLLIN
    pfd.revents = 0;


    printf_notification("Entering poll");


    int ret = poll(
        &pfd,
        1,
        -1
    );


    printf_debug(
        "poll returned %d",
        ret
    );


    scePthreadExit(NULL);

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
    initSysUtil();



    char socketName[] = "polltest";


    sockfd = sceNetSocket(
        socketName,
        AF_INET,
        SOCK_STREAM,
        0
    );


    if(sockfd < 0)
    {
        printf_debug("sceNetSocket failed");
        return 0;
    }



    ScePthread thread;


    scePthreadCreate(
        &thread,
        NULL,
        poll_thread,
        (void *)(long)sockfd,
        "poll_thread"
    );



    sceKernelSleep(1);



    printf_debug("closing socket");


    sceNetSocketClose(sockfd);



    scePthreadJoin(
        thread,
        NULL
    );


    printf_debug("done");


    return 0;
}