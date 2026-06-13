#define DEBUG_SOCKET
#define DEBUG_IP "192.168.100.16"
#define DEBUG_PORT 9023

#include "ps4.h"
#include "syscall.h"

#define SYS_NAMEDOBJ_CREATE 557
#define SYS_NAMEDOBJ_DELETE 558

int _main(struct thread *td)
{
    UNUSED(td);

    initKernel();
    initLibc();

#ifdef DEBUG_SOCKET
    initNetwork();
    DEBUG_SOCK = SckConnect(DEBUG_IP, DEBUG_PORT);
#endif

    jailbreak();
    initSysUtil();

    int handles[8];
    int fd;

    printf_notification("=== Generation Wraparound ===");

    // object 
    fd = kqueue();

    int h0 = syscall(
        SYS_NAMEDOBJ_CREATE,
        "poc",
        fd,
        0x107
    );

    printf_debug("Initial handle: 0x%x\n", h0);
    printf_notification("Initial handle: 0x%x", h0);


    // delete + recreate
    for (int i = 0; i < 8; i++)
    {
        syscall(
            SYS_NAMEDOBJ_DELETE,
            h0 & 0x1fff,
            0x107
        );

        fd = kqueue();

        handles[i] = syscall(
            SYS_NAMEDOBJ_CREATE,
            "poc",
            fd,
            0x107
        );

        printf_debug(
            "Iteration %d handle: 0x%x\n",
            i,
            handles[i]
        );
    }


    // 3) check wrap
    printf_debug(
        "Original: 0x%x After wrap: 0x%x\n",
        h0,
        handles[7]
    );


    if ((handles[7] & 0xffff) == (h0 & 0xffff))
    {
        printf_notification(
            "WRAPAROUND CONFIRMED!"
        );
    }
    else
    {
        printf_notification(
            "No wrap"
        );
    }


#ifdef DEBUG_SOCKET
    SckClose(DEBUG_SOCK);
#endif

    return 0;
}