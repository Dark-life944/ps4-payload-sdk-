#include "ps4.h"

#define SYS_SET_TIMEZONE_INFO 636

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== debug ===\n");

    // td + 0x130 = td_ucred pointer
    uint64_t ucred_ptr = *(uint64_t*)((char*)td + 0x130);
    printf_debug("td       = %p\n",   td);
    printf_debug("ucred    = 0x%lx\n", ucred_ptr);

    // ucred + 0x60 = sonyCred
    uint64_t sonyCred = *(uint64_t*)(ucred_ptr + 0x60);
    printf_debug("sonyCred = 0x%lx\n", sonyCred);
    printf_debug("bit62    = %d\n", (int)((sonyCred >> 62) & 1));

    // لو bit62 = 0 نضبطه
    if (((sonyCred >> 62) & 1) == 0) {
        printf_debug("fixing...\n");
        *(uint64_t*)(ucred_ptr + 0x60) = 0xffffffffffffffff;
        sonyCred = *(uint64_t*)(ucred_ptr + 0x60);
        printf_debug("sonyCred after = 0x%lx\n", sonyCred);
    }

    // الآن جرب الـ syscall
    static uint8_t data[2 * 16];
    memset(data, 0, sizeof(data));

    *(long*)(data + 0)  = 0x0;
    *(int*)(data  + 8)  = 0x41414141;
    *(int*)(data  + 12) = 0x42424242;

    *(long*)(data + 16) = 0x7FFFFFFF;
    *(int*)(data  + 24) = 0x43434343;
    *(int*)(data  + 28) = 0x44444444;

    struct {
        void*    ptr;
        uint32_t pad;
        uint32_t count;
    } set_args = {
        .ptr   = data,
        .pad   = 0,
        .count = 2
    };

    int r = syscall(SYS_SET_TIMEZONE_INFO, &set_args);
    printf_debug("set_timezone r=%d\n", r);

    return 0;
}