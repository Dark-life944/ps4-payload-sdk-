#include "ps4.h"

#define SYS_SET_TIMEZONE_INFO 636
#define SYS_UTC_TO_LOCALTIME  638

struct poc_args {
    int result_set;
    int result_utc;
    long utc_out;
};

int poc_kernel(struct thread *td, struct poc_args *args) {

    // بناء الـ data في kernel stack
    static uint8_t data[2 * 16];
    
    // entry[0]
    *(long*)(data + 0)  = 0x0;
    *(int*)(data + 8)   = 0x41414141;
    *(int*)(data + 12)  = 0x42424242;

    // entry[1]
    *(long*)(data + 16) = 0x7FFFFFFF;
    *(int*)(data + 24)  = 0x43434343;
    *(int*)(data + 28)  = 0x44444444;

    struct {
        void*    ptr;
        uint32_t count;
    } set_args = {
        .ptr   = data,
        .count = 2
    };

    args->result_set = syscall(SYS_SET_TIMEZONE_INFO, &set_args);

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

    args->result_utc = syscall(SYS_UTC_TO_LOCALTIME, &utc_args);
    args->utc_out    = result;

    return 0;
}

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== timezone PoC ===\n");

    struct poc_args args = {0};

    // شغّل في kernel context مباشرة
    kexec(&poc_kernel, &args);

    printf_debug("set_timezone r=%d\n", args.result_set);
    printf_debug("utc r=%d\n",          args.result_utc);
    printf_debug("result = 0x%lx\n",    args.utc_out);

    long expected = 0x1000 + 0x41414141LL;
    if (args.utc_out == expected) {
        printf_debug("[+] DATA CONTROL CONFIRMED!\n");
    } else {
        printf_debug("expected = 0x%lx\n", expected);
    }

    return 0;
}