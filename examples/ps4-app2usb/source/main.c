#include "ps4.h"

void test_overflow_on_all_devices(void) {
    char payload[256];
    memset(payload, 'A', 256);
    payload[255] = '\0';
    
    // محاولة على أجهزة USB المختلفة
    const char *devices[] = {
        "/dev/da0s1",
        "/dev/da0s2",
        "/dev/da1s1",
        "/dev/da1s2",
        "/dev/da2s1",
        NULL
    };
    
    for (int i = 0; devices[i] != NULL; i++) {
        printf_notification("Trying device: %s", devices[i]);
        
        int ret = mount_large_fs(devices[i], "/mnt/usb", "exfatfs", payload, 0);
        
        if (ret < 0) {
            printf("Mount failed on %s\n", devices[i]);
        }
    }
}

int _main(struct thread *td) {
    UNUSED(td);
    
    initKernel();
    initLibc();
    jailbreak();
    mmap_patch();
    initSysUtil();
    
    printf_notification("Triggering overflow on USB devices...");
    
    test_overflow_on_all_devices();
    
    printf_notification("If you see this, the system did NOT crash");
    
    return 0;
}