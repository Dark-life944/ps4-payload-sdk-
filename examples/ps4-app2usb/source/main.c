#include <ps4.h>

#define O_RDWR 2

#define ntohs sceNetNtohs
#define htons sceNetHtons

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork(); 
    jailbreak();
    initSysUtil();

    printf_debug("[+] PPPoE Started...\n");

    int tapfd;
    char host_uniq[8];
    char buf[2048];
    int n, wr;

    tapfd = open("/dev/tap0", O_RDWR, 0); 
    if(tapfd < 0) {
        printf_debug("[!] open /dev/tap0: Error Occurred\n");
        return 1;
    }

    memset(host_uniq, 0, sizeof(host_uniq));

    while(1) {
        n = read(tapfd, buf, sizeof(buf));
        if(n <= 0) {
            printf_debug("[!] read PADI: Error Occurred\n");
            close(tapfd);
            return 1;
        }
        
        if(ntohs(*(unsigned short *)(buf+12)) == 0x8863 && buf[15] == 0x09 && ntohs(*(unsigned short *)(buf+20)) == 0x0103) {
            memcpy(host_uniq, buf+24, 8);
        }
        if(ntohs(*(unsigned short *)(buf+12)) == 0x8863 && buf[15] == 0x09) {
            break;
        }
    }

    {
        static char pado_buf[64];
        memset(pado_buf, 0xff, sizeof(pado_buf));
        for(int i = 0; i < 6; i++) pado_buf[i] = 3;
        for(int i = 0; i < 6; i++) pado_buf[i+6] = i;
        *(short*)(pado_buf+12) = htons(0x8863);
        pado_buf[14] = 0x11; 
        pado_buf[15] = 0x07; 
        *(short*)(pado_buf+16) = htons(0); 
        *(short*)(pado_buf+18) = htons(sizeof(pado_buf)-14-6); 
        *(short*)(pado_buf+20) = htons(0x0101); 
        *(short*)(pado_buf+22) = htons(0); 
        *(short*)(pado_buf+24) = htons(0x0103); 
        *(short*)(pado_buf+26) = htons(8); 
        memcpy(pado_buf+28, host_uniq, 8);

        wr = write(tapfd, pado_buf, 28+8);
        if(wr < 0) printf_debug("[!] write PADO: Error Occurred\n");
    }

    while(1) {
        n = read(tapfd, buf, sizeof(buf));
        if(n <= 0) {
            printf_debug("[!] read PADR: Error Occurred\n");
            close(tapfd);
            return 1;
        }
        if(ntohs(*(unsigned short *)(buf+12)) == 0x8863 && buf[15] == 0x19) break;
    }

    {
        static char pads_buf[64];
        memset(pads_buf, 0xff, sizeof(pads_buf));
        for(int i = 0; i < 6; i++) pads_buf[i] = 3;
        for(int i = 0; i < 6; i++) pads_buf[i+6] = i;
        *(short*)(pads_buf+12) = htons(0x8863);
        pads_buf[14] = 0x11; 
        pads_buf[15] = 0x65; 
        *(short*)(pads_buf+16) = htons(1); 
        *(short*)(pads_buf+18) = htons(sizeof(pads_buf)-14-6); 
        *(short*)(pads_buf+20) = htons(0x0101); 
        *(short*)(pads_buf+22) = htons(0); 
        *(short*)(pads_buf+24) = htons(0x0103); 
        *(short*)(pads_buf+26) = htons(8); 
        memcpy(pads_buf+28, host_uniq, 8);

        wr = write(tapfd, pads_buf, sizeof(pads_buf));
        if(wr < 0) printf_debug("[!] write PADS: Error Occurred\n");
    }

    char buf1[1024];
    int buf1len = -1;
    memset(buf1, 0, sizeof(buf1));
    while(1) {
        n = read(tapfd, buf, sizeof(buf));
        if(n <= 0) {
            printf_debug("[!] read LCP: Error Occurred\n");
            close(tapfd);
            return 1;
        }
        if(ntohs(*(unsigned short *)(buf+12)) == 0x8864) {
            memcpy(buf1, buf, n);
            buf1len = n;
            break;
        }
    }

    {
        static char ack_buf[128];
        memset(ack_buf, 0xff, sizeof(ack_buf));
        for(int i = 0; i < 6; i++) ack_buf[i] = 3;
        for(int i = 0; i < 6; i++) ack_buf[i+6] = i;
        *(short*)(ack_buf+12) = htons(0x8864);
        
        if (buf1len <= sizeof(ack_buf)) {
            memcpy(ack_buf+14, buf1+14, buf1len-14);
            ack_buf[22] = 2; 
            wr = write(tapfd, ack_buf, buf1len);
            if(wr < 0) printf_debug("[!] write Configure-Ack: Error Occurred\n");
        }
    }

    {
        static char req_buf[96];
        memset(req_buf, 0xff, sizeof(req_buf));
        for(int i = 0; i < 6; i++) req_buf[i] = 3;
        for(int i = 0; i < 6; i++) req_buf[i+6] = i;
        *(short*)(req_buf+12) = htons(0x8864);
        
        if(buf1len > sizeof(req_buf)) buf1len = sizeof(req_buf);
        memcpy(req_buf+14, buf1+14, buf1len-14);
        req_buf[buf1len-1] ^= 1; 

        wr = write(tapfd, req_buf, buf1len);
        if(wr < 0) printf_debug("[!] write Configure-Request: Error Occurred\n");
    }

    while(1) {
        n = read(tapfd, buf, sizeof(buf));
        if(n <= 0) {
            printf_debug("[!] read Final Ack: Error Occurred\n");
            close(tapfd);
            return 1;
        }
        if(ntohs(*(unsigned short *)(buf+12)) == 0x8864 && buf[22] == 2) {
            break;
        }
    }

    {
        static char chap_buf[256+32];
        memset(chap_buf, 0xff, sizeof(chap_buf));
        for(int i = 0; i < 6; i++) chap_buf[i] = 3;
        for(int i = 0; i < 6; i++) chap_buf[i+6] = i;
        *(short*)(chap_buf+12) = htons(0x8864);
        int ii = 14;
        chap_buf[ii++] = 0x11;
        chap_buf[ii++] = 0x00;
        chap_buf[ii++] = 0x00;
        chap_buf[ii++] = 0x01;
        *(short *)(chap_buf+ii) = htons(sizeof(chap_buf) - 20); 
        ii += 2;
        chap_buf[ii++] = 0xc2;
        chap_buf[ii++] = 0x23; 
        chap_buf[ii++] = 1;
        chap_buf[ii++] = 2;
        *(short*)(chap_buf+ii) = htons(sizeof(chap_buf) - 22); 
        
        wr = write(tapfd, chap_buf, sizeof(chap_buf));
        if(wr < 0) printf_debug("[!] write CHAP: Error Occurred\n");
    }

    sceKernelSleep(1); 
    close(tapfd);

    printf_debug("[+] Payload execution finished successfully.\n");
    return 0;
}
