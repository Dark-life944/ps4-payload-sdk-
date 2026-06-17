#include <ps4.h>

#define O_RDWR 2

#define BIOCSBLEN _IOW('B', 102, unsigned int)
#define BIOCSETIF _IOW('B', 108, struct ifreq)
#define BIOCIMMEDIATE _IOW('B', 112, unsigned int)
#define BIOCGHDRLEN _IOR('B', 105, unsigned int)

#define ntohs sceNetNtohs
#define htons sceNetHtons

struct ifreq {
    char ifr_name[16];
    char ifr_dstaddr[16];
};

struct bpf_hdr {
    struct timeval bh_tstamp;
    unsigned int bh_caplen;
    unsigned int bh_datalen;
    unsigned short bh_hdrlen;
};

int init_bpf(void) {
    int fd;
    struct ifreq ifr;
    unsigned int len = 1;
    unsigned int buf_size = 4096;

    fd = open("/dev/bpf0", O_RDWR, 0);
    if (fd < 0) {
        fd = open("/dev/bpf", O_RDWR, 0);
    }
    if (fd < 0) return -1;

    ioctl(fd, BIOCSBLEN, &buf_size);

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, "ae0", 3); 
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    ioctl(fd, BIOCIMMEDIATE, &len);
    return fd;
}

int _main(struct thread *td) {
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork(); 
    jailbreak();
    initSysUtil();

    printf_debug("[+] PPPoE BPF Payload Started...\n");

    int bpffd = init_bpf();
    if(bpffd < 0) {
        printf_debug("[!] Failed to initialize BPF interface\n");
        return 1;
    }

    unsigned int bpf_hdr_len = 0;
    if (ioctl(bpffd, BIOCGHDRLEN, &bpf_hdr_len) < 0) {
        bpf_hdr_len = 18; 
    }

    char read_buf[4096];
    char host_uniq[8];
    int n, wr;

    memset(host_uniq, 0, sizeof(host_uniq));

    while(1) {
        n = read(bpffd, read_buf, sizeof(read_buf));
        if(n <= 0) {
            printf_debug("[!] read PADI error\n");
            close(bpffd);
            return 1;
        }

        struct bpf_hdr *bh = (struct bpf_hdr *)read_buf;
        char *eth_packet = read_buf + bh->bh_hdrlen;

        if(ntohs(*(unsigned short *)(eth_packet+12)) == 0x8863 && eth_packet[15] == 0x09 && ntohs(*(unsigned short *)(eth_packet+20)) == 0x0103) {
            memcpy(host_uniq, eth_packet+24, 8);
        }
        if(ntohs(*(unsigned short *)(eth_packet+12)) == 0x8863 && eth_packet[15] == 0x09) {
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

        wr = write(bpffd, pado_buf, 28+8);
        if(wr < 0) printf_debug("[!] write PADO error\n");
    }

    while(1) {
        n = read(bpffd, read_buf, sizeof(read_buf));
        if(n <= 0) {
            printf_debug("[!] read PADR error\n");
            close(bpffd);
            return 1;
        }
        struct bpf_hdr *bh = (struct bpf_hdr *)read_buf;
        char *eth_packet = read_buf + bh->bh_hdrlen;

        if(ntohs(*(unsigned short *)(eth_packet+12)) == 0x8863 && eth_packet[15] == 0x19) break;
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

        wr = write(bpffd, pads_buf, sizeof(pads_buf));
        if(wr < 0) printf_debug("[!] write PADS error\n");
    }

    char buf1[1024];
    int buf1len = -1;
    memset(buf1, 0, sizeof(buf1));
    while(1) {
        n = read(bpffd, read_buf, sizeof(read_buf));
        if(n <= 0) {
            printf_debug("[!] read LCP error\n");
            close(bpffd);
            return 1;
        }
        struct bpf_hdr *bh = (struct bpf_hdr *)read_buf;
        char *eth_packet = read_buf + bh->bh_hdrlen;
        int packet_len = bh->bh_caplen;

        if(ntohs(*(unsigned short *)(eth_packet+12)) == 0x8864) {
            memcpy(buf1, eth_packet, packet_len);
            buf1len = packet_len;
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
            wr = write(bpffd, ack_buf, buf1len);
            if(wr < 0) printf_debug("[!] write Configure-Ack error\n");
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

        wr = write(bpffd, req_buf, buf1len);
        if(wr < 0) printf_debug("[!] write Configure-Request error\n");
    }

    while(1) {
        n = read(bpffd, read_buf, sizeof(read_buf));
        if(n <= 0) {
            printf_debug("[!] read Final Ack error\n");
            close(bpffd);
            return 1;
        }
        struct bpf_hdr *bh = (struct bpf_hdr *)read_buf;
        char *eth_packet = read_buf + bh->bh_hdrlen;

        if(ntohs(*(unsigned short *)(eth_packet+12)) == 0x8864 && eth_packet[22] == 2) {
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
        
        wr = write(bpffd, chap_buf, sizeof(chap_buf));
        if(wr < 0) printf_debug("[!] write CHAP error\n");
    }

    sceKernelSleep(1); 
    close(bpffd);

    printf_debug("[+] Payload execution finished successfully.\n");
    return 0;
}
