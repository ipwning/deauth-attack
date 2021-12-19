#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include <iostream>
#include <vector>

#include "header.h"

#define BEACON  0b1000
#define DEAUTH  0b1100
#define MANAGE  0b00
#define _2GHZ   0b0000000100000000
#define _5GHZ   0b0000000010000000

#define BROADCAST   0
#define UNICAST     1

#define BRD_MAC "\xff\xff\xff\xff\xff\xff"

#define MAC_STR "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n"
#define MAC_ARG(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

void dump(unsigned char* buf, int size);
void error(const char *msg);
void deauthAtk(pcap_t *pcap);
uint8_t *translateMac(const char *mac);