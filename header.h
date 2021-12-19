#include <stdint.h>

typedef struct _radiotap_header {
    uint8_t hdrRvsn;
    uint8_t pad;
    uint16_t hdr_len;
    uint32_t pFlags;
    uint8_t _pad[3];
} radiotap_header;

typedef struct _deauth {
    uint8_t frmCtrlFld;
    uint8_t flags;
    uint16_t dur;
    uint8_t rcvrMac[6];
    uint8_t srcMac[6];
    uint8_t bssid[6];
    uint16_t nums;
} deauth;
