#include <stdint.h>
#include "net-address.h"

#pragma pack(push, 1)
struct IEEE80211HeaderCommon {
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;

    uint16_t duration;
};
#pragma pack(pop)

enum IEEE80211Types {
    MANAGEMENT,
    CONTROL,
    DATA,
    EXTENSION
};

#pragma pack(push, 1)
struct IEEE80211Beacon {
    MacAddr receiver_addr;
    MacAddr transmitter_addr;
    MacAddr bssid;
    uint8_t fragment_num:4;
    uint16_t sequence_num:12;
};
#pragma pack(pop)

/*
struct IEEE80211Management {

};
*/