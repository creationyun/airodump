#include <stdint.h>

/* RadioTap Header */
#pragma pack(push, 1)
struct RadioTapHeader {
	uint8_t version;
	uint8_t pad;
	uint16_t len;
	uint32_t present;
};
#pragma pack(pop)

/* RadioTap Present's Flags */
enum RadioTapPresentFlags {
	TSFT,
	FLAGS,
	RATE,
	CHANNEL,
	FHSS,
	DBM_ANTENNA_SIGNAL,
	DBM_ANTENNA_NOISE,
	LOCK_QUALITY,
	TX_ATTENUATION,
	DB_TX_ATTENUATION,
	DBM_TX_POWER,
	ANTENNA,
	DB_ANTENNA_SIGNAL,
	DB_ANTENNA_NOISE,
	RX_FLAGS,
	TX_FLAGS,
	RESERVED16,
	RESERVED17,
	CHANNEL_PLUS,
	MCS_INFORMATION,
	A_MPDU_STATUS,
	VHT_INFORMATION,
	FRAME_TIMESTAMP,
	HE_INFORMATION,
	HE_MU_INFORMATION,
	RESERVED25,
	ZERO_LENGTH_PSDU,
	L_SIG,
	TLVS,
	RADIOTAP_NS_NEXT,
	VENDOR_NS_NEXT,
	EXT
};

/* TSFT Data */
#pragma pack(push, 1)
struct RadioTapTSFT {
	uint64_t mac_timestamp;
};
#pragma pack(pop)

/* Flags Data */
#pragma pack(push, 1)
struct RadioTapFlags {
	uint8_t flags;
};
#pragma pack(pop)

/* Rate Data */
#pragma pack(push, 1)
struct RadioTapRate {
	uint8_t rate;
};
#pragma pack(pop)

/* Channel Data */
#pragma pack(push, 1)
struct RadioTapChannel {
	uint16_t channel_freq;
	uint16_t channel_flags;
};
#pragma pack(pop)

/* FHSS Data */
#pragma pack(push, 1)
struct RadioTapFHSS {
	uint8_t hop_set;
	uint8_t hop_pattern;
};
#pragma pack(pop)

/* dBm Antenna Signal Data */
#pragma pack(push, 1)
struct RadioTap_dBmAntennaSignal {
	int8_t dbm_signal;
};
#pragma pack(pop)

/* dBm Antenna Noise Data */
#pragma pack(push, 1)
struct RadioTap_dBmAntennaNoise {
	int8_t dbm_noise;
};
#pragma pack(pop)
