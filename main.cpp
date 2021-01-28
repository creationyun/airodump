#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "radiotap-protocol.h"
#include "ieee80211-protocol.h"

void usage();

int main(int argc, char* argv[]) {
	// check syntax
	if (argc != 2) {
		usage();
		return -1;
	}

	char *dev = argv[1];

	// open my network interface
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Error: could not open device %s. (%s)\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;  // not captured
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		printf(" ** %u bytes read ** \n", header->caplen);

		struct RadioTapHeader *rt_header = 
			(struct RadioTapHeader*) packet;

		//printf("version=%u\n", rt_header->version);
		//printf("pad=%u\n", rt_header->pad);
		//printf("len=%u\n", rt_header->len);
		//printf("present=%x\n", rt_header->present);

		/*
		for (int i = 0; i < header->caplen; i++) {
			printf("%02X ", packet[i]);
		}
		*/

		//printf("\n");

		struct IEEE80211HeaderCommon *dot11_header =
			(struct IEEE80211HeaderCommon*) (packet + rt_header->len);

		//printf("%u, %u \n", dot11_header->type, dot11_header->subtype);

		if (dot11_header->type == MANAGEMENT && dot11_header->subtype == 0x08) {
			// Beacon Frame
			printf("It's beacon frame!\n");
			struct IEEE80211Beacon *dot11_beacon =
				(struct IEEE80211Beacon*) (packet + rt_header->len + sizeof(IEEE80211HeaderCommon));
			printf("Receiver: ");
			dot11_beacon->receiver_addr.print_mac_addr();
			printf("\n");
			printf("Transmitter: ");
			dot11_beacon->transmitter_addr.print_mac_addr();
			printf("\n");
			printf("BSS ID: ");
			dot11_beacon->bssid.print_mac_addr();
			printf("\n");
		}
	}

	pcap_close(handle);

	return 0;
}

void usage()
{
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}

