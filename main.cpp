#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include "radiotap-protocol.h"
#include "ieee80211-protocol.h"

void usage();

struct APData {
	size_t beacons{0};
	size_t num_of_data{0};
	char enc[16]{""};
	char essid[256]{""};
};

typedef std::map<MacAddr, APData> APInfo;

APInfo ap_info;

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
		uint8_t* packet_ptr;
		int remained_bytes;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;  // not captured
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		//printf(" ** %u bytes read ** \n", header->caplen);

		// Print AP information first
		printf("\x1B[2J");  // clear screen
		printf("\x1B[H");  // move cursor to (0, 0)
		printf("\n BSSID              Beacons    #Data   ENC   ESSID       \n");

		for (auto &ap : ap_info) {
			printf(" ");
			ap.first.print_mac_addr();
			printf(" %8d %8d %-7s %-16s \n",
				ap.second.beacons, ap.second.num_of_data, ap.second.enc, ap.second.essid);
		}

		packet_ptr = const_cast<uint8_t*>(packet);
		remained_bytes = header->caplen;
		struct RadioTapHeader *rt_header = (struct RadioTapHeader*) packet_ptr;

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
		
		packet_ptr += rt_header->len;
		remained_bytes -= rt_header->len;
		if (remained_bytes <= 0) continue;
		struct IEEE80211HeaderCommon *dot11_header = (struct IEEE80211HeaderCommon*) packet_ptr;

		//printf("%u, %u \n", dot11_header->type, dot11_header->subtype);

		if (dot11_header->type == MANAGEMENT && dot11_header->subtype == 0x08) {
			// Beacon Frame
			//printf("It's beacon frame!\n");

			packet_ptr += sizeof(IEEE80211HeaderCommon);
			remained_bytes -= sizeof(IEEE80211HeaderCommon);
			if (remained_bytes <= 0) continue;

			struct IEEE80211Beacon *dot11_beacon = (struct IEEE80211Beacon*) packet_ptr;
			
			//printf("Receiver: ");
			//dot11_beacon->receiver_addr.print_mac_addr();
			//printf("\n");
			//printf("Transmitter: ");
			//dot11_beacon->transmitter_addr.print_mac_addr();
			//printf("\n");
			//printf("BSSID: ");
			//dot11_beacon->bssid.print_mac_addr();
			//printf("\n");

			APInfo::iterator it = 
				ap_info.find(dot11_beacon->bssid);
			std::pair<APInfo::iterator, bool> insert_info;

			if (it == ap_info.end()) {
				insert_info = ap_info.insert({dot11_beacon->bssid, APData()});
				it = insert_info.first;
			}

			it->second.beacons += 1;

			packet_ptr += sizeof(IEEE80211Beacon);
			remained_bytes -= sizeof(IEEE80211Beacon);
			if (remained_bytes <= 0) continue;

			struct IEEE80211Management *dot11_mgmt = (struct IEEE80211Management*) packet_ptr;

			//printf("Beacon Interval: 0x%x\n", dot11_mgmt->beacon_interval);

			packet_ptr += sizeof(IEEE80211Management);
			remained_bytes -= sizeof(IEEE80211Management);
			if (remained_bytes <= 0) continue;

			// Tag parameters parsing
			uint8_t tag_num, tag_len;

			while (remained_bytes > 0) {
				tag_num = packet_ptr[0];
				tag_len = packet_ptr[1];
				// Is it SSID parameter set?
				if (tag_num == SSID_PARAMETER_SET) {
					// ESSID parameter
					memcpy(it->second.essid, packet_ptr+2, tag_len);
					it->second.essid[tag_len] = '\0';
				}

				packet_ptr += 2 + tag_len;
				remained_bytes -= 2 + tag_len;
			}

			//printf("Remained: %d bytes\n", remained_bytes);
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

