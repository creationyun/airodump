#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

		for (int i = 0; i < header->caplen; i++) {
			printf("%02X ", packet[i]);
		}

		printf("\n");
	}

	pcap_close(handle);

	return 0;
}

void usage()
{
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}

