#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

struct payload{
    uint8_t t1_data;
    uint8_t t2_data;
    uint8_t t3_data;
    uint8_t t4_data;
    uint8_t t5_data;
    uint8_t t6_data;
    uint8_t t7_data;
    uint8_t t8_data;
};
struct headlength{
    uint32_t dummy1;
    uint32_t dummy2;
    uint8_t dummy3;
    uint16_t datalength;
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void ethernet(struct libnet_ethernet_hdr *eth){
	printf("---------------------------\n");
    int i = 0;
    printf("src MAC:");
    while(i < ETHER_ADDR_LEN-1){
        printf("%02x:",eth ->ether_shost[i]);
        if((i+1) == ETHER_ADDR_LEN-1)
            printf("%02x",eth ->ether_shost[i+1]);
        i++;
    }
    printf("\n");
    int a = 0;
    printf("dest MAC:");
    while(a < ETHER_ADDR_LEN-1){
        printf("%02x:",eth ->ether_dhost[a]);
        if((a+1) == ETHER_ADDR_LEN-1)
            printf("%02x",eth ->ether_dhost[a+1]);
        a++;
    }
    printf("\n");
}

void ipv4(struct libnet_ipv4_hdr *ip){
    printf("src ip :%s\n",inet_ntoa(ip->ip_src));
    printf("dest ip :%s\n",inet_ntoa(ip->ip_dst));


}

void tcp_port(struct libnet_tcp_hdr *pcap_port){
    printf("src port :%d\n", ntohs(pcap_port->th_sport));
    printf("dest port:%d\n", ntohs(pcap_port->th_dport));
    }

void byte_data(struct payload*pay_data){
  uint8_t a_1 =(pay_data->t1_data);
  uint8_t a_2 =(pay_data->t2_data);
  uint8_t a_3 =(pay_data->t3_data);
  uint8_t a_4 =(pay_data->t4_data);
  uint8_t a_5 =(pay_data->t5_data);
  uint8_t a_6 =(pay_data->t6_data);
  uint8_t a_7 =(pay_data->t7_data);
  uint8_t a_8 =(pay_data->t8_data);

        printf("Data: %02X ",a_1);
        printf("%02X ",a_2);
        printf("%02X ",a_3);
        printf("%02X ",a_4);
        printf("%02X ",a_5);
        printf("%02X ",a_6);
        printf("%02X ",a_7);
        printf("%02X \n",a_8);



}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        struct libnet_ethernet_hdr* ethernet_packet = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ipv4_packet = ((struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr)));
        struct libnet_tcp_hdr* tcp_packet = (struct libnet_tcp_hdr*)(packet+ (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr)));
        struct payload* pay_data = (struct payload*)(packet+ (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr)) );




        ethernet(ethernet_packet);
        ipv4(ipv4_packet);
        tcp_port(tcp_packet);
        byte_data(pay_data);
    }

	pcap_close(pcap);
}
