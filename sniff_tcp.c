#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) return; 

    struct ipheader *ip = (struct ipheader *)(packet + SIZE_ETHERNET);
    if (ip->iph_protocol != IPPROTO_TCP) return; 

    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + SIZE_ETHERNET + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    const u_char *payload = packet + SIZE_ETHERNET + ip_header_len + tcp_header_len;
    int total_len = ntohs(ip->iph_len);
    int payload_len = total_len - ip_header_len - tcp_header_len;

    printf("\n=== TCP Packet ===\n");


    printf("Ethernet Header\n");
    printf(" |- Src MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->ether_shost[i]);
        if (i < 5) printf(":");
    }
    printf("\n |- Dst MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->ether_dhost[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

  
    printf("IP Header\n");
    printf(" |- Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf(" |- Dst IP: %s\n", inet_ntoa(ip->iph_destip));

 
    printf("TCP Header\n");
    printf(" |- Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf(" |- Dst Port: %d\n", ntohs(tcp->tcp_dport));


    printf("Payload (%d bytes): ", payload_len);
    if (payload_len > 0) {
        int max_len = payload_len < 32 ? payload_len : 32;
        for (int i = 0; i < max_len; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    } else {
        printf("(none)\n");
    }

    printf("==================\n");
}

int main() {
    char *dev = "ens160";  
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't set filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
