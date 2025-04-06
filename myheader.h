#ifndef MYHEADER_H
#define MYHEADER_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#define SIZE_ETHERNET 14

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6]; // Destination MAC
    u_char ether_shost[6]; // Source MAC
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    u_char  iph_ihl:4, iph_ver:4;
    u_char  iph_tos;
    u_short iph_len;
    u_short iph_ident;
    u_short iph_flag:3, iph_offset:13;
    u_char  iph_ttl;
    u_char  iph_protocol;
    u_short iph_chksum;
    struct  in_addr iph_sourceip;
    struct  in_addr iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

#endif
