#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#define BUFFER_SIZE 65536

// Define Ethernet header structure for macOS
struct ethernet_header {
    u_char ether_dhost[6];    // Destination host address
    u_char ether_shost[6];    // Source host address
    u_short ether_type;       // IP? ARP? RARP? etc
};

void print_ethernet_header(struct ethernet_header *eth) {
    printf("Ethernet Header:\n");
    printf("  |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], 
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("  |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], 
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  |-Protocol            : %u\n", ntohs(eth->ether_type));
}

void print_ip_header(struct ip *iph) {
    struct sockaddr_in source, dest;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->ip_src.s_addr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->ip_dst.s_addr;
    
    printf("IP Header:\n");
    printf("  |-IP Version        : %d\n", (unsigned int)iph->ip_v);
    printf("  |-IP Header Length  : %d DWORDS or %d Bytes\n", 
           (unsigned int)iph->ip_hl, ((unsigned int)(iph->ip_hl))*4);
    printf("  |-Type Of Service   : %d\n", (unsigned int)iph->ip_tos);
    printf("  |-IP Total Length   : %d Bytes\n", ntohs(iph->ip_len));
    printf("  |-Identification    : %d\n", ntohs(iph->ip_id));
    printf("  |-TTL               : %d\n", (unsigned int)iph->ip_ttl);
    printf("  |-Protocol          : %d\n", (unsigned int)iph->ip_p);
    printf("  |-Checksum          : %d\n", ntohs(iph->ip_sum));
    printf("  |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
    printf("  |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char *buffer, int size) {
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ethernet_header));
    struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethernet_header) + (iph->ip_hl * 4));
    
    printf("\n***********************TCP Packet*************************\n");
    print_ethernet_header((struct ethernet_header *)buffer);
    print_ip_header(iph);
    
    printf("TCP Header:\n");
    printf("  |-Source Port      : %u\n", ntohs(tcph->th_sport));
    printf("  |-Destination Port : %u\n", ntohs(tcph->th_dport));
    printf("  |-Sequence Number  : %u\n", ntohl(tcph->th_seq));
    printf("  |-Acknowledge Number : %u\n", ntohl(tcph->th_ack));
    printf("  |-Header Length    : %d DWORDS or %d BYTES\n", 
           (unsigned int)tcph->th_off, (unsigned int)tcph->th_off * 4);
    printf("  |-Urgent Flag      : %d\n", (unsigned int)tcph->th_flags & TH_URG ? 1 : 0);
    printf("  |-Acknowledgement Flag : %d\n", (unsigned int)tcph->th_flags & TH_ACK ? 1 : 0);
    printf("  |-Push Flag        : %d\n", (unsigned int)tcph->th_flags & TH_PUSH ? 1 : 0);
    printf("  |-Reset Flag       : %d\n", (unsigned int)tcph->th_flags & TH_RST ? 1 : 0);
    printf("  |-Synchronise Flag : %d\n", (unsigned int)tcph->th_flags & TH_SYN ? 1 : 0);
    printf("  |-Finish Flag      : %d\n", (unsigned int)tcph->th_flags & TH_FIN ? 1 : 0);
    printf("  |-Window           : %d\n", ntohs(tcph->th_win));
    printf("  |-Checksum         : %d\n", ntohs(tcph->th_sum));
    printf("  |-Urgent Pointer   : %d\n", tcph->th_urp);
}

void print_udp_packet(unsigned char *buffer, int size) {
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ethernet_header));
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethernet_header) + (iph->ip_hl * 4));
    
    printf("\n***********************UDP Packet*************************\n");
    print_ethernet_header((struct ethernet_header *)buffer);
    print_ip_header(iph);
    
    printf("UDP Header:\n");
    printf("  |-Source Port      : %d\n", ntohs(udph->uh_sport));
    printf("  |-Destination Port : %d\n", ntohs(udph->uh_dport));
    printf("  |-UDP Length       : %d\n", ntohs(udph->uh_ulen));
    printf("  |-UDP Checksum     : %d\n", ntohs(udph->uh_sum));
}

void print_icmp_packet(unsigned char *buffer, int size) {
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ethernet_header));
    
    printf("\n***********************ICMP Packet*************************\n");
    print_ethernet_header((struct ethernet_header *)buffer);
    print_ip_header(iph);
    printf("ICMP Header:\n");
    printf("  |-Type : %d\n", (unsigned int)(buffer[sizeof(struct ethernet_header) + (iph->ip_hl * 4)]));
    printf("  |-Code : %d\n", (unsigned int)(buffer[sizeof(struct ethernet_header) + (iph->ip_hl * 4) + 1]));
    printf("  |-Checksum : %d\n", ntohs(*(unsigned short*)(buffer + sizeof(struct ethernet_header) + (iph->ip_hl * 4) + 2)));
}

void process_packet(unsigned char *buffer, int size) {
    static int packet_count = 0;
    struct ethernet_header *eth = (struct ethernet_header *)buffer;
    
    packet_count++;
    
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[80];
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", timeinfo);
    
    printf("\n========== Packet #%d [%s] ==========\n", packet_count, timestamp);
    printf("Packet Size: %d bytes\n", size);
    
    // Check if it's an IP packet
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip *iph = (struct ip *)(buffer + sizeof(struct ethernet_header));
        
        switch (iph->ip_p) {
            case 1:  // ICMP Protocol
                print_icmp_packet(buffer, size);
                break;
            
            case 6:  // TCP Protocol
                print_tcp_packet(buffer, size);
                break;
            
            case 17: // UDP Protocol
                print_udp_packet(buffer, size);
                break;
            
            default: // Some Other Protocol
                printf("\n***********************Other IP Packet*************************\n");
                print_ethernet_header(eth);
                print_ip_header(iph);
                printf("Protocol: %d (Other)\n", iph->ip_p);
                break;
        }
    } else {
        printf("\n***********************Non-IP Packet*************************\n");
        print_ethernet_header(eth);
        printf("Non-IP Packet (EtherType: 0x%04x)\n", ntohs(eth->ether_type));
    }
    
    printf("********************************************************\n\n");
}

void process_ip_packet(unsigned char *buffer, int size) {
    static int packet_count = 0;
    struct ip *iph = (struct ip *)buffer;
    
    packet_count++;
    
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[80];
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", timeinfo);
    
    printf("\n========== IP Packet #%d [%s] ==========\n", packet_count, timestamp);
    printf("Packet Size: %d bytes\n", size);
    
    switch (iph->ip_p) {
        case 1:  // ICMP Protocol
            printf("\n***********************ICMP Packet*************************\n");
            print_ip_header(iph);
            printf("ICMP Header:\n");
            printf("  |-Type : %d\n", (unsigned int)(buffer[iph->ip_hl * 4]));
            printf("  |-Code : %d\n", (unsigned int)(buffer[iph->ip_hl * 4 + 1]));
            printf("  |-Checksum : %d\n", ntohs(*(unsigned short*)(buffer + (iph->ip_hl * 4) + 2)));
            break;
        
        case 6:  // TCP Protocol
            {
                struct tcphdr *tcph = (struct tcphdr *)(buffer + (iph->ip_hl * 4));
                printf("\n***********************TCP Packet*************************\n");
                print_ip_header(iph);
                printf("TCP Header:\n");
                printf("  |-Source Port      : %u\n", ntohs(tcph->th_sport));
                printf("  |-Destination Port : %u\n", ntohs(tcph->th_dport));
                printf("  |-Sequence Number  : %u\n", ntohl(tcph->th_seq));
                printf("  |-Acknowledge Number : %u\n", ntohl(tcph->th_ack));
                printf("  |-Header Length    : %d DWORDS or %d BYTES\n", 
                       (unsigned int)tcph->th_off, (unsigned int)tcph->th_off * 4);
                printf("  |-Flags: URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
                       (tcph->th_flags & TH_URG) ? 1 : 0,
                       (tcph->th_flags & TH_ACK) ? 1 : 0,
                       (tcph->th_flags & TH_PUSH) ? 1 : 0,
                       (tcph->th_flags & TH_RST) ? 1 : 0,
                       (tcph->th_flags & TH_SYN) ? 1 : 0,
                       (tcph->th_flags & TH_FIN) ? 1 : 0);
                printf("  |-Window           : %d\n", ntohs(tcph->th_win));
                printf("  |-Checksum         : %d\n", ntohs(tcph->th_sum));
            }
            break;
        
        case 17: // UDP Protocol
            {
                struct udphdr *udph = (struct udphdr *)(buffer + (iph->ip_hl * 4));
                printf("\n***********************UDP Packet*************************\n");
                print_ip_header(iph);
                printf("UDP Header:\n");
                printf("  |-Source Port      : %d\n", ntohs(udph->uh_sport));
                printf("  |-Destination Port : %d\n", ntohs(udph->uh_dport));
                printf("  |-UDP Length       : %d\n", ntohs(udph->uh_ulen));
                printf("  |-UDP Checksum     : %d\n", ntohs(udph->uh_sum));
            }
            break;
        
        default: // Some Other Protocol
            printf("\n***********************Other IP Packet*************************\n");
            print_ip_header(iph);
            printf("Protocol: %d (Other)\n", iph->ip_p);
            break;
    }
    
    printf("********************************************************\n\n");
}

int main() {
    int sock_raw;
    unsigned char *buffer;
    struct sockaddr saddr;
    int saddr_size, data_size;
    
    printf("Simple Raw Socket Packet Sniffer\n");
    printf("=================================\n");
    printf("Starting packet capture... Press Ctrl+C to stop\n\n");
    
    // Create a raw socket that captures all packets
    // On macOS, we use PF_INET with IPPROTO_IP for raw sockets
    sock_raw = socket(PF_INET, SOCK_RAW, IPPROTO_IP);
    
    if (sock_raw < 0) {
        printf("Socket Error: %s\n", strerror(errno));
        printf("Note: This program requires root privileges to create raw sockets.\n");
        printf("Try running with: sudo ./simple_tcpdump\n");
        return 1;
    }
    
    // Enable IP header inclusion
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s\n", errno, strerror(errno));
        return 1;
    }
    
    buffer = (unsigned char *)malloc(BUFFER_SIZE);
    
    printf("Raw socket created successfully. Waiting for packets...\n\n");
    
    while (1) {
        saddr_size = sizeof(saddr);
        
        // Receive a packet
        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t*)&saddr_size);
        
        if (data_size < 0) {
            printf("Recvfrom error, failed to get packets: %s\n", strerror(errno));
            break;
        }
        
        // Process the packet (note: raw IP socket doesn't include Ethernet header)
        // We'll create a simpler processing function for IP-only packets
        process_ip_packet(buffer, data_size);
    }
    
    close(sock_raw);
    free(buffer);
    printf("Finished.\n");
    return 0;
}