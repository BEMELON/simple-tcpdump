#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#define MAX_BPF_DEVICES 256

int open_bpf_device() {
    char device[32];
    int fd;
    
    for (int i = 0; i < MAX_BPF_DEVICES; i++) {
        snprintf(device, sizeof(device), "/dev/bpf%d", i);
        fd = open(device, O_RDWR);
        if (fd != -1) {
            printf("Opened BPF device: %s\n", device);
            return fd;
        }
    }
    
    printf("Error: Could not open any BPF device\n");
    printf("Make sure you have proper permissions or try running as root\n");
    return -1;
}

int bind_bpf_to_interface(int bpf_fd, const char *interface) {
    struct ifreq ifr;
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name) - 1);
    
    if (ioctl(bpf_fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl BIOCSETIF");
        return -1;
    }
    
    printf("Bound to interface: %s\n", interface);
    return 0;
}

int configure_bpf(int bpf_fd) {
    u_int enable = 1;
    
    // Enable immediate mode
    if (ioctl(bpf_fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl BIOCIMMEDIATE");
        return -1;
    }
    
    // Set promiscuous mode (optional - some interfaces don't support it)
    if (ioctl(bpf_fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl BIOCPROMISC");
        printf("Warning: Could not enable promiscuous mode, continuing anyway...\n");
    }
    
    // Get buffer length
    u_int buffer_len;
    if (ioctl(bpf_fd, BIOCGBLEN, &buffer_len) == -1) {
        perror("ioctl BIOCGBLEN");
        return -1;
    }
    
    printf("BPF buffer size: %u bytes\n", buffer_len);
    return buffer_len;
}

void install_tcp_filter(int bpf_fd) {
    // BPF program to filter TCP packets
    struct bpf_insn tcp_filter[] = {
        // Load ethernet type from offset 12
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
        // Jump if not IP (0x0800)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 4),
        // Load IP protocol from offset 23 (14 ethernet + 9 IP header)
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
        // Jump if TCP (protocol 6)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1),
        // Accept packet
        BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
        // Reject packet
        BPF_STMT(BPF_RET + BPF_K, 0)
    };
    
    struct bpf_program filter_prog = {
        .bf_len = sizeof(tcp_filter) / sizeof(tcp_filter[0]),
        .bf_insns = tcp_filter
    };
    
    if (ioctl(bpf_fd, BIOCSETF, &filter_prog) == -1) {
        perror("ioctl BIOCSETF");
    } else {
        printf("TCP filter installed\n");
    }
}

void install_udp_filter(int bpf_fd) {
    // BPF program to filter UDP packets
    struct bpf_insn udp_filter[] = {
        // Load ethernet type
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
        // Jump if not IP
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 4),
        // Load IP protocol
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
        // Jump if UDP (protocol 17)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 1),
        // Accept packet
        BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
        // Reject packet
        BPF_STMT(BPF_RET + BPF_K, 0)
    };
    
    struct bpf_program filter_prog = {
        .bf_len = sizeof(udp_filter) / sizeof(udp_filter[0]),
        .bf_insns = udp_filter
    };
    
    if (ioctl(bpf_fd, BIOCSETF, &filter_prog) == -1) {
        perror("ioctl BIOCSETF");
    } else {
        printf("UDP filter installed\n");
    }
}

void install_port_filter(int bpf_fd, int port) {
    // BPF program to filter packets by port (TCP or UDP)
    struct bpf_insn port_filter[] = {
        // Load ethernet type
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
        // Jump if not IP
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 12),
        // Load IP protocol
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
        // Jump if TCP
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 4),
        // Load TCP source port
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 34),
        // Jump if matches port
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 5, 0),
        // Load TCP dest port
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 36),
        // Jump if matches port
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 3, 0),
        // Check if UDP
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 4),
        // Load UDP source port
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 34),
        // Jump if matches port
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 1, 0),
        // Load UDP dest port
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 36),
        // Jump if matches port
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 0, 1),
        // Accept packet
        BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
        // Reject packet
        BPF_STMT(BPF_RET + BPF_K, 0)
    };
    
    struct bpf_program filter_prog = {
        .bf_len = sizeof(port_filter) / sizeof(port_filter[0]),
        .bf_insns = port_filter
    };
    
    if (ioctl(bpf_fd, BIOCSETF, &filter_prog) == -1) {
        perror("ioctl BIOCSETF");
    } else {
        printf("Port %d filter installed\n", port);
    }
}

void print_ethernet_header(const struct ether_header *eth) {
    printf("Ethernet Header:\n");
    printf("  |-Destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("  |-Source MAC      : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  |-Protocol        : 0x%04x\n", ntohs(eth->ether_type));
}

void print_ip_header(const struct ip *iph) {
    struct sockaddr_in source, dest;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->ip_src.s_addr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->ip_dst.s_addr;
    
    printf("IP Header:\n");
    printf("  |-Version         : %d\n", (unsigned int)iph->ip_v);
    printf("  |-Header Length   : %d DWORDS (%d bytes)\n", 
           (unsigned int)iph->ip_hl, (unsigned int)(iph->ip_hl * 4));
    printf("  |-Type of Service : %d\n", (unsigned int)iph->ip_tos);
    printf("  |-Total Length    : %d bytes\n", ntohs(iph->ip_len));
    printf("  |-Identification  : %d\n", ntohs(iph->ip_id));
    printf("  |-TTL             : %d\n", (unsigned int)iph->ip_ttl);
    printf("  |-Protocol        : %d\n", (unsigned int)iph->ip_p);
    printf("  |-Checksum        : %d\n", ntohs(iph->ip_sum));
    printf("  |-Source IP       : %s\n", inet_ntoa(source.sin_addr));
    printf("  |-Destination IP  : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_header(const u_char *packet) {
    const struct ether_header *eth = (struct ether_header *)packet;
    const struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    const struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + (iph->ip_hl * 4));
    
    printf("TCP Header:\n");
    printf("  |-Source Port     : %u\n", ntohs(tcph->th_sport));
    printf("  |-Dest Port       : %u\n", ntohs(tcph->th_dport));
    printf("  |-Sequence Number : %u\n", ntohl(tcph->th_seq));
    printf("  |-Ack Number      : %u\n", ntohl(tcph->th_ack));
    printf("  |-Header Length   : %d DWORDS (%d bytes)\n", 
           (unsigned int)tcph->th_off, (unsigned int)(tcph->th_off * 4));
    printf("  |-Flags           : ");
    if (tcph->th_flags & TH_URG) printf("URG ");
    if (tcph->th_flags & TH_ACK) printf("ACK ");
    if (tcph->th_flags & TH_PUSH) printf("PSH ");
    if (tcph->th_flags & TH_RST) printf("RST ");
    if (tcph->th_flags & TH_SYN) printf("SYN ");
    if (tcph->th_flags & TH_FIN) printf("FIN ");
    printf("\n");
    printf("  |-Window Size     : %d\n", ntohs(tcph->th_win));
    printf("  |-Checksum        : %d\n", ntohs(tcph->th_sum));
}

void print_udp_header(const u_char *packet) {
    const struct ether_header *eth = (struct ether_header *)packet;
    const struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    const struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + (iph->ip_hl * 4));
    
    printf("UDP Header:\n");
    printf("  |-Source Port     : %d\n", ntohs(udph->uh_sport));
    printf("  |-Dest Port       : %d\n", ntohs(udph->uh_dport));
    printf("  |-Length          : %d\n", ntohs(udph->uh_ulen));
    printf("  |-Checksum        : %d\n", ntohs(udph->uh_sum));
}

void process_packet(const u_char *packet, int packet_len, int verbose) {
    static int packet_count = 0;
    packet_count++;
    
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[80];
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", timeinfo);
    
    printf("\n========== Packet #%d [%s] ==========\n", packet_count, timestamp);
    printf("Packet Length: %d bytes\n", packet_len);
    
    const struct ether_header *eth = (struct ether_header *)packet;
    
    if (!verbose) {
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            const struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
            struct sockaddr_in src, dst;
            
            src.sin_addr.s_addr = iph->ip_src.s_addr;
            dst.sin_addr.s_addr = iph->ip_dst.s_addr;
            
            printf("  %s -> %s ", inet_ntoa(src.sin_addr), inet_ntoa(dst.sin_addr));
            
            switch (iph->ip_p) {
                case IPPROTO_TCP: {
                    const struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + (iph->ip_hl * 4));
                    printf("TCP %d -> %d", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
                    break;
                }
                case IPPROTO_UDP: {
                    const struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + (iph->ip_hl * 4));
                    printf("UDP %d -> %d", ntohs(udph->uh_sport), ntohs(udph->uh_dport));
                    break;
                }
                case IPPROTO_ICMP:
                    printf("ICMP");
                    break;
                default:
                    printf("Protocol %d", iph->ip_p);
                    break;
            }
            printf("\n");
        } else {
            printf("  Non-IP packet (EtherType: 0x%04x)\n", ntohs(eth->ether_type));
        }
        printf("********************************************************\n");
        return;
    }
    
    print_ethernet_header(eth);
    
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        const struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
        print_ip_header(iph);
        
        switch (iph->ip_p) {
            case IPPROTO_TCP:
                printf("\n***********************TCP Packet*************************\n");
                print_tcp_header(packet);
                break;
            case IPPROTO_UDP:
                printf("\n***********************UDP Packet*************************\n");
                print_udp_header(packet);
                break;
            case IPPROTO_ICMP:
                printf("\n***********************ICMP Packet*************************\n");
                break;
            default:
                printf("\n***********************Other IP Packet*************************\n");
                printf("Protocol: %d\n", iph->ip_p);
                break;
        }
    }
    
    printf("********************************************************\n");
}

void print_usage(const char *program_name) {
    printf("Usage: %s [options] [filter]\n", program_name);
    printf("Direct BPF access packet capture\n\n");
    printf("Options:\n");
    printf("  -i interface   : Network interface (default: en0)\n");
    printf("  -c count       : Exit after capturing 'count' packets\n");
    printf("  -v             : Verbose output\n");
    printf("  -h             : Show this help\n");
    printf("\nFilters:\n");
    printf("  tcp                    : Capture only TCP packets\n");
    printf("  udp                    : Capture only UDP packets\n");
    printf("  port 80                : Capture packets on port 80\n");
    printf("\nNote: This program requires root privileges to access BPF devices.\n");
    printf("Try running with: sudo %s\n", program_name);
}

int main(int argc, char *argv[]) {
    int bpf_fd;
    char *interface = "en0";
    int packet_count = 0;
    int verbose = 0;
    int captured = 0;
    int opt;
    char *filter = NULL;
    
    while ((opt = getopt(argc, argv, "i:c:vh")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'c':
                packet_count = atoi(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (optind < argc) {
        filter = argv[optind];
    }
    
    printf("Direct BPF Packet Sniffer\n");
    printf("=========================\n");
    
    // Open BPF device
    bpf_fd = open_bpf_device();
    if (bpf_fd == -1) {
        return 1;
    }
    
    // Configure BPF
    int buffer_len = configure_bpf(bpf_fd);
    if (buffer_len == -1) {
        close(bpf_fd);
        return 1;
    }
    
    // Bind to interface
    if (bind_bpf_to_interface(bpf_fd, interface) == -1) {
        close(bpf_fd);
        return 1;
    }
    
    // Install filter if specified
    if (filter) {
        printf("Filter: %s\n", filter);
        if (strcmp(filter, "tcp") == 0) {
            install_tcp_filter(bpf_fd);
        } else if (strcmp(filter, "udp") == 0) {
            install_udp_filter(bpf_fd);
        } else if (strncmp(filter, "port ", 5) == 0) {
            int port = atoi(filter + 5);
            install_port_filter(bpf_fd, port);
        } else {
            printf("Unknown filter: %s\n", filter);
        }
    } else {
        printf("Filter: none (capturing all packets)\n");
    }
    
    printf("Verbose mode: %s\n", verbose ? "ON" : "OFF");
    if (packet_count > 0) {
        printf("Capturing %d packets...\n", packet_count);
    } else {
        printf("Capturing packets... Press Ctrl+C to stop\n");
    }
    printf("\n");
    
    // Allocate buffer
    char *buffer = malloc(buffer_len);
    if (!buffer) {
        printf("Memory allocation failed\n");
        close(bpf_fd);
        return 1;
    }
    
    // Capture packets
    while (1) {
        ssize_t bytes_read = read(bpf_fd, buffer, buffer_len);
        if (bytes_read == -1) {
            perror("read");
            break;
        }
        
        char *ptr = buffer;
        while (ptr < buffer + bytes_read) {
            struct bpf_hdr *bpf_packet = (struct bpf_hdr *)ptr;
            
            process_packet(ptr + bpf_packet->bh_hdrlen, bpf_packet->bh_caplen, verbose);
            captured++;
            
            if (packet_count > 0 && captured >= packet_count) {
                goto cleanup;
            }
            
            ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
        }
    }
    
cleanup:
    free(buffer);
    close(bpf_fd);
    printf("\nCapture complete. Total packets captured: %d\n", captured);
    return 0;
}