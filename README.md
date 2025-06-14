# Simple TCPDump

A simple packet sniffer built using raw sockets with `ETH_P_ALL` to capture all Ethernet packets.

## Features

- Captures all network packets using raw sockets
- Parses Ethernet, IP, TCP, UDP, and ICMP headers
- Displays detailed packet information including:
  - Source and destination MAC addresses
  - Source and destination IP addresses
  - Protocol information
  - Port numbers for TCP/UDP
  - Packet timestamps

## Requirements

- macOS or Linux system
- Root privileges (required for raw socket creation)
- GCC compiler

## Building

```bash
make
```

## Running

**Important:** This program requires root privileges to create raw sockets.

```bash
sudo ./simple_tcpdump
```

## Usage

The program will start capturing packets immediately and display detailed information for each packet. Press `Ctrl+C` to stop the capture.

## Installation

To install the program system-wide:

```bash
make install
```

To uninstall:

```bash
make uninstall
```

## How it works

1. Creates a raw socket using `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`
2. Uses `recvfrom()` to capture packets from the network interface
3. Parses the packet headers (Ethernet, IP, TCP/UDP/ICMP)
4. Displays formatted packet information

## Note

This is a educational implementation. For production use, consider using established libraries like libpcap.