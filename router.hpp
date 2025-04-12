#include "protocols.h"
// #include "queue.h"
#include "lib.h"
#include <arpa/inet.h>	
#include <cstring>
#include <arpa/inet.h>

#include <array>
#include <algorithm>

#define ETHER_TYPE_IP 0x0800
#define ETHER_TYPE_ARP 0x0806

#define RTABLE_SIZE 80000
#define ARP_TABLE_SIZE 10

typedef ether_hdr ethernet_header;
typedef ip_hdr ipv4_header;
typedef arp_hdr arp_header;
typedef icmp_hdr icmp_header;

struct ethernet_frame
{
	ethernet_header eth_hdr;
	uint8_t payload[MAX_PACKET_LEN - sizeof(ethernet_header)];
};

struct ipv4_packet
{
	ethernet_header eth_hdr;
	ipv4_header ipv4_hdr;
	uint8_t payload[MAX_PACKET_LEN - sizeof(ethernet_header) - sizeof(ip_hdr)];
};

struct arp_packet
{
	ethernet_header eth_hdr;
	arp_header arp_hdr;
	uint8_t payload[MAX_PACKET_LEN - sizeof(ethernet_header) - sizeof(arp_header)];
};

struct icmp_packet
{
	ethernet_header eth_hdr;
	ipv4_header ipv4_hdr;
	icmp_header icmp_hdr;
	uint8_t payload[MAX_PACKET_LEN - sizeof(ethernet_header) - sizeof(ip_hdr) - sizeof(icmp_header)];
};
