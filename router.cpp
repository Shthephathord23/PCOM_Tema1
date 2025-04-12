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


route_table_entry* get_best_route(uint32_t ip_dest, route_table_entry* rtable, size_t rtable_len)
{
	for (size_t i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
			return &rtable[i];
		}
	}
	return NULL;
}

arp_table_entry* get_arp_entry(uint32_t ip_dest, arp_table_entry* arp_table, size_t arp_table_len)
{
	for (size_t i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_dest) {
			return &arp_table[i];
		}
	}
	return NULL;
}

route_table_entry* get_best_route_array(uint32_t ip_dest, std::array<route_table_entry, RTABLE_SIZE>& rtable_array)
{
	for (size_t i = 0; i < rtable_array.size(); i++) {
		if (rtable_array[i].prefix == (ip_dest & rtable_array[i].mask)) {
			return &rtable_array[i];
		}
	}
	return NULL;
}

arp_table_entry* get_arp_entry_array(uint32_t ip_dest, std::array<arp_table_entry, ARP_TABLE_SIZE>& arp_table_array)
{
	for (size_t i = 0; i < arp_table_array.size(); i++) {
		if (arp_table_array[i].ip == ip_dest) {
			return &arp_table_array[i];
		}
	}
	return NULL;
}

char* my_inet_ntoa(uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	char* tmp = (char* )malloc(100);
	memcpy(tmp, inet_ntoa(addr), 100);
	return tmp;
}

char *my_mac_ntoa(uint8_t *mac)
{
	static char mac_str[18];
	sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	char* tmp = (char* )malloc(100);
	memcpy(tmp, mac_str, 18);
	return tmp;
}


bool cmp(route_table_entry& a, route_table_entry& b)
{
	if (a.mask == b.mask) {
		return a.prefix < b.prefix;
	}
	return a.mask > b.mask;
}

void handle_ip_packet(char buf[MAX_PACKET_LEN], size_t len, size_t interface,
					  std::array<route_table_entry, RTABLE_SIZE>& rtable_array,
					  size_t rtable_len,
					  std::array<arp_table_entry, ARP_TABLE_SIZE>& arp_table_array,
					  size_t arp_table_len)
{

}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	route_table_entry* rtable = (route_table_entry*)malloc(sizeof(route_table_entry) * RTABLE_SIZE);
	size_t rtable_len = read_rtable(argv[1], rtable);
	DIE(rtable_len < 0, "read_rtable");

	std::array<route_table_entry, RTABLE_SIZE> rtable_array;
	std::copy(rtable, rtable + rtable_len, rtable_array.begin());
	std::sort(rtable_array.begin(), &rtable_array[rtable_len], cmp);

	arp_table_entry* arp_table = (arp_table_entry*)malloc(sizeof(arp_table_entry) * ARP_TABLE_SIZE);
	size_t arp_table_len = parse_arp_table((char* )"arp_table.txt", arp_table);
	DIE(arp_table_len < 0, "parse_arp_table");

	std::array<arp_table_entry, ARP_TABLE_SIZE> arp_table_array;
	std::copy(arp_table, arp_table + arp_table_len, arp_table_array.begin());

	size_t cnt = 0;

	while (1)
	{
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		printf("\n\nrouter %zu\n", ++cnt);

		// ethernet_frame* eth_frame = (ethernet_frame *)buf;
		// uint16_t eth_type = ntohs(eth_frame->eth_hdr.ethr_type);

		ether_hdr* eth_header = reinterpret_cast<ether_hdr *>(buf);
		void* payload = (void *)(buf + sizeof(ether_hdr));

		printf("Am primit frame cu src = %s si dest = %s\nde tip = %x\n", my_mac_ntoa(eth_header->ethr_shost), my_mac_ntoa(eth_header->ethr_dhost), ntohs(eth_header->ethr_type));
		uint16_t l_ether_type = ntohs(eth_header->ethr_type);

		switch (l_ether_type)
		{
		case ETHER_TYPE_IP:
		{
			printf("Am primit IP packet\n");
			
			ip_hdr* ip_header = (ip_hdr* )payload;

			uint16_t packet_checksum = ip_header->checksum;
			packet_checksum = ntohs(packet_checksum);
			ip_header->checksum = 0;
			uint16_t calculated_checksum = checksum((uint16_t* )ip_header, sizeof(ip_hdr));
			if (packet_checksum != calculated_checksum)
			{
				continue;
			}
			ip_header->checksum = htons(packet_checksum);
			printf("Avem checksum bun\n");

			uint32_t dest_address = ip_header->dest_addr;
			route_table_entry* best_route = get_best_route_array(dest_address, rtable_array);

			printf("Sursa este %s, iar destinatia este %s\n", my_inet_ntoa(ip_header->source_addr), my_inet_ntoa(dest_address));

			if (best_route == NULL)
			{
				printf("Nu am gasit ruta\n");
				continue;
			}
			
			dest_address = best_route->next_hop;
			printf("Am gasit ruta si next-hop este %s\n", my_inet_ntoa(dest_address));

			printf("best route:\n\tprefix = %s next_hop = %s mask = %s interface = %d\n", my_inet_ntoa(best_route->prefix), my_inet_ntoa(best_route->next_hop), my_inet_ntoa(best_route->mask), best_route->interface);

			if (ip_header->ttl >= 1)
			{
				ip_header->ttl = ip_header->ttl - 1;
			}
			else
			{
				printf("TTL expired\n");
				continue;
			}

			printf("TTL este %d\n", ip_header->ttl);

			// ip_header->checksum = htons(~(~ntohs(ip_header->checksum) + ~((uint16_t)((ip_header->ttl) + 1)) + (uint16_t)(ip_header->ttl)) - 1);
			ip_header->checksum = 0;
			ip_header->checksum = htons(checksum((uint16_t*)ip_header, sizeof(ip_hdr)));

			arp_table_entry* arp_entry = get_arp_entry_array(dest_address, arp_table_array);
			if (arp_entry == NULL)
			{
				printf("Nu am gasit entry in ARP\n");
				continue;
			}

			uint8_t src_mac[6] = {0};
			get_interface_mac(best_route->interface, src_mac);

			memcpy(eth_header->ethr_shost, src_mac, 6);
			memcpy(eth_header->ethr_dhost, arp_entry->mac, 6);

			printf("Am gasit entry in ARP, src = %s dst = %s\n", my_mac_ntoa(src_mac), my_mac_ntoa(arp_entry->mac));

			send_to_link(len, buf, best_route->interface);

			break;
		}

		case ETHER_TYPE_ARP:
		{
			printf("Am primit ARP packet\n");

			arp_hdr* arp_header = (arp_hdr* )payload;

			uint16_t opcode = ntohs(arp_header->opcode);
			if (opcode == 1)
			{
				printf("Am primit ARP request\n");
				uint32_t dest_ip = arp_header->tprotoa;
				uint8_t dest_mac[6] = {0};
				uint32_t src_ip = arp_header->sprotoa;
				uint8_t src_mac[6] = {0};

				printf("\tsrc_mac = %s src_ip = %s\n\tdest_mac = %s dest_ip = %s\n",
					my_mac_ntoa(arp_header->shwa), my_inet_ntoa(src_ip),
					my_mac_ntoa(arp_header->thwa), my_inet_ntoa(dest_ip));
				
			}
			else if (opcode == 2)
			{
				printf("Am primit ARP reply\n");

				uint32_t dest_ip = arp_header->tprotoa;
				uint8_t dest_mac[6] = {0};
				uint32_t src_ip = arp_header->sprotoa;
				uint8_t src_mac[6] = {0};

				printf("\tsrc_mac = %s src_ip = %s\n\tdest_mac = %s dest_ip = %s\n",
					my_mac_ntoa(arp_header->shwa), my_inet_ntoa(src_ip),
					my_mac_ntoa(arp_header->thwa), my_inet_ntoa(dest_ip));
			}
			else
			{
				printf("Am primit un ARP invalid\n");
				continue;
			}
		}
		
		default:
			break;
		}

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

	}
	free(rtable);
	free(arp_table);
}
