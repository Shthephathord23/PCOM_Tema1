#include "protocols.h"
// #include "queue.h"
#include "lib.h"
#include <arpa/inet.h>	
#include <cstring>
#include <arpa/inet.h>

#define ETHER_TYPE_IP 0x0800
#define ETHER_TYPE_ARP 0x0806

#define RTABLE_SIZE 80000

route_table_entry* get_best_route(uint32_t ip_dest, route_table_entry* rtable, size_t rtable_len)
{
	for (size_t i = 0; i < rtable_len; i++) {
		/* Cum tabela este sortatD, primul match este prefixul ce mai specific */
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

char* my_inet_ntoa(uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	return inet_ntoa(addr);
}

void process_ip_packet()
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

	arp_table_entry* arp_table = (arp_table_entry*)malloc(sizeof(arp_table_entry) * RTABLE_SIZE);
	size_t arp_table_len = parse_arp_table((char* )"arp_table.txt", arp_table);
	DIE(arp_table_len < 0, "parse_arp_table");

	while (1)
	{
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		printf("router\n");

		ether_hdr* eth_header = (ether_hdr *)buf;
		void* payload = (void *)(buf + sizeof(ether_hdr));

		printf("%x\n", ntohs(eth_header->ethr_type));
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
			route_table_entry* best_route = get_best_route(dest_address, rtable, rtable_len);

			printf("Destinatia este %s\n", my_inet_ntoa(dest_address));

			if (best_route == NULL)
			{
				printf("Nu am gasit ruta\n");
				continue;
			}

			printf("Am gasit ruta\n");

			dest_address = best_route->next_hop;
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


			arp_table_entry* arp_entry = get_arp_entry(dest_address, arp_table, arp_table_len);
			if (arp_entry == NULL)
			{
				printf("Nu am gasit entry in ARP\n");
				continue;
			}

			uint8_t src_mac[6] = {0};
			get_interface_mac(best_route->interface, src_mac);

			memcpy(eth_header->ethr_shost, src_mac, 6);
			memcpy(eth_header->ethr_dhost, arp_entry->mac, 6);

			send_to_link(len, buf, best_route->interface);

			break;
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
