#include "router.hpp"

void send_ipv4_packet(ipv4_packet* ipv4_packet, bool drop_if_no_route);
void handle_time_exceeded(ipv4_packet* recieved_packet);
void handle_destination_unreachable(ipv4_packet* recieved_packet);
void handle_ipv4_packet(ipv4_packet* ipv4_packet);

std::array<route_table_entry, RTABLE_SIZE> rtable_array;
size_t rtable_len;

std::array<arp_table_entry, ARP_TABLE_SIZE> arp_table_array;
size_t arp_table_len;

std::unordered_map<uint32_t, uint8_t[6]> arp_table_map;

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

void send_ipv4_packet(ipv4_packet* ipv4_packet, bool drop_if_no_route)
{
	printf("Sursa este %s, iar destinatia este %s\n", my_inet_ntoa(*get_ipv4_src_ip(ipv4_packet)), my_inet_ntoa(*get_ipv4_dest_ip(ipv4_packet)));
	route_table_entry* best_route = get_best_route_array(*get_ipv4_dest_ip(ipv4_packet), rtable_array);
	if (best_route == NULL || best_route->next_hop == 0)
	{
		printf("Nu am gasit ruta\n");
		if (drop_if_no_route)
			return;
		handle_destination_unreachable(ipv4_packet);
		return;
	}
	printf("%p %s %s %s %s\n", best_route, my_inet_ntoa(best_route->prefix), my_inet_ntoa(best_route->next_hop), my_inet_ntoa(best_route->mask), get_interface_ip(best_route->interface));
	printf("Am gasit ruta si next-hop este %s\n", my_inet_ntoa(best_route->next_hop));

	arp_table_entry* arp_entry = get_arp_entry_array(best_route->next_hop, arp_table_array);
	if (arp_entry == NULL)
	{
		printf("Nu am gasit entry in ARP\n");
		return;
	}

	ipv4_packet->send_to_route(best_route, arp_entry);

	printf("Am gasit entry in ARP, src = %s dst = %s\n", my_mac_ntoa(get_eth_src_mac(ipv4_packet)), my_mac_ntoa(arp_entry->mac));
}

void handle_icmp(ipv4_packet* recieved_packet, icmp_packet* icmp_response, size_t length,
							   uint8_t icmp_type, uint8_t id, uint8_t seq)
{
	memset(icmp_response, 0, sizeof(icmp_packet));

	size_t len = std::min(length, MAX_ICMP_PAYLOAD_LEN);
	if (icmp_type == ICMP_ECHO_REPLY)
	{
		memcpy(get_icmp_payload(icmp_response), get_icmp_payload(recieved_packet), len);
	}
	else
	{
		memcpy(get_icmp_payload(icmp_response), get_eth_payload(recieved_packet), len);
	}
	*get_eth_length(icmp_response) = sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(icmp_header) + len;

	init_icmp_hdr(icmp_response, icmp_type, id, seq);

	init_ipv4_hdr(icmp_response, len + sizeof(ipv4_header) + sizeof(icmp_header),
				  reinterpret_cast<uint32_t>(inet_addr(get_interface_ip(*get_eth_interface(recieved_packet)))),
				  *get_ipv4_src_ip(recieved_packet));
	
	send_ipv4_packet(reinterpret_cast<ipv4_packet*>(icmp_response), true);
}

void handle_time_exceeded(ipv4_packet* recieved_packet)
{
	icmp_packet icmp_response;
	handle_icmp(recieved_packet, &icmp_response, get_eth_payload_len(recieved_packet), ICMP_TIME_EXCEEDED, 0, 0);
}

void handle_destination_unreachable(ipv4_packet* recieved_packet)
{
	icmp_packet icmp_response;
	handle_icmp(recieved_packet, &icmp_response, get_eth_payload_len(recieved_packet), ICMP_DEST_UNREACHABLE, 0, 0);
}

void handle_echo_reply(ipv4_packet* recieved_packet)
{
	icmp_packet icmp_response;
	handle_icmp(recieved_packet, &icmp_response, get_eth_payload_len(recieved_packet), ICMP_ECHO_REPLY, get_icmp_hdr(recieved_packet)->un_t.echo_t.id, get_icmp_hdr(recieved_packet)->un_t.echo_t.seq);
}

void handle_ipv4_packet(ipv4_packet* ipv4_packet)
{
	printf("Am primit IP packet\n");
	if (!ipv4_packet->is_valid())
	{
		printf("Pachet IP invalid, checksum prost\n");
		return;
	}
	printf("Avem checksum bun\n");

	if (!ipv4_packet->is_not_expired())
	{
		printf("TTL expired\n");
		handle_time_exceeded(ipv4_packet);
		return;
	}
	ipv4_packet->calculate_checksum();
	printf("TTL este %d\n", *get_ipv4_ttl(ipv4_packet));

	printf("interfata mea este %zu ip-ul meu %s\n", *get_eth_interface(ipv4_packet), get_interface_ip(*get_eth_interface(ipv4_packet)));
	if (*get_ipv4_dest_ip(ipv4_packet) ==
		reinterpret_cast<uint32_t>(inet_addr(get_interface_ip(*get_eth_interface(ipv4_packet))))
	)
	{
		printf("Pachetul este pentru mine\n");
		if (*get_icmp_type(ipv4_packet) == ICMP_ECHO_REQUEST)
		{
			printf("Am primit un echo request\n");
			handle_echo_reply(ipv4_packet);
		}
		return;
	}

	send_ipv4_packet(ipv4_packet, false);
}

int main(int argc, char *argv[])
{
	ethernet_frame eth_frame;

	// Do not modify this line
	init(argv + 2, argc - 2);

	printf("ip i guess %s %s %s\n", get_interface_ip(0), get_interface_ip(1), get_interface_ip(2));

	route_table_entry* rtable = (route_table_entry*)malloc(sizeof(route_table_entry) * RTABLE_SIZE);
	rtable_len = read_rtable(argv[1], rtable);
	DIE(rtable_len < 0, "read_rtable");

	std::copy(rtable, rtable + rtable_len, rtable_array.begin());
	std::sort(rtable_array.begin(), &rtable_array[rtable_len], cmp);

	arp_table_entry* arp_table = (arp_table_entry*)malloc(sizeof(arp_table_entry) * ARP_TABLE_SIZE);
	arp_table_len = parse_arp_table((char* )"arp_table.txt", arp_table);
	DIE(arp_table_len < 0, "parse_arp_table");

	std::copy(arp_table, arp_table + arp_table_len, arp_table_array.begin());

	size_t cnt = 0;

	while (1)
	{
		*get_eth_interface(&eth_frame) = recv_from_any_link(eth_frame.buf, &eth_frame.length);
		DIE(*get_eth_interface(&eth_frame) < 0, "recv_from_any_links");

		printf("\n\nrouter %zu\n", ++cnt);

		uint16_t eth_type = ntohs(*get_eth_type(&eth_frame));

		printf("Am primit frame cu src = %s si dest = %s\nde tip = %x si lungime = %zu\n", my_mac_ntoa(get_eth_src_mac(&eth_frame)), my_mac_ntoa(get_eth_dest_mac(&eth_frame)), ntohs(*get_eth_type(&eth_frame)), *get_eth_length(&eth_frame));

		switch (eth_type)
		{
		case ETHER_TYPE_IP:
		{
			handle_ipv4_packet(reinterpret_cast<ipv4_packet* >(&eth_frame));
			break;
		}

		case ETHER_TYPE_ARP:
		{
			printf("Am primit ARP packet\n");

			// arp_hdr* arp_header = (arp_hdr* )eth_frame->payload;

			// uint16_t opcode = ntohs(arp_header->opcode);
			// if (opcode == 1)
			// {
			// 	printf("Am primit ARP request\n");
			// 	uint32_t dest_ip = arp_header->tprotoa;
			// 	uint8_t dest_mac[6] = {0};
			// 	uint32_t src_ip = arp_header->sprotoa;
			// 	uint8_t src_mac[6] = {0};

			// 	printf("\tsrc_mac = %s src_ip = %s\n\tdest_mac = %s dest_ip = %s\n",
			// 		my_mac_ntoa(arp_header->shwa), my_inet_ntoa(src_ip),
			// 		my_mac_ntoa(arp_header->thwa), my_inet_ntoa(dest_ip));
				
			// }
			// else if (opcode == 2)
			// {
			// 	printf("Am primit ARP reply\n");

			// 	uint32_t dest_ip = arp_header->tprotoa;
			// 	uint8_t dest_mac[6] = {0};
			// 	uint32_t src_ip = arp_header->sprotoa;
			// 	uint8_t src_mac[6] = {0};

			// 	printf("\tsrc_mac = %s src_ip = %s\n\tdest_mac = %s dest_ip = %s\n",
			// 		my_mac_ntoa(arp_header->shwa), my_inet_ntoa(src_ip),
			// 		my_mac_ntoa(arp_header->thwa), my_inet_ntoa(dest_ip));
			// }
			// else
			// {
			// 	printf("Am primit un ARP invalid\n");
			// 	continue;
			// }
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
