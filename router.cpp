#include "router.hpp"

void send_arp_req(uint32_t dest_ip, size_t non_interface);
void handle_arp_packet(arp_packet* arp_packet);

void send_ipv4_packet(ipv4_packet* ipv4_packet, bool drop_if_no_route);
void handle_time_exceeded(ipv4_packet* recieved_packet);
void handle_destination_unreachable(ipv4_packet* recieved_packet);
void handle_echo_reply(ipv4_packet* recieved_packet);
void handle_ipv4_packet(ipv4_packet* ipv4_packet);

std::array<route_table_entry, RTABLE_SIZE> rtable_array;
size_t rtable_len;

std::array<arp_table_entry, ARP_TABLE_SIZE> arp_table_array;
size_t arp_table_len;

std::unordered_map<uint32_t, uint8_t*> arp_table_map;

std::unordered_map<uint32_t, std::queue<ipv4_packet>> waiting_packets;

void debug_waiting_packets() {
    printf("Current waiting_packets contents:\n");
    for (const auto& entry : waiting_packets) {
        printf("  IP: %s (0x%x) - %zu packets waiting\n", 
               my_inet_ntoa(entry.first), entry.first, entry.second.size());
    }
}

bool cmp(route_table_entry& a, route_table_entry& b)
{
	if (a.mask == b.mask) {
		return a.prefix < b.prefix;
	}
	return a.mask > b.mask;
}

void send_arp_req(uint32_t dest_ip, size_t non_interface)
{
	arp_packet arp_req;
	memset(&arp_req, 0, sizeof(arp_packet));
	arp_req.length = sizeof(ethernet_header) + sizeof(arp_header);

	init_arp_hdr(&arp_req, ARP_REQUEST, dest_ip);

	printf("Trimitem ARP BROADCAST request pentru %s\n", my_inet_ntoa(dest_ip));

	for (size_t i = 0; i < ROUTER_NUM_INTERFACES; ++i)
	{
		if (i == non_interface)
			continue;

		uint8_t src_mac[6] = {0};
		get_interface_mac(i, src_mac);
		arp_hdr_set_src(&arp_req, src_mac, reinterpret_cast<uint32_t>(inet_addr(get_interface_ip(i))));

		reinterpret_cast<ethernet_frame* >(&arp_req)->send_to_broadcast(ETHER_TYPE_ARP, src_mac, i);
	}
}

void send_arp_reply(arp_packet* arp_request)
{
	arp_packet arp_reply;
	memset(&arp_reply, 0, sizeof(arp_packet));
	arp_reply.length = sizeof(ethernet_header) + sizeof(arp_header);

	init_arp_hdr(&arp_reply, ARP_REPLY, *get_arp_src_ip(arp_request));
	memcpy(get_arp_dest_mac(&arp_reply), get_arp_src_mac(arp_request), 6);

	uint32_t dest_ip = *get_arp_dest_ip(arp_request);
	arp_hdr_set_src(&arp_reply, arp_table_map[dest_ip], dest_ip);
	
	uint8_t src_mac[6] = {0};
	get_interface_mac(*get_eth_interface(arp_request), src_mac);

	printf("Bouta send ARP packet\n\tsrc_mac = %s src_ip = %s\n\tdest_mac = %s dest_ip = %s\n",
		my_mac_ntoa(get_arp_src_mac(&arp_reply)), my_inet_ntoa(*get_arp_src_ip(&arp_reply)),
		my_mac_ntoa(get_arp_dest_mac(&arp_reply)), my_inet_ntoa(*get_arp_dest_ip(&arp_reply)));

	reinterpret_cast<ethernet_frame* >(&arp_reply)->send_to_mac(ETHER_TYPE_ARP, src_mac, get_arp_src_mac(arp_request), *get_eth_interface(arp_request));
}

void handle_arp_packet(arp_packet* arp_pkt)
{
	if (ntohs(*get_arp_hw_type(arp_pkt)) != HARDWARE_TYPE_ETHERNET ||
		ntohs(*get_arp_proto_type(arp_pkt)) != PROTOCOL_TYPE_IP ||
		*get_arp_hw_len(arp_pkt) != HARDWARE_SIZE_ETHERNET ||
		*get_arp_proto_len(arp_pkt) != PROTOCOL_SIZE_IP)
	{
		printf("ARP invalid\n");
		return;
	}
	uint16_t opcode = ntohs(*get_arp_opcode(arp_pkt));
	switch (opcode)
	{
		case ARP_REQUEST:
		{
			printf("Am primit ARP request\n");
			printf("\tsrc_mac = %s src_ip = %s\n\tdest_mac = %s dest_ip = %s\n",
				my_mac_ntoa(get_arp_src_mac(arp_pkt)), my_inet_ntoa(*get_arp_src_ip(arp_pkt)),
				my_mac_ntoa(get_arp_dest_mac(arp_pkt)), my_inet_ntoa(*get_arp_dest_ip(arp_pkt)));

			uint32_t dest_ip = *get_arp_dest_ip(arp_pkt);

			if (arp_table_map.find(dest_ip) != arp_table_map.end())
			{
				printf("Am gasit entry in ARP MAP\n");
				send_arp_reply(arp_pkt);
				return;
			}

			// waiting_packets[dest_ip].push(*reinterpret_cast<ethernet_frame*>(arp_pkt));
			
			// if (waiting_packets[dest_ip].size() < 2)
			// 	send_arp_req(dest_ip, *get_eth_interface(arp_pkt));
			break;
		}

		case ARP_REPLY:
		{
			printf("Am primit ARP reply\n");
			printf("\tsrc_mac = %s src_ip = %s\n\tdest_mac = %s dest_ip = %s\n",
				my_mac_ntoa(get_arp_src_mac(arp_pkt)), my_inet_ntoa(*get_arp_src_ip(arp_pkt)),
				my_mac_ntoa(get_arp_dest_mac(arp_pkt)), my_inet_ntoa(*get_arp_dest_ip(arp_pkt)));

			uint32_t dest_ip = *get_arp_src_ip(arp_pkt);

			arp_table_map[dest_ip] = (uint8_t*)malloc(6);
			memcpy(arp_table_map[dest_ip], get_arp_src_mac(arp_pkt), 6);

			printf("arp_table_map[%s] = %s\n", my_inet_ntoa(dest_ip), my_mac_ntoa(arp_table_map[dest_ip]));
			debug_waiting_packets();
			printf("Am gasit %zu entry in waiting_packets[%s]\n", waiting_packets[dest_ip].size(), my_inet_ntoa(dest_ip));

			if (waiting_packets.find(dest_ip) != waiting_packets.end())
			{
				while (!waiting_packets[dest_ip].empty())
				{
					ipv4_packet* eth_frame = &waiting_packets[dest_ip].front();
					uint16_t eth_type = ntohs(*get_eth_type(eth_frame));

					switch (eth_type)
					{
						case ETHER_TYPE_IP:
						{
							ipv4_packet* packet_to_send = reinterpret_cast<ipv4_packet*>(eth_frame);
							send_ipv4_packet(packet_to_send, false);
							break;
						}

						case ETHER_TYPE_ARP:
						{
							printf("Trolaj imens\n");
							arp_packet* arp_req = reinterpret_cast<arp_packet*>(eth_frame);
							if (ntohs(*get_arp_opcode(arp_req)) == ARP_REQUEST)
							{
								send_arp_reply(arp_req);
							}
							break;
						}

						default:
							break;
					}

					waiting_packets[dest_ip].pop();
				}
				waiting_packets.erase(dest_ip);
			}
			break;
		}
		
		default:
			printf("Am primit un ARP invalid\n");
			break;
	}
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

	// arp_table_entry* arp_entry = get_arp_entry_array(best_route->next_hop, arp_table_array);
	// if (arp_entry == NULL)
	// {
	// 	printf("Nu am gasit entry in ARP\n");
	// 	return;
	// }

	if (arp_table_map.find(best_route->next_hop) == arp_table_map.end())
	{
		printf("Nu am gasit entry in ARP MAP\n");

		ethernet_frame eth_copy;
		memcpy(&eth_copy, ipv4_packet, sizeof(ethernet_frame));
		waiting_packets[best_route->next_hop].push(*ipv4_packet);

		debug_waiting_packets();
		printf("Am gasit %zu entry in waiting_packetsl la ip = %s\n", waiting_packets[best_route->next_hop].size(), my_inet_ntoa(best_route->next_hop));

		if (waiting_packets[best_route->next_hop].size() < 2)
			send_arp_req(best_route->next_hop, ipv4_packet->interface);

		return;
	}

	// ipv4_packet->send_to_route(best_route, arp_entry->mac);
	ipv4_packet->send_to_route(best_route, arp_table_map[best_route->next_hop]);
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
	arp_table_len = parse_arp_table((char* )"arp_table/arp_table.txt", arp_table);
	DIE(arp_table_len < 0, "parse_arp_table");

	std::copy(arp_table, arp_table + arp_table_len, arp_table_array.begin());

	for (size_t i = 0; i < ROUTER_NUM_INTERFACES; ++i)
	{
		uint8_t src_mac[6] = {0};
		get_interface_mac(i, src_mac);
		uint32_t src_ip = reinterpret_cast<uint32_t>(inet_addr(get_interface_ip(i)));
		arp_table_map[src_ip] = (uint8_t*)malloc(6);
		memcpy(arp_table_map[src_ip], src_mac, 6);
	}

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
				handle_arp_packet(reinterpret_cast<arp_packet* >(&eth_frame));
				break;
			}
			
			default:
			{
				break;
			}
		}

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

	}
	free(rtable);
	free(arp_table);
	for (auto& entry : arp_table_map)
	{
		free(entry.second);
	}
}
