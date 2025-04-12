#include "protocols.h"
#include "lib.h"
#include <arpa/inet.h>	
#include <cstring>

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

#define get_eth_hdr(x) ((ethernet_header *)(x)->buf)
#define get_eth_src_mac(x) (get_eth_hdr(x)->ethr_shost)
#define get_eth_dest_mac(x) (get_eth_hdr(x)->ethr_dhost)
#define get_eth_type(x) (&(get_eth_hdr(x)->ethr_type))
#define get_eth_payload(x) ((char *)(x)->buf + sizeof(ethernet_header))

struct ethernet_frame
{
#define eth_hdr get_eth_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;
};


#define get_ipv4_hdr(x) ((ipv4_header *)((char *)(x)->buf + sizeof(ethernet_header)))
#define get_ipv4_src_ip(x) (&(get_ipv4_hdr(x)->source_addr))
#define get_ipv4_dest_ip(x) (&(get_ipv4_hdr(x)->dest_addr))
#define get_ipv4_ttl(x) (&(get_ipv4_hdr(x)->ttl))
#define get_ipv4_proto(x) (&(get_ipv4_hdr(x)->proto))
#define get_ipv4_checksum(x) (&(get_ipv4_hdr(x)->checksum))
#define get_ipv4_payload(x) ((char *)(x)->buf + sizeof(ethernet_header) + sizeof(ipv4_header))

struct ipv4_packet
{
#define ipv4_hdr get_ipv4_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;
    // #define eth_hdr ((ethernet_header *)this->buf)
    // #define ipv4_hdr ((ipv4_header *)((char *)this->buf + sizeof(ethernet_header)))
    
    // inline uint8_t* get_src_mac() const
    // {
    //     return eth_hdr->ethr_shost;
    // }
    // inline uint8_t* get_dest_mac() const
    // {
    //     return eth_hdr->ethr_dhost;
    // }
    // inline uint16_t get_ether_type() const
    // {
    //     return ntohs(eth_hdr->ethr_type);
    // }
    
    // inline uint32_t get_src_ip() const
    // {
    //     return ipv4_hdr->source_addr;
    // }
    // inline uint32_t get_dest_ip() const
    // {
    //     return ipv4_hdr->dest_addr;
    // }
    
    // inline uint8_t get_ttl() const
    // {
    //     return ipv4_hdr->ttl;
    // }
    
    inline void calculate_checksum()
    {
        ipv4_hdr->checksum = 0;
        ipv4_hdr->checksum = htons(checksum(reinterpret_cast<uint16_t *>(ipv4_hdr), sizeof(ipv4_header)));
    }
    
    inline bool is_valid()
    {
        uint16_t packet_checksum = ipv4_hdr->checksum;
        calculate_checksum();
        uint16_t calculated_checksum = ipv4_hdr->checksum;
        printf("Checksum: %x %x\n", packet_checksum, calculated_checksum);
        return packet_checksum == calculated_checksum;
    }
    
    inline bool is_not_expired()
    {
        return --ipv4_hdr->ttl > 0;
    }
    
    inline route_table_entry* get_best_route(std::array<route_table_entry, RTABLE_SIZE>& rtable) const
    {
        return ::get_best_route_array(ipv4_hdr->dest_addr, rtable);
    }
    
    inline arp_table_entry* get_arp_entry(std::array<arp_table_entry, ARP_TABLE_SIZE>& arp_table) const
    {
        return ::get_arp_entry_array(ipv4_hdr->dest_addr, arp_table);
    }
    
    inline void send_to_route(route_table_entry* route, arp_table_entry* arp_entry)
    {
        uint8_t src_mac[6] = {0};
        get_interface_mac(route->interface, src_mac);
        
        memcpy(eth_hdr->ethr_shost, src_mac, 6);
        memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
        
        send_to_link(length, buf, route->interface);
    }
    
};

struct arp_packet
{
    char buf[MAX_PACKET_LEN];
    size_t length;
};

#define get_icmp_hdr(x) ((icmp_header *)((char *)(x)->buf + sizeof(ethernet_header) + sizeof(ipv4_header)))

struct icmp_packet
{
#define icmp_hdr get_icmp_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;

    inline uint8_t* get_src_mac() const
    {
        return eth_hdr->ethr_shost;
    }
    inline uint8_t* get_dest_mac() const
    {
        return eth_hdr->ethr_dhost;
    }
    inline uint16_t get_ether_type() const
    {
        return ntohs(eth_hdr->ethr_type);
    }

    inline uint32_t get_src_ip() const
    {
        return ipv4_hdr->source_addr;
    }
    inline uint32_t get_dest_ip() const
    {
        return ipv4_hdr->dest_addr;
    }

    inline uint8_t get_ttl() const
    {
        return ipv4_hdr->ttl;
    }

    uint8_t get_icmp_type() const
    {
        return icmp_hdr->mtype;
    }
    uint8_t get_icmp_code() const
    {
        return icmp_hdr->mcode;
    }
    uint16_t get_icmp_checksum() const
    {
        return icmp_hdr->check;
    }


};
