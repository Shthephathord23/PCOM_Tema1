#include "protocols.h"
#include "lib.h"
#include <arpa/inet.h>
#include <cstring>

#include <array>
#include <algorithm>

#define ETHER_TYPE_IP 0x0800
#define ETHER_TYPE_ARP 0x0806

#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACHABLE 3
#define ICMP_ECHO_REQUEST 8
#define ICMP_TIME_EXCEEDED 11

#define RTABLE_SIZE 80000
#define ARP_TABLE_SIZE 10

typedef ether_hdr ethernet_header;
typedef ip_hdr ipv4_header;
typedef arp_hdr arp_header;
typedef icmp_hdr icmp_header;

route_table_entry *get_best_route(uint32_t ip_dest, route_table_entry *rtable, size_t rtable_len)
{
    for (size_t i = 0; i < rtable_len; i++)
    {
        if (rtable[i].prefix == (ip_dest & rtable[i].mask))
        {
            return &rtable[i];
        }
    }
    return NULL;
}

arp_table_entry *get_arp_entry(uint32_t ip_dest, arp_table_entry *arp_table, size_t arp_table_len)
{
    for (size_t i = 0; i < arp_table_len; i++)
    {
        if (arp_table[i].ip == ip_dest)
        {
            return &arp_table[i];
        }
    }
    return NULL;
}

route_table_entry *get_best_route_array(uint32_t ip_dest, std::array<route_table_entry, RTABLE_SIZE> &rtable_array)
{
    for (size_t i = 0; i < rtable_array.size(); i++)
    {
        if (rtable_array[i].prefix == (ip_dest & rtable_array[i].mask))
        {
            return &rtable_array[i];
        }
    }
    return NULL;
}

arp_table_entry *get_arp_entry_array(uint32_t ip_dest, std::array<arp_table_entry, ARP_TABLE_SIZE> &arp_table_array)
{
    for (size_t i = 0; i < arp_table_array.size(); i++)
    {
        if (arp_table_array[i].ip == ip_dest)
        {
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
#define get_eth_interface(x) (&(x)->interface)
#define get_eth_length(x) (&((x)->length))
#define get_eth_payload_len(x) (*get_eth_length(x) - sizeof(ethernet_header))
#define MAX_ETH_PAYLOAD_LEN (MAX_PACKET_LEN - sizeof(ethernet_header))

#define init_eth_hdr(__x__, __src_addr__, __dst_addr__, __type__) \
    do                                                            \
    {                                                             \
        ethernet_header *hdr = get_eth_hdr(__x__);                \
        memcpy(hdr->ethr_shost, __src_addr__, 6);                 \
        memcpy(hdr->ethr_dhost, __dst_addr__, 6);                 \
        hdr->ethr_type = htons(__type__);                         \
    } while (0)

struct ethernet_frame
{
#define eth_hdr get_eth_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;
    size_t interface;
};

#define get_ipv4_hdr(x) ((ipv4_header *)((char *)(x)->buf + sizeof(ethernet_header)))
#define get_ipv4_src_ip(x) (&(get_ipv4_hdr(x)->source_addr))
#define get_ipv4_dest_ip(x) (&(get_ipv4_hdr(x)->dest_addr))
#define get_ipv4_ttl(x) (&(get_ipv4_hdr(x)->ttl))
#define get_ipv4_proto(x) (&(get_ipv4_hdr(x)->proto))
#define get_ipv4_checksum(x) (&(get_ipv4_hdr(x)->checksum))
#define get_ipv4_payload(x) ((char *)(x)->buf + sizeof(ethernet_header) + sizeof(ipv4_header))
#define get_ipv4_payload_len(x) (*get_eth_length(x) - sizeof(ethernet_header) - sizeof(ipv4_header))
#define MAX_IPV4_PAYLOAD_LEN (MAX_PACKET_LEN - sizeof(ethernet_header) - sizeof(ipv4_header))

#define init_ipv4_hdr(__x__, __tot_len__, __src_addr__, __dst_addr__)                            \
    do                                                                                           \
    {                                                                                            \
        ipv4_header *hdr = get_ipv4_hdr(__x__);                                                  \
        hdr->ihl = 5;                                                                            \
        hdr->ver = 4;                                                                            \
        hdr->tos = 0;                                                                            \
        hdr->tot_len = htons(__tot_len__);                                                       \
        hdr->id = htons(4);                                                                      \
        hdr->frag = htons(0);                                                                    \
        hdr->ttl = 64;                                                                           \
        hdr->proto = IPPROTO_ICMP;                                                               \
        hdr->source_addr = __src_addr__;                                                         \
        hdr->dest_addr = __dst_addr__;                                                           \
        hdr->checksum = 0;                                                                       \
        hdr->checksum = htons(checksum(reinterpret_cast<uint16_t *>(hdr), sizeof(ipv4_header))); \
    } while (0)

struct ipv4_packet
{
#define ipv4_hdr get_ipv4_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;
    size_t interface;

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

    inline route_table_entry *get_best_route(std::array<route_table_entry, RTABLE_SIZE> &rtable) const
    {
        return ::get_best_route_array(ipv4_hdr->dest_addr, rtable);
    }

    inline arp_table_entry *get_arp_entry(std::array<arp_table_entry, ARP_TABLE_SIZE> &arp_table) const
    {
        return ::get_arp_entry_array(ipv4_hdr->dest_addr, arp_table);
    }

    inline void send_to_route(route_table_entry *route, arp_table_entry *arp_entry)
    {
        uint8_t src_mac[6] = {0};
        get_interface_mac(route->interface, src_mac);

        init_eth_hdr(this, src_mac, arp_entry->mac, ETHER_TYPE_IP);

        send_to_link(length, buf, route->interface);
    }
};

struct arp_packet
{
    char buf[MAX_PACKET_LEN];
    size_t length;
    size_t interface;
};

#define get_icmp_hdr(x) ((icmp_header *)((char *)(x)->buf + sizeof(ethernet_header) + sizeof(ipv4_header)))
#define get_icmp_type(x) (&(get_icmp_hdr(x)->mtype))
#define get_icmp_code(x) (&(get_icmp_hdr(x)->mcode))
#define get_icmp_checksum(x) (&(get_icmp_hdr(x)->check))
#define get_icmp_payload(x) ((char *)(x)->buf + sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(icmp_header))
#define get_icmp_payload_len(x) (*get_eth_length(x) - sizeof(ethernet_header) - sizeof(ipv4_header) - sizeof(icmp_header))
#define MAX_ICMP_PAYLOAD_LEN (MAX_PACKET_LEN - sizeof(ethernet_header) - sizeof(ipv4_header) - sizeof(icmp_header))

#define init_icmp_hdr_echo_reply(__x__, __id__, __seq__)                                       \
    do                                                                                         \
    {                                                                                          \
        icmp_header *hdr = get_icmp_hdr(__x__);                                                \
        hdr->mtype = ICMP_ECHO_REPLY;                                                          \
        hdr->mcode = 0;                                                                        \
        hdr->un_t.echo_t.id = htons(__id__);                                                   \
        hdr->un_t.echo_t.seq = htons(__seq__);                                                 \
        hdr->check = 0;                                                                        \
        hdr->check = htons(checksum(reinterpret_cast<uint16_t *>(hdr), sizeof(icmp_header)));  \
    } while (0)

#define init_icmp_hdr(__x__, __type__)                                                        \
    do                                                                                        \
    {                                                                                         \
        icmp_header *hdr = get_icmp_hdr(__x__);                                               \
        hdr->mtype = __type__;                                                                \
        hdr->mcode = 0;                                                                       \
        hdr->un_t.gateway_addr = htonl(0);                                                    \
        hdr->check = 0;                                                                       \
        hdr->check = htons(checksum(reinterpret_cast<uint16_t *>(hdr), sizeof(icmp_header))); \
    } while (0)

struct icmp_packet
{
#define icmp_hdr get_icmp_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;
    size_t interface;
};
