#pragma once

#ifndef __ROUTER_HPP__

#define __ROUTER_HPP__

#include "protocols.h"
#include "lib.h"
#include <arpa/inet.h>
#include <cstring>

#include <array>
#include <unordered_map>
#include <queue>
#include <algorithm>

#define HARDWARE_TYPE_ETHERNET 0x0001
#define PROTOCOL_TYPE_IP 0x0800
#define HARDWARE_SIZE_ETHERNET 6
#define PROTOCOL_SIZE_IP 4
#define BROADCAST_MAC 0xFFFFFFFFFFFF

#define ARP_REQUEST 1
#define ARP_REPLY 2

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

struct mac_address
{
    uint8_t mac[6];
};

char *my_inet_ntoa(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    char *tmp = (char *)malloc(100);
    memcpy(tmp, inet_ntoa(addr), 100);
    return tmp;
}

char *my_mac_ntoa(uint8_t *mac)
{
    static char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    char *tmp = (char *)malloc(100);
    memcpy(tmp, mac_str, 18);
    return tmp;
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

#define init_eth_hdr_broadcast(__x__, __src_addr__, __type__) \
    do                                                        \
    {                                                         \
        ethernet_header *hdr = get_eth_hdr(__x__);            \
        memcpy(hdr->ethr_shost, __src_addr__, 6);             \
        memset(hdr->ethr_dhost, 0xFF, 6);                     \
        hdr->ethr_type = htons(__type__);                     \
    } while (0)

struct ethernet_frame
{
#define eth_hdr get_eth_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;
    size_t interface;

    inline void send_to_mac(uint16_t type, uint8_t *src_mac, uint8_t *dest_mac, size_t interf)
    {
        init_eth_hdr(this, src_mac, dest_mac, type);
        interface = interf;

        printf("Bouta send EHT frame\n\tsrc_mac = %s dst_mac = %s\n",
               my_mac_ntoa(get_eth_src_mac(this)), my_mac_ntoa(get_eth_dest_mac(this)));

        send_to_link(length, buf, interface);
    }

    inline void send_to_broadcast(uint16_t type, uint8_t *src_mac, size_t interf)
    {
        init_eth_hdr_broadcast(this, src_mac, type);
        interface = interf;

        printf("Bouta send EHT frame\n\tsrc_mac = %s dst_mac = %s\n",
               my_mac_ntoa(get_eth_src_mac(this)), my_mac_ntoa(get_eth_dest_mac(this)));

        send_to_link(length, buf, interface);
    }
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

    inline void send_to_route(route_table_entry *route, uint8_t *dest_mac)
    {
        uint8_t src_mac[6] = {0};
        get_interface_mac(route->interface, src_mac);

        reinterpret_cast<ethernet_frame *>(this)->send_to_mac(ETHER_TYPE_IP, src_mac, dest_mac, route->interface);
    }
};

#define get_icmp_hdr(x) ((icmp_header *)((char *)(x)->buf + sizeof(ethernet_header) + sizeof(ipv4_header)))
#define get_icmp_type(x) (&(get_icmp_hdr(x)->mtype))
#define get_icmp_code(x) (&(get_icmp_hdr(x)->mcode))
#define get_icmp_checksum(x) (&(get_icmp_hdr(x)->check))
#define get_icmp_payload(x) ((char *)(x)->buf + sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(icmp_header))
#define get_icmp_payload_len(x) (*get_eth_length(x) - sizeof(ethernet_header) - sizeof(ipv4_header) - sizeof(icmp_header))
#define MAX_ICMP_PAYLOAD_LEN (MAX_PACKET_LEN - sizeof(ethernet_header) - sizeof(ipv4_header) - sizeof(icmp_header))

#define init_icmp_hdr(__x__, __type__, __id__, __seq__)                                       \
    do                                                                                        \
    {                                                                                         \
        icmp_header *hdr = get_icmp_hdr(__x__);                                               \
        hdr->mtype = __type__;                                                                \
        hdr->mcode = 0;                                                                       \
        hdr->un_t.echo_t.id = __id__;                                                         \
        hdr->un_t.echo_t.seq = __seq__;                                                       \
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

#define get_arp_hdr(x) ((arp_header *)((char *)(x)->buf + sizeof(ethernet_header)))

#define init_arp_hdr(__x__, __opcode__, __src_mac__, __src_ip__, __target_ip__) \
    do                                                                          \
    {                                                                           \
        arp_header *hdr = get_arp_hdr(__x__);                                   \
        hdr->hw_type = htons(HARDWARE_TYPE_ETHERNET);                           \
        hdr->proto_type = htons(PROTOCOL_TYPE_IP);                              \
        hdr->hw_len = HARDWARE_SIZE_ETHERNET;                                   \
        hdr->proto_len = PROTOCOL_SIZE_IP;                                      \
        hdr->opcode = htons(__opcode__);                                        \
        hdr->sprotoa = __src_ip__;                                              \
        memcpy(hdr->shwa, __src_mac__, HARDWARE_SIZE_ETHERNET);                 \
        memset(hdr->thwa, 0, hdr->hw_type);                                     \
        hdr->tprotoa = __target_ip__;                                           \
    } while (0)

#define get_arp_hw_type(x) (&(get_arp_hdr(x)->hw_type))
#define get_arp_proto_type(x) (&(get_arp_hdr(x)->proto_type))
#define get_arp_hw_len(x) (&(get_arp_hdr(x)->hw_len))
#define get_arp_proto_len(x) (&(get_arp_hdr(x)->proto_len))
#define get_arp_opcode(x) (&(get_arp_hdr(x)->opcode))
#define get_arp_src_mac(x) (get_arp_hdr(x)->shwa)
#define get_arp_src_ip(x) (&(get_arp_hdr(x)->sprotoa))
#define get_arp_dest_mac(x) (get_arp_hdr(x)->thwa)
#define get_arp_dest_ip(x) (&(get_arp_hdr(x)->tprotoa))

struct arp_packet
{
#define arp_hdr get_arp_hdr(this)
    char buf[MAX_PACKET_LEN];
    size_t length;
    size_t interface;
};

#endif
