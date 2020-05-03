#pragma once

#include <pcap.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <cstdio>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define Ethernet 0x0001
#define IPv4 0x0800
#define Request 0x0001
#define Reply 0x0002
#define ARP 0x0806
#define MAC_LEN 6
#define IP_LEN 4


#pragma pack(push, 1)
struct ETH_hdr{
    uint8_t  ether_dmac[6];/* destination ethernet address */
    uint8_t  ether_smac[6];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};
#pragma pack(pop)

#pragma pack(push ,1)
struct ARP_hdr{
    uint16_t hrd;
    uint16_t pro;
    uint8_t  hln;
    uint8_t  pln;
    uint16_t op;

    uint8_t smac[6];
    uint8_t tmac[6];
    uint32_t sip;
    uint32_t tip;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthArpPacket {
    ETH_hdr eth_;
    ARP_hdr arp_;
};
#pragma pack(pop)



