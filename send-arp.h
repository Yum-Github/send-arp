#pragma once

#include "ip.h"
#include "mac.h"
#include "arphdr.h"
#include "ethhdr.h"
#include <pcap.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)
