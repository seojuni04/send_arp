#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

struct	ETHER_ARP {
    struct	arphdr ea_hdr;		/* fixed-size header */
    u_int8_t arp_sha[ETH_ALEN];	/* sender hardware address */
    u_int8_t *arp_spa;		/* sender protocol address */
    u_int8_t arp_tha[ETH_ALEN];	/* target hardware address */
    u_int8_t *arp_tpa;		/* target protocol address */
};

int main(int argc, char *argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *sender_ip, *target_ip;
    struct ifreq ifreq_ip, ifreq_mac;
    unsigned char *attacker_mac;
    unsigned char *attacker_ip;
    pcap_t *handle;
    char packet[60];
    struct ether_header *ethh;
    struct ETHER_ARP *arph;

    if(argc<4)
    {
        printf("Usage: %s <interface> <sender ip> <target ip>\n", argv[0]);
        exit(1);
    }

    dev = argv[1];
    sender_ip = argv[2];
    target_ip = argv[3];

    /* Open pcap */
    handle = pcap_open_live(dev, BUFSIZ,1, 1000, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
        return 2;
    }

    /* Get My(Attacker) MAC address */
    int s = socket(AF_INET, SOCK_DGRAM,0);
    if(s<0){
        perror("socket fail");
    }
    strncpy(ifreq_mac.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifreq_mac)<0){
        perror("ioctl fail");
    }
    attacker_mac = ifreq_mac.ifr_hwaddr.sa_data;
    printf("My(Attacker) MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n", attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);

    /* Get My(Attacker) IP address */
    struct sockaddr_in *sin;
    strncpy(ifreq_ip.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifreq_ip)<0) perror("ioctl fail");
    sin = (struct sockaddr_in*)&ifreq_ip.ifr_addr;
    attacker_ip=inet_ntoa(sin->sin_addr);
    printf("My(Attacker) IP address : %s\n", attacker_ip);

    /* Send ARP Request Packet */
    printf("===================== Send ARP Request for Broadcast =====================\n");

    /* Make Ethernet Packet */
    ethh = (struct ether_header *)packet;
    ethh->ether_type = ntohs(ETHERTYPE_ARP);
    printf("Destination :\n");
    for(int i=0; i<5; i++)
    {
        ethh->ether_dhost[i] = '\xff';
        printf("%02x:", ethh->ether_dhost[i]);
    }
    ethh->ether_dhost[5] = '\xff';
    printf("%02x\n", ethh->ether_dhost[5]);

    printf("Source :\n");
    for(int i=0; i<5; i++)
    {
        ethh->ether_shost[i] = attacker_mac[i];
        printf("%02x:", ethh->ether_shost[i]);
    }
    ethh->ether_shost[5] = attacker_mac[5];
    printf("%02x\n", ethh->ether_shost[5]);

    printf("Type : ");
    printf("0x0%x\n", htons(ethh->ether_type));

    arph = (struct ETHER_ARP *)(packet+14);
    arph->ea_hdr.ar_hrd = ntohs(ARPHRD_ETHER);
    arph->ea_hdr.ar_pro = ntohs(ETHERTYPE_IP);
    arph->ea_hdr.ar_hln = 6;
    arph->ea_hdr.ar_pln = 4;
    arph->ea_hdr.ar_op = ntohs(ARPOP_REQUEST);
    memcpy(arph->arp_sha, attacker_mac, 6);
    arph->arp_spa = attacker_ip;
    memcpy(arph->arp_tha, "\x00\x00\x00\x00\x00\x00", 6);
    arph->arp_tpa = sender_ip;

    printf("Hardware type : %d\n", arph->ea_hdr.ar_hrd);
    printf("Protocol type : 0x0%x\n", htons(arph->ea_hdr.ar_pro));
    printf("Hardware size : %d\n", arph->ea_hdr.ar_hln);
    printf("Protocol size : %d\n", arph->ea_hdr.ar_pln);
    printf("Opcode : %d\n", arph->ea_hdr.ar_op);
    printf("Sender MAC address : ");
    for(int i=0; i<5; i++){
        printf("%02x:", arph->arp_sha[i]);
    }
    printf("%02x\n", arph->arp_sha[5]);
    printf("Sender IP address : %s\n", arph->arp_spa);
    printf("Target MAC address : ");
    for(int i=0; i<5; i++){
        printf("%02x:", arph->arp_tha[i]);
    }
    printf("%02x\n", arph->arp_tha[5]);
    printf("Target IP address : %s\n", arph->arp_tpa);

    /* Send ARP Packet */
    pcap_sendpacket(handle, packet, 42);
    printf("Success Send ARP Request!\n");

    /* Close pcap */
    pcap_close(handle);
    return 0;
}
