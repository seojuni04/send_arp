#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>

#define HAL 6
#define PAL 4

void get_mac_addr(struct ethhdr *ethh, char *interface){
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;
    char *intface = interface;

    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, intface, IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0){
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    for(int i=0; i<6; i++)
    {
        ethh->h_source[i] = req.ifr_hwaddr.sa_data[i];
        ethh->h_dest[i] = 255;
    }

    close(sock);
}

void make_eth_header(char *interface, char *sender_ip, struct ethhdr *ethh){
    ethh->h_proto = htons(ETHERTYPE_ARP);
    get_mac_addr(ethh, interface);
    printf("dest mac : %s\n", ether_ntoa((struct ether_addr *)ethh->h_dest));
    printf("source mac : %s\n", ether_ntoa((struct ether_addr *)ethh->h_source));
}

void make_arp_header(char *sender_ip, char *target_ip, struct ethhdr *ethh, struct ether_arp *arph){
    arph->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arph->ea_hdr.ar_pro = htons(ETH_P_IP);
    arph->ea_hdr.ar_hln = HAL;
    arph->ea_hdr.ar_pln = PAL;
    arph->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    sscanf(sender_ip, "%d.%d.%d.%d", arph->arp_spa, arph->arp_spa+1, arph->arp_spa+2, arph->arp_spa+3);
    sscanf(target_ip, "%d.%d.%d.%d", arph->arp_tpa, arph->arp_tpa+1, arph->arp_tpa+2, arph->arp_tpa+3);
    for(int i=0; i<6; i++){
        arph->arp_sha[i] = ethh->h_source[i];
        arph->arp_tha[i] = ethh->h_dest[i];
    }
}

int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *interface;         /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
    bpf_u_int32 mask;      /* Our netmask */
    bpf_u_int32 net;      /* Our IP */
    const u_char *packet;      /* The actual packet */
    struct ether_header *ethh;
    struct ether_arp *arph;
    int packet_length = 0;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <interface> <sender ip> <target ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Define the device */
    interface = argv[1];

    /* Find the properties for the device */
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return(2);
    }

    /* Make Ethernet Header */
    make_eth_header(interface, argv[2], &ethh);

    /* Make ARP Header */
    make_arp_header(argv[2], argv[3], &ethh, &arph);

    return 0;
}
