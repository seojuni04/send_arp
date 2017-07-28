#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;         /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
    bpf_u_int32 mask;      /* Our netmask */
    bpf_u_int32 net;      /* Our IP */
    const u_char *packet;      /* The actual packet */
    struct ether_header *ethh;
    int packet_length = 0;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <interface> <sender ip> <target ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Define the device */
    dev = argv[1];

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    /* Set Packet */
    /* Ethernet Header - Destination */
    for(int i=0; i<6; i++)
    {
        ethh->ether_dhost[i] = 0xff;
    }

    /* Ethernet Header - Source */
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;

    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, argv[1], IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0){
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    for(int i=0; i<6; i++)
    {
        ethh->ether_shost[i] = req.ifr_hwaddr.sa_data[i];
    }

    close(sock);

    /* Ethernet Header - Type */
    ethh->ether_type = ETHERTYPE_ARP;

    /* Test Print Ethernet Header */
    for(int i=0; i<6; i++)
    {
        printf("%.2x", ethh->ether_dhost[i]);
        if(i < 5)
            printf(":");
    }
    printf("\n");

    for(int i=0; i<6; i++)
    {
        printf("%.2x", ethh->ether_shost[i]);
        if(i < 5)
            printf(":");
    }
    printf("\n");

    return 0;
}
