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
    printf("attacker's IP address : %s\n", attacker_ip);

    /* Close pcap */
    pcap_close(handle);
    return 0;
}
