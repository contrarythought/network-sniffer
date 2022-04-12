#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <libnet.h>

#define ETH_SIZE    14
#define IP_SIZE     20 

// TODO - FIX
void pkt_dump(const u_char *packet, u_int len) {
    int i;
    for(i = 0; i <= len; i++) {
        if(i > 0 && (i % 16 == 0 || i >= len)) {
            printf("\t|\t");
            int j;
            for(j = i % 16 == 0 ? (i - 16) : (i - (i % 16)); j < i; j++) {
                if(packet[j] > 32 && packet[j] < 127)
                    printf("%c", packet[j]);
                else printf(".");
            }
            printf("\n");
        } else 
            printf("%02x", packet[i]);
    }
}

static inline void fatal(char *failed_in, char *e_buf) {
    printf("%s: %s\n", failed_in, e_buf);
    exit(1);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_ethernet_header(const u_char *header_start);
void print_ip_header(const u_char *header_start);

int main(int argc, char **argv) {
    char e_buf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev_list, *device;
    int res;
    
    res = pcap_findalldevs(&dev_list, e_buf);
    if(res == -1)
        fatal("pcap_findalldevs", e_buf);

    printf("Devices:\n");
    
    char menu[10][20];
    int i, cnt;
    for(device = dev_list, cnt = 0; device; device = device->next, cnt++) {
        printf("[%d]\t%s:\t%s\n", (cnt + 1), device->name, device->description);
        strcpy(menu[cnt], device->name);
    }
        
    char *dev_to_sniff;
    int c;
    do {
        printf("Device # to sniff:\n");
        scanf("%d", &c);
    } while(c > (cnt + 1) || c < 0);

    dev_to_sniff = menu[c - 1];
    printf("Chose %s\n", dev_to_sniff);

    pcap_t *packet_handle = pcap_open_live(dev_to_sniff, BUFSIZ, 1, 0, e_buf);
    if(!packet_handle)
        fatal("pcap_open_live", e_buf);


    pcap_loop(packet_handle, -1, packet_handler, NULL);

    pcap_close(packet_handle); 
    pcap_freealldevs(dev_list);     
    return 0;
}

// TODO
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // ethernet header comes first
    print_ethernet_header(packet);

    // ip header comes second
    print_ip_header(packet + sizeof(struct ethhdr));

}

void print_ip_header(const u_char *header_start) {
    struct iphdr *ip_header = (struct iphdr *) header_start;
    
    printf("\tSource IP address:\t%s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
    printf("\tDestination IP address:\t%s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));

}

void print_ethernet_header(const u_char *packet) {
    struct ethhdr *ethernet_header = (struct ethhdr *) packet;

    printf("Source MAC address:\t");
    int i;
    for(i = 0; i < ETH_ALEN; i++) 
        printf("%02x", ethernet_header->h_source[i]);
    printf("\n");

    printf("Destination MAC address:\t");
    for(i = 0; i < ETH_ALEN; i++)
        printf("%02x", ethernet_header->h_dest[i]);
    printf("\n");
}
