#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#define ETH_SIZE    14
#define IP_SIZE     20 

/*
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
*/

void pkt_dump(const u_char *packet, u_int len) {
    int i;
    for(i = 0; i < len; i++) {
        printf("%02x", packet[i]);
        if((i % 16) == 15 || i == len - 1) {
            printf("\t|\t");
            int j;
            for(j = (i % 16) == 15 ? (i - 15) : i - (i % 15); j <= i; j++) {
                if(packet[j] > 32 && packet[j] < 127)
                    printf("%c", packet[j]);
                else 
                    printf(".");
            }
            printf("\n");
        }
    }
}

static inline void fatal(char *failed_in, char *e_buf) {
    printf("%s: %s\n", failed_in, e_buf);
    exit(1);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_ethernet_header(const u_char *header_start);
void print_ip_header(const u_char *header_start);
__u_int print_tcp_header(const u_char *header_start);
void print_data(const u_char *header_start, __u_int data_len);

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

    int num_packets;
    printf("How many packets to capture?\n");
    scanf("%d", &num_packets);

    pcap_t *packet_handle = pcap_open_live(dev_to_sniff, BUFSIZ, 1, 1000, e_buf);
    if(!packet_handle)
        fatal("pcap_open_live", e_buf);


    pcap_loop(packet_handle, num_packets, packet_handler, NULL);

    pcap_close(packet_handle); 
    pcap_freealldevs(dev_list);     
    return 0;
}

// TODO
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    __u_int total_packet_size = 0;
    // 2nd layer
    print_ethernet_header(packet);

    // 3rd layer
    print_ip_header(packet + sizeof(struct ethhdr));

    // 4th layer
    __u_int tcp_len = print_tcp_header(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    total_packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + tcp_len;
    __u_int data_len = header->len - total_packet_size;

    // data layer
    if(!data_len)
        printf("No packet data available\n");
    else 
        print_data(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + tcp_len, data_len);
}

// TODO
void print_data(const u_char *header_start, __u_int data_len) {
    printf("Captured %d bytes of data:\n", data_len);
    pkt_dump(header_start, data_len);
    printf("\n");
}

// TODO
__u_int print_tcp_header(const u_char *header_start) {
    struct tcphdr *tcp_header = (struct tcphdr *) header_start;
    printf("\t\tSource port:\t%02x", ntohs(tcp_header->source));
    printf("\t\tDestination port:\t%02x\n", ntohs(tcp_header->dest));
    printf("\t\tSeq Number:\t%u\n", ntohl(tcp_header->th_seq));
    printf("\t\tAck Number:\t%u\n", ntohl(tcp_header->th_ack));

    printf("\t\t\tFlags:\t");
    if(tcp_header->th_flags & TH_FIN)
        printf("FIN ");
    if(tcp_header->th_flags & TH_ACK)
        printf("ACK ");
    if(tcp_header->th_flags & TH_SYN)
        printf("SYN ");
    if(tcp_header->th_flags & TH_RST)
        printf("RST ");
    if(tcp_header->th_flags & TH_PUSH)
        printf("PUSH ");
    if(tcp_header->th_flags & TH_URG)
        printf("URG ");
    printf("\n");    

    // offset is the # of 32 bit words in the header. Each 32 bit word = 4 bytes, hence multiply the offset by 4 to find TCP header size in bytes
    return tcp_header->th_off * 4;
}

void print_ip_header(const u_char *header_start) {
    struct iphdr *ip_header = (struct iphdr *) header_start;
    
    printf("\tSource IP address:\t%s", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
    printf("\tDestination IP address:\t%s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));

}

void print_ethernet_header(const u_char *packet) {
    struct ethhdr *ethernet_header = (struct ethhdr *) packet;

    printf("Source MAC address:\t");
    int i;
    for(i = 0; i < ETH_ALEN; i++) 
        printf("%02x", ethernet_header->h_source[i]);
    printf("\t");

    printf("Destination MAC address:\t");
    for(i = 0; i < ETH_ALEN; i++)
        printf("%02x", ethernet_header->h_dest[i]);
    printf("\n");
}
