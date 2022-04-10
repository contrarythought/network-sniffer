#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

// TODO - FIX
void dump(const u_char *packet, u_int len) {

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


    

    pcap_close(packet_handle);      
    return 0;
}
