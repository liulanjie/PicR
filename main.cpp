#include <stdio.h>
#include "pcap.h"
#include <stdlib.h>
#include <vector>


int main()
{
    char *dev;                      /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    pcap_t *handle;                 /* Session handle */  
    struct bpf_program fp;          /* The compiled filter expression */
    char filter_exp[] = "";  /* The filter expression */
    bpf_u_int32 mask;               /* The netmask of our sniffing device */
    bpf_u_int32 net;                /* The IP of our sniffing device */
    struct pcap_pkthdr header;      /* The header that pcap gives us */
    const u_char *packet;           /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (NULL == dev)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    /* Find the properties for the device */
    if (-1 == pcap_lookupnet(dev, &net, &mask, errbuf)) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (NULL == handle)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }    
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }

    /* Compile and apply the filter */
    if (NULL != filter_exp)
    {
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
    }

    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(handle);

    return 0;
}
