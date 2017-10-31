/*
 * @Copyrigth: CQUPT 
 * @Author: Zeno 
 * @Date: 2017-10-31 00:58:56 
 * @Last Modified by: Zeno
 * @Last Modified time: 2017-10-31 01:05:40
 * @Description: 图片还原程序
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include<string.h>
#include "pcap.h"

#define MAX_PKT_NUM 65535

typedef struct _PKT_
{
    pcap_pkthdr *pHdr;
    u_char *packet;
} Pkt;

Pkt pkts[MAX_PKT_NUM];
static uint16_t num = 0;

int readCapture(char *file);
int freeCapture();
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Please Enter the file name.\n");
        return 0;
    }
    else if (argc == 2)
    {
        if (-1 == readCapture(argv[1]))
        {
            return 0;
        }
    }
    else
    {
        printf("Too more params.\n");
        return 0;
    }
    
    //TODO Processer

    freeCapture();
    
    return 0;
}

/**
 * @brief 读包函数
 * 
 * @param file 文件名 
 * @return int -1 失败， 0 成功
 */
int readCapture(char *file)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (NULL == (handle = pcap_open_offline(file, errbuf)))
    {
        printf("Error: %s\n", errbuf);
        return -1;
    }
    if (-1 == pcap_loop(handle, -1, callback, NULL))
    {
        printf("Error Capture format.\n");
        return -1;
    }
    pcap_close(handle);
}

/**
 * @brief 释放内存
 * 
 * @return int -1 失败， 0 成功
 */
int freeCapture()
{
    for (uint16_t ix = 0; ix < num; ++ix)
    {
        free(pkts[ix].pHdr);
        free(pkts[ix].packet);
    }
    return 0;
}

/**
 * @brief pcap_loop 回调函数
 * 
 * @param args 参数
 * @param header pcap 包头 
 * @param packet 包负载
 */
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    Pkt *pPkt = &pkts[++num];
    size_t headerLen = sizeof(pcap_pkthdr);
    size_t packetLen = sizeof(u_char) * header->len;

    pPkt->pHdr = (pcap_pkthdr *)malloc(headerLen);
    pPkt->packet = (u_char *)malloc(packetLen);

    memcpy(pPkt->pHdr, header, headerLen);
    memcpy(pPkt->packet, packet, packetLen);
}