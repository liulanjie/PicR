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
#define ETHER_ADDR_LEN 6
#define ETH_HDR_LEN 14

#define ETHERTYPE_IP 8
#define PROTOCOL_TCP 6
//存放读出报文结构体
typedef struct _PKT_
{
    pcap_pkthdr *pHdr;
    u_char *pStr;
    uint16_t uOffset;
    uint16_t uType;

    //四元组
    uint32_t uSrc;
    uint32_t uDst;
    uint16_t uSrcPort;
    uint16_t uDstPort;
} Pkt;

//Eth 报头结构体
typedef struct ether_header  
{  
    uint8_t ether_dhost[ETHER_ADDR_LEN];  
    uint8_t ether_shost[ETHER_ADDR_LEN];  
    uint16_t ether_type;  
}ETH_HEADER;

//IP 报头结构体
typedef struct ip  
{  
    uint8_t ip_v:4;
    uint8_t ip_hl:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
}IP_HEADER;

//TCP 报头结构体
typedef struct tcphdr   
{  
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_off:4;
    uint8_t th_x2:4;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
}TCP_HEADER;

//UDP 报头结构体
typedef struct udphdr   
{  
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
}UDP_HEADER; 

Pkt *pkts[MAX_PKT_NUM];
static uint16_t num = 0;
static uint16_t tcp_num;

int readCapture(char *file);
int freeCapture();
void processer();
int ethParse(Pkt &pkt);
int ipParse(Pkt &pkt);
int tcpParse(Pkt &pkt);
int udpParse(Pkt &pkt);
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *pStr);

//函数返回值
namespace RET
{
    int FAIL = -1;
    int SUCCESS = 0;
}

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
    
    processer();

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
        return RET::FAIL;
    }
    if (-1 == pcap_loop(handle, -1, callback, NULL))
    {
        printf("Error Capture format.\n");
        return RET::FAIL;
    }
    pcap_close(handle);

    return RET::SUCCESS;
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
        free(pkts[ix]->pHdr);
        free(pkts[ix]->pStr);
        free(pkts[ix]);
    }
    return RET::SUCCESS;
}

/**
 * @brief pcap_loop 回调函数
 * 
 * @param args 参数
 * @param header pcap 包头 
 * @param pStr 包负载
 */
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *pStr)
{
    Pkt *pPkt = (Pkt *)malloc(sizeof(Pkt));
    size_t headerLen = sizeof(pcap_pkthdr);
    size_t pStrLen = sizeof(u_char) * header->len;

    pPkt->pHdr = (pcap_pkthdr *)malloc(headerLen);
    pPkt->pStr = (u_char *)malloc(pStrLen);
    pPkt->uOffset = 0;

    memcpy(pPkt->pHdr, header, headerLen);
    memcpy(pPkt->pStr, pStr, pStrLen);

    pkts[num++] = pPkt;
}

/**
 * @brief 控制台输出报文（调试用）
 * 
 */
void showPkt(Pkt &pkt)
{
    //获取包长
    uint16_t uLen = pkt.pHdr->caplen;
    printf("--------------------- PKT ---------------------\n");
    for (uint16_t ixLen = 0; ixLen != uLen; ++ixLen)
    {
        if ((ixLen != 0) && ((ixLen % 16) == 0))
            printf("\n");
        printf("%02X ", pkt.pStr[ixLen]);
    }
    printf("\n");
}

/**
 * @brief 主处理函数
 * 
 */
void processer()
{
    //协议解析
    for (uint16_t ix = 0; ix < num; ++ix)
    {
        Pkt &pkt = *pkts[ix];

        ethParse(pkt);
    }

    printf("TCP NUM: %d\n", tcp_num);

    //TODO 建流
    for (uint16_t ix = 0; ix < num; ++ix)
    {
        Pkt &pkt = *pkts[ix];
        //For Test
        if(pkt.uType == 1)
        {
            printf("---------------------\n");
            printf("SrcIP:%d\n", pkt.uSrc);
            printf("DstIP:%d\n", pkt.uDst);
            printf("SrcPort:%d\n", pkt.uSrcPort);
            printf("DstPort:%d\n", pkt.uDstPort);
        }

    }
}

/**
 * @brief 以太层解析
 * 
 * @param pkt 处理报文结构体
 * @return int -1 失败， 0 成功
 */
int ethParse(Pkt &pkt)
{
    //异常保护
    if ((NULL == pkt.pStr) || (pkt.uOffset > pkt.pHdr->caplen))
        return RET::FAIL;
    
    ETH_HEADER *ethHdr = (ETH_HEADER *)pkt.pStr;
    pkt.uOffset += ETH_HDR_LEN;

    if (ETHERTYPE_IP == ethHdr->ether_type)
        ipParse(pkt);
    else
        return RET::FAIL;

    return RET::SUCCESS;
}

/**
 * @brief IP 解析
 * 
 * @param pkt 处理报文结构体
 * @return int -1 失败， 0 成功
 */
int ipParse(Pkt &pkt)
{
    IP_HEADER *ipHdr = (IP_HEADER *)(pkt.pStr + pkt.uOffset);
    pkt.uOffset += ipHdr->ip_hl;
    pkt.uDst = ipHdr->ip_dst;
    pkt.uSrc = ipHdr->ip_src;

    if (PROTOCOL_TCP == ipHdr->ip_p)
        tcpParse(pkt);
    else
        return RET::FAIL;
    
    return RET::SUCCESS;
}

/**
 * @brief tcp 解析
 * 
 * @param pkt 处理报文结构体
 * @return int -1 失败， 0 成功
 */
int tcpParse(Pkt &pkt)
{
    ++tcp_num;

    TCP_HEADER *tcpHdr = (TCP_HEADER *)(pkt.pStr + pkt.uOffset);
    
    pkt.uDstPort = tcpHdr->th_dport;
    pkt.uSrcPort = tcpHdr->th_sport;

    pkt.uType = 1;

    return RET::SUCCESS;
}

/**
 * @brief udp 解析
 * 
 * @param pkt 处理报文结构体
 * @return int -1 失败， 0 成功
 */
int udpParse(Pkt &pkt)
{
    return RET::SUCCESS;
}