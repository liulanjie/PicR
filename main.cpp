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
#include <string.h>
#include "pcap.h"

#define MAX_PKT_NUM 65535
#define MAX_HASH_NUM 4998
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
}Pkt;

//流节点
typedef struct _HashNode_
{
    Pkt *pkt;
    struct _HashNode_ *nextNode;
}HashNode;

//Hash 槽
typedef struct _HashSlot_
{
    bool isUsed;
    uint16_t nodeNum;
    HashNode *firstNode;
}HashSlot;

//Eth 报头结构体
typedef struct ether_header  
{  
    uint8_t DstAddress[ETHER_ADDR_LEN];  
    uint8_t SrcAddress[ETHER_ADDR_LEN];  
    uint16_t Type;  
}ETH_HEADER;

//IP 报头结构体
typedef struct IPHeader {
    uint8_t HeaderLen : 4;
    uint8_t Version : 4;
    uint8_t DS ;
    uint16_t TotalLength;
    uint16_t ID;
    uint8_t FragmentOffset0 : 5;
    uint8_t MF : 1;
    uint8_t DF : 1;
    uint8_t Reserved : 1;
    uint8_t FragmentOffset1;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t IpChkSum;
    uint32_t SrcIP;
    uint32_t DstIP;
}IP_HEADER;

//TCP 报头结构体
typedef struct TCPHEADER {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint32_t SeqNo;
    uint32_t AckNo;
    uint8_t Reserved0 : 4;
    uint8_t HeaderLen : 4;
    uint8_t FIN : 1;
    uint8_t SYN : 1;
    uint8_t RST : 1;
    uint8_t PSH : 1;
    uint8_t ACK : 1;
    uint8_t URG : 1;
    uint8_t Reserved1 : 2;
    uint16_t WindowSize;
    uint16_t TcpChkSum;
    uint16_t UrgentPointer;
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
HashSlot *HashTable[MAX_HASH_NUM];
static uint16_t pktNum = 0;
static uint16_t tcp_num = 0;

int readCapture(char *file);
int freeCapture();
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *pStr);

int initHashTable();
int initHashSlot(HashSlot *pSlot);
int initHashNode(HashNode *pNode);
int pushNode(HashSlot *pSlot, HashNode *pNode);
int popNode();

void processer();
int ethParse(Pkt &pkt);
int ipParse(Pkt &pkt);
int tcpParse(Pkt &pkt);
int udpParse(Pkt &pkt);

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

    initHashTable();
    
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
    for (uint32_t ix = 0; ix < pktNum; ++ix)
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

    pkts[pktNum++] = pPkt;
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
    for (uint32_t ix = 0; ix < pktNum; ++ix)
    {
        Pkt &pkt = *pkts[ix];

        ethParse(pkt);
    }

    printf("TCP NUM: %d\n", tcp_num);

    //TODO 建流
    for (uint32_t ix = 0; ix < pktNum; ++ix)
    {
        Pkt &pkt = *pkts[ix];

    }

    //统计建流条数
    int StreamNum = 0;
    for(uint16_t ix = 0; ix != MAX_HASH_NUM; ++ix)
    {
        if (HashTable[ix]->isUsed == true)
            ++StreamNum;
    }
    printf("STREAM NUM:%d\n", StreamNum);
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

    if (ETHERTYPE_IP == ethHdr->Type)
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
    pkt.uOffset += (ipHdr->HeaderLen << 2);
    pkt.uDst = ipHdr->DstIP;
    pkt.uSrc = ipHdr->SrcIP;

    if (PROTOCOL_TCP == ipHdr->Protocol)
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
    
    pkt.uDstPort = tcpHdr->DstPort;
    pkt.uSrcPort = tcpHdr->SrcPort;
    pkt.uOffset = (tcpHdr->HeaderLen << 2);

    pkt.uType = 1;

    //TCP 建流
    uint32_t uHashValue = pkt.uDstPort ^ pkt.uSrcPort ^ pkt.uSrc ^ pkt.uDst;
    HashSlot &pSlot = *HashTable[uHashValue % MAX_HASH_NUM];

    HashNode *pNode = (HashNode *)malloc(sizeof(HashNode));
    pNode->pkt = &pkt;
    pNode->nextNode = NULL;

    if ((false == pSlot.isUsed) && (NULL == pSlot.firstNode))
    {
        //第一条报文，先压入
        pushNode(&pSlot, pNode);

        ++pSlot.nodeNum;
    }
    else if ((false == pSlot.isUsed) && (NULL != pSlot.firstNode))
    {
        //第二条报文，开始建流
        pSlot.isUsed = true;
        pushNode(&pSlot, pNode);
        
        ++pSlot.nodeNum;
    }
    else if (true == pSlot.isUsed)
    {
        //后续报文挂到流链表上
        pushNode(&pSlot, pNode);

        ++pSlot.nodeNum;
    }
    else
    {
        //其余情况异常
        free(pNode);
    }

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

/**
 * @brief 哈希表初始化
 * 
 * @return int 
 */
int initHashTable()
{
    for(uint16_t ix = 0; ix != MAX_HASH_NUM; ++ix)
    {
        HashTable[ix] = (HashSlot *)malloc(sizeof(HashSlot));

        initHashSlot(HashTable[ix]);
    }

    return RET::SUCCESS;
}

/**
 * @brief 哈希槽初始化
 * 
 * @param node 
 * @return int 
 */
int initHashSlot(HashSlot *pSlot)
{
    pSlot->isUsed = false;
    pSlot->firstNode = NULL;
    pSlot->nodeNum = 0;

    return RET::SUCCESS;
}

/**
 * @brief 初始化哈希节点
 * 
 * @param node 
 * @return int 
 */
int initHashNode(HashNode *pNode)
{
    pNode->pkt = NULL;
    pNode->nextNode = NULL;

    return RET::SUCCESS;
}

int pushNode(HashSlot *pSlot, HashNode *pNode)
{
    if (NULL == pSlot->firstNode)
    {
        pSlot->firstNode = pNode;
    }
    else
    {
        HashNode *qNode = pSlot->firstNode;
        while(NULL != qNode->nextNode)
        {
            qNode = qNode->nextNode;
        }
        qNode->nextNode = pNode;
    }

    return RET::SUCCESS;
}
int popNode()
{
    return RET::SUCCESS;
}