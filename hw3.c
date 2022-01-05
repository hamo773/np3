#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#define BUFSIZE 10240
#define STRSIZE 1024

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
typedef u_int16_t u_short;
typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;

//pacp文件头结构体
struct pcap_file_header
{
    bpf_u_int32 magic;       /* 0xa1b2c3d4 */
    u_short version_major;   /* magjor Version 2 */
    u_short version_minor;   /* magjor Version 4 */
    bpf_int32 thiszone;      /* gmt to local correction */
    bpf_u_int32 sigfigs;     /* accuracy of timestamps */
    bpf_u_int32 snaplen;     /* max length saved portion of each pkt */
    bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) */
};

//timestamp
struct time_val
{
    int tv_sec;         /* seconds  */
    int tv_usec;        /* and microseconds */
};

//pcap pktheader
struct pcap_pkthdr
{
    struct time_val ts;  /* time stamp */  
    bpf_u_int32 caplen; /* length of portion present */  
    bpf_u_int32 len;    /* length this packet (off wire) */ 
};


typedef struct FramHeader_t
{ 
    u_int8 DstMAC[6]; 
    u_int8 SrcMAC[6]; 
    //u_int64_t DstMAC;
    //u_int64_t SrcMAC;
    u_int16 FrameType;
} FramHeader_t;

//IP
typedef struct IPHeader_t
{
    u_int8 Ver_HLen;       
    u_int8 TOS;          
    u_int16 TotalLen;       
    u_int16 ID; 
    u_int16 Flag_Segment;  
    u_int8 TTL;          
    u_int8 Protocol;       
    u_int16 Checksum;      
    u_int32 SrcIP;
    u_int32 DstIP; 
} IPHeader_t;

//TCPheader
typedef struct TCPHeader_t
{
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int32 SeqNO;
    u_int32 AckNO; 
    u_int8 HeaderLen; 
    u_int8 Flags; 
    u_int16 Window; 
    u_int16 Checksum;
    u_int16 UrgentPointer;
}TCPHeader_t;

//UDP HEADER
typedef struct UDPHeader_s
{
    u_int16_t SrcPort;     
    u_int16_t DstPort;   
    u_int16_t len;      
    u_int16_t checkSum;  
}UDPHeader_t;


int main(int argc, char ** argv)
{
    struct pcap_file_header *file_header = NULL;
    struct pcap_pkthdr *ptk_header = NULL;
    FramHeader_t *eth_header = NULL;
    IPHeader_t *ip_header = NULL;
    TCPHeader_t *tcp_header = NULL;
    UDPHeader_t *udp_header = NULL;
    char output_name[100] = {};
    FILE *fp, *output, *tmp = NULL;
    u_int64_t   pkt_offset, i=0;
    int ip_len, http_len, ip_proto;
    int src_port, dst_port, tcp_flags;
    char buf[BUFSIZE], my_time[STRSIZE];
    char src_ip[STRSIZE], dst_ip[STRSIZE];
    char  host[STRSIZE], uri[BUFSIZE];
    char src_MAC[6],dst_MAC[6];
    //char eth_type[2];
    u_int eth_type; 
    
    int last_time = 0;
    
    //初始化
    file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
    ptk_header  = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    eth_header = (FramHeader_t *)malloc(sizeof(FramHeader_t));
    ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
    udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));
    memset(buf, 0, sizeof(buf));
//
    /*if(argc != 2)
    {
        printf("./parse_cap file_name.cap\n");
        //return 0;
    }*/
    
    if((fp = fopen(argv[1],"r")) == NULL)
    {
        printf("error: can not open pcap file\n");
        exit(0);
    }


    pkt_offset = 24;    //pcap file header 
    while(fseek(fp, pkt_offset, SEEK_SET) == 0) 
    {
        i++;
        //printf("packet_number: %ld\n",i);
        memset(ptk_header, 0, sizeof(struct pcap_pkthdr));
        //pcap_pkt_header 16 byte
        if(fread(ptk_header, 16, 1, fp) != 1) //pcap pkt header
        {
            printf("\nread end of pcap file\n");
            break;
        }
    
        pkt_offset += 16 + ptk_header->caplen;   //下個pkt
        strftime(my_time, sizeof(my_time), "%Y-%m-%d %T", localtime((time_t *)&(ptk_header->ts.tv_sec)));   //timestamp
        double time = ((u_int64_t)ptk_header->ts.tv_sec * 1000000 + ptk_header->ts.tv_usec)/1000000.000;
        printf("packet_number: %ld\n",i);
        printf("time = %.4f \n", time);

        
        

        memset(eth_header , 0, 14);
        
        if(fread(eth_header, sizeof(FramHeader_t), 1, fp) != 1)   // mac       ethernet type
        {
            printf("\nread end of pcap file\n");
            break;
        }
        //printf("packet_number: %ld\n",i);
        //printf("time = %.4f \n", time);
        //inet_ntop(AF_INET, (void *)&(eth_header->SrcMAC), src_MAC, 24);
        //inet_ntop(AF_INET, (void *)&(eth_header->DstMAC), dst_MAC, 24);
        //inet_ntop(AF_INET, eth_header->SrcMAC, src_MAC, 24);
        //inet_ntop(AF_INET, eth_header->DstMAC, dst_MAC, 24);
        //inet_ntop(AF_INET, (void *)&(eth_header->FrameType), eth_type, 8);
        //eth_type = ntohs(eth_header->FrameType);
        printf("Src_MAC = %02x.%02x.%02x.%02x.%02x.%02x\n", eth_header->SrcMAC[0], eth_header->SrcMAC[1], eth_header->SrcMAC[2], eth_header->SrcMAC[3], eth_header->SrcMAC[4]
        , eth_header->SrcMAC[5]);
        printf("Dst_MAC = %02x.%02x.%02x.%02x.%02x.%02x\n", eth_header->DstMAC[0], eth_header->DstMAC[1], eth_header->DstMAC[2], eth_header->DstMAC[3], eth_header->DstMAC[4]
        , eth_header->DstMAC[5]);
        //printf("Ethernet type =  %d\n", eth_header->SrcMAC);
        //printf("Src_MAC =  %s\n", src_MAC);
        //printf("Dst_MAC =  %s\n", dst_MAC);
        eth_type = ((eth_header->FrameType) << 8) | ((eth_header->FrameType) >> (16 - 8));
        //printf("Ethernet type =  %s\n", eth_type);
        printf("Ethernet type =  %04x\n", eth_type);

        //printf("Ethernet type =  %x\n", eth_header->FrameType);
        if(eth_header->FrameType != 0x0008)
        {
            continue;
        }
        
        memset(ip_header, 0, sizeof(IPHeader_t));
        if(fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1)    //read ip    info
        {
            printf("%ld: can not read ip_header\n", i);
            break;
        }
        inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
        inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);
        ip_proto = ip_header->Protocol;
        ip_len = ip_header->TotalLen; 
       printf("src_ip=%s\n", src_ip);
       printf("dst_ip=%s\n", dst_ip);
        
        memset(buf, 0 ,BUFSIZE);
        
        if(ip_proto == 0x06)    //TCP 
        {
            if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1)
            {
                printf("%ld: can not read tcp_header\n", i);
                break;
            }
            src_port = ntohs(tcp_header->SrcPort);
            dst_port = ntohs(tcp_header->DstPort);
            tcp_flags = tcp_header->Flags;
            //printf("%d:  src=%x\n", i, tcp_flags);
            printf( "tcp src_port=%d  dst_post=%d  \r\n", src_port, dst_port);

        }
        else if(ip_proto == 0x11)   //UDP
        {
            if(fread(udp_header, 8, 1, fp) != 1)
            {
                printf("%ld: can not read udp_header\n", i);
            }
            src_port = ntohs(udp_header->SrcPort);
            dst_port = ntohs(udp_header->DstPort);
            printf("udp src port = %d  dst port = %d\n", src_port, dst_port);
        }
        printf("-----------------------------------------------------------------------\n");
        

    } // end while
    fclose(fp);
    //fclose(output);
    return 0;
}