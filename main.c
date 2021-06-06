#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h> //ethernet header
#include <netinet/ip.h>   //ip header
#include <netinet/tcp.h>  //tcp header
#include <arpa/inet.h>    //inet_ntoa()

#define INITIATE_REQUESTPDU 0xa826

struct ether_header *ethh;
struct ip *iph;
struct tcphdr *tcph;
struct udphdr *udph;

struct TPKT
{
    uint8_t version;
    uint8_t reserved;
    uint16_t len;
}*tpkth;

#pragma pack(push,1)
struct ISO8073
{
    uint8_t len;
    uint8_t pdutype;
    uint8_t tpdunum;
}*iso8073h;
#pragma pack(pop)

uint8_t debuging_count = 1;

void ethernet_dump(const u_char* packet);
void ip_dump(const u_char* packet);
void tcp_dump(const u_char* packet);
void tpkt_dump(const u_char *packet);
void iso8073_dump(const u_char* packet);
void mms_dump(const u_char* packet);
void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet);
void usage()
{
  printf("sysntax : mms_parser <interface>\n");
  printf("sample@linux~$ ./mms_parser ens33\n");
}

void printByHexData(uint8_t *printArr, int len)
{
    for(int i = 0; i < len; i++)
    {
        if(i % 16 == 0)
            printf("\n");
        printf("%02x ", printArr[i]);
    }
}


int main(int argc, char* argv[])
{
  // usage error check!
  if(argc != 2)
  {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];  // errbuf
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  // packet descripter

  dev = pcap_lookupdev(errbuf);

  // device error check!
  if(handle == NULL)
  {
    fprintf(stderr,"Couldn't open device : %s : %s\n",dev,errbuf);
    return -1;
  }
  printf("dev : %s\n",dev);

  pcap_loop(handle,0,callback,NULL);
  return 0;
}

void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet)
{
  // Ethernet header
  ethernet_dump(packet);

  // IP header
  packet += sizeof(struct ether_header); //sizeof(struct eth);
  ip_dump(packet);

  // TCP header
  packet += 20; //(iph -> ip_hl * 4);		// packet length (total length -> 5 * 4 = 20)
  tcp_dump(packet);

  // Packet Data
  printf("\nDEBUG : %d\n", debuging_count++);
  packet += tcph -> th_off * 4;
  tpkt_dump(packet);

  packet += sizeof(struct TPKT);
  iso8073_dump(packet);

  packet += sizeof(struct ISO8073);
  mms_dump(packet);
}

void ethernet_dump(const u_char* packet)
{
    ethh = (struct ether_header *)packet;
    printf("\n[Layer 2] DataLink\n");
    printf("[*]Dst Mac address[*] : ");

    for(int i = 0; i < 6; i++)
    {
       printf("%02x", packet[i]);
       if (i != 5)
        printf(":");
    }
    printf("\n");
    printf("[*]Src Mac address[*] : ");
    for(int i = 6; i < 12; i++)
    {
       printf("%02x", packet[i]);
       if (i != 11)
        printf(":");
    }
    printf("\n");
}

void ip_dump(const u_char* packet)
{
    iph = (struct ip *)packet;
    printf("\n[Layer 3] Network\n");
    printf("[*]Src IP address : %s\n",inet_ntoa(iph -> ip_src));	//inet_ntoa() -> number to string
    printf("[*]Dst IP address : %s\n",inet_ntoa(iph -> ip_dst));
}

void tcp_dump(const u_char* packet)
{
    tcph = (struct tcphdr *)packet;
    printf("\n[Layer 4] Transport\n");
    printf("[*]Src Port : %d\n" , ntohs(tcph -> th_sport));	//ntohs() -> network to host type : short
    printf("[*]Dst Port : %d\n" , ntohs(tcph -> th_dport));	// short : 2 byte
}

void tpkt_dump(const u_char* packet)
{
    tpkth = (struct TPKT *)packet;
    printf("\n[*]TPKT[*]\n");
    printf("[*]Version : %d\n", tpkth->version);
    printf("[*]Reserved : %d\n", tpkth->reserved);
    printf("[*]Length : %d\n", ntohs(tpkth->len));
}

void iso8073_dump(const u_char* packet)
{
    iso8073h = (struct ISO8073 *)packet;
    printf("\n[*]ISO8073/X.224 COTP[*]\n");
    printf("[*]Length : %dx\n", iso8073h->len);
    printf("[*]PDU Type : %02x\n", iso8073h->pdutype);
    printf("[*]Length : %02x\n", iso8073h->tpdunum);
}

void mms_dump(const u_char* packet)
{
    uint16_t mms_type;
    memcpy(&mms_type, packet, sizeof(uint16_t));

    printf("mms_type = %x\n", ntohs(mms_type));
    packet += sizeof(uint16_t);

    if(ntohs(mms_type) == INITIATE_REQUESTPDU)
    {
        uint8_t tag_lDC = *packet;
        printf("tag_lDC : %#x\n", tag_lDC);
        packet += sizeof(uint8_t);

        uint8_t len_lDC = *packet;
        printf("len_lDC : %#x\n", len_lDC);
        packet += sizeof(uint8_t);

//        uint8_t lDC[len_lDC];
        uint16_t lDC;
        memcpy(&lDC, packet, len_lDC);
        printf("localDetailCalling : %d\n", ntohs(lDC));

        packet += sizeof(uint16_t);
        uint8_t tag_pMSOC = *packet;
        packet += sizeof(uint8_t);
        printf("tag_pMSOC : %#x\n", tag_pMSOC);

        uint8_t len_Calling = *packet;
        packet += sizeof(uint8_t);
        printf("len_pMSOC : %#x\n", len_Calling);

        uint8_t Calling[len_Calling];
        memcpy(Calling, packet, len_Calling);
        printf("proposedMaxServOutstandingCalling : %d\n", *Calling);

        packet += len_Calling;
        uint8_t tag_Called = *packet;
        packet += sizeof(uint8_t);
        printf("tag_Called : %#x\n", tag_Called);

        uint8_t len_Called = *packet;
        packet += sizeof(uint8_t);
        printf("len_Called : %#x\n", len_Called);

        uint8_t Called[len_Called];
        memcpy(Called, packet, len_Called);
        printf("proposedMaxServOutstandingCalled : %d\n", *Called);

        packet += len_Called;
        uint8_t tag_data_structure = *packet;
        printf("tag : %#x\n", tag_data_structure);

        packet += sizeof(uint8_t);
        uint8_t len_data_structure = *packet;
        printf("len : %#x\n", len_data_structure);

        uint16_t data_structure;
        memcpy(&data_structure, packet, len_data_structure);
        printf("proposedDataStructureNestingLevel : %d\n", ntohs(data_structure));

        packet += len_data_structure;
        printByHexData(packet, 24);
    }
}
