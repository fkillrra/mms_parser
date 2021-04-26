#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h> //ethernet header
#include <netinet/ip.h>   //ip header
#include <netinet/tcp.h>  //tcp header
#include <arpa/inet.h>    //inet_ntoa()

struct ether_header *ethh;
struct ip *iph;
struct tcphdr *tcph;
struct udphdr *udph;


void ethernet_dump(const u_char* packet);
void ip_dump(const u_char* packet);
void tcp_dump(const u_char* packet);
void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet);
void usage()
{
  printf("sysntax : pcap_test <interface>\n");
  printf("sample@linux~$ ./pcap_test wlan0\n");
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
  packet += (tcph -> th_off);
  printf("================ Data ================\n");
  for(int i = 0; i < 14; i++)
  {
    printf("%02x", *(packet++));
    if(i % 14 == 0 && i != 0)
       printf("\n");
  }
  printf("\n\n\n");
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
