#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

#define TRUE 1
#define FALSE 0
#define ETHER_SIZE 14

struct ip *_ip;
struct tcphdr *_tcphdr;
struct ether_header *_ether_header;


void data_func(const uint8_t *packet, int ip_size, int tcp_size)
{
  char *packet_data = (u_char *)packet + ETHER_SIZE + ip_size + tcp_size;
  int packet_data_length = ntohs(_ip->ip_len) - (ip_size + tcp_size);

  if(packet_data_length == 0)
    printf("no packet_data\n");
  else
  {
    for(int i=0; i<packet_data_length; i++)
    {
      if(i==15)
      {
        printf("\n");
        return ;
      }
      printf("%02x ", packet_data[i]);
    }
  }
}

void tcp_func(const uint8_t *packet, int ip_size)
{
  _tcphdr = (struct tcphdr *)(packet + ETHER_SIZE + ip_size);
  printf("src port: %d\n", ntohs(_tcphdr->th_sport));
  printf("dst port: %d\n", ntohs(_tcphdr->th_dport));
  data_func(packet, ip_size, _tcphdr->th_off * 4);
}

void ip_func(const uint8_t *packet)
{

  _ip = (struct ip*)(packet + ETHER_SIZE);
  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(_ip->ip_src), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(_ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

  printf("src IP : %s \n", src_ip);
  printf("dst IP : %s \n", dst_ip);

  if(_ip->ip_p == IPPROTO_TCP) //0x06
  {
    tcp_func(packet, _ip->ip_off * 4);
  }
  else
  {
    printf("no tcp header\n");
    return ;
  }
}

void ethernet_func(const uint8_t *packet)
{
  int i;
  _ether_header = (struct ether_header *)packet;
  printf("========Information=======\n");

  printf("src mac: ");
  for(i=0; i<ETHER_ADDR_LEN-1;i++)
  {
    printf("%02x:", _ether_header->ether_shost[i]);
  }
  printf("%02x\n", _ether_header->ether_shost[i]);

  printf("dst mac: ");
  for(i=0; i<ETHER_ADDR_LEN-1; i++)
  {
    printf("%02x:", _ether_header->ether_dhost[i]);
  }
    printf("%02x\n", _ether_header->ether_shost[i]);

  if(ntohs(_ether_header->ether_type) == ETHERTYPE_IP) //0X0800
  {
    ip_func(packet);
  }
  else
  {
    printf("no ip header\n");
  }
  printf("\n");
}


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (TRUE) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    ethernet_func(packet);
  }

  pcap_close(handle);
  return 0;
}
