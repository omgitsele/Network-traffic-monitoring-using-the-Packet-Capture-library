#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define PCAP_BUF_SIZE	1024


int totalPackets = 0;
int tcpCount = 0;
int udpCount = 0;
int totalNetFlows = 0;
int totalTCPFlows = 0;
int totalUDPFlows = 0;
long tcpBytes = 0;
long udpBytes = 0;
int anomalies = 0;
int flag = 0;
int previousACK = 0;


struct Node {
		char *src_address;
		int src_port;
		char *dst_address;
		int dst_port;
		char *protocol;
    struct Node *next;
};
struct Node *Head = NULL;

void packetHandler(u_char *, const struct pcap_pkthdr*, const u_char*);
void insertNewNode(char *, int , char *, int , char *);
void checkFlow(char *, int , char *, int , char *);
char *applicationLayerProtocol(int , char *);

/*
 * checkFlow is used to check and store network flows
 */
void checkFlow(char *src, int src_port, char *dst, int dst_port, char *protocol) {
    struct Node *ptr = Head;
    bool exists = false;

    while(ptr != NULL) {
        if (src==ptr->src_address && src_port==ptr->src_port && dst==ptr->dst_address && dst_port==ptr->dst_port && protocol==ptr->protocol) {
            exists = true;
            break;
        }
        ptr = ptr->next;
    }
    if (!exists){//if flow doesnt already exist insert it
        insertNewNode(src, src_port, dst, dst_port, protocol);
        if (protocol == "TCP")
            totalTCPFlows++;        
        else
            totalUDPFlows++;

        totalNetFlows++;
        
    }
    return;
}

/*
 * insertNewNode inserts a new node to the Node structure
 */
void insertNewNode(char *src_address, int src_port, char *dst_address, int dst_port, char *protocol) {
  struct Node *link = (struct Node*) malloc(sizeof(struct Node));
	link->src_address = src_address;
	link->src_port = src_port;
	link->dst_address = dst_address;
	link->dst_port = dst_port;
	link->protocol = protocol;
    link->next = Head;
    Head = link;
}

void
usage(void){
	printf("\nusage:\n\t./monitor \nOptions:\n-r  Packet capture file name (e.g. test.pcap)\n-h, Help message\n\n");
	exit(1);
}

/*
 * applicationLayerProtocol will check the port number used and which protocol (TCP or UDP) is used
 * and will return the application layer protocol if that exists.
 */
char *applicationLayerProtocol(int portNumber, char *protocol)
{
    switch (portNumber)
    {
        case 20:
        case 21:
            if (protocol == "TCP")
                return "File Transfer Protocol (FTP)";
            else
                return "Unknown UDP protocol";
            break;
        case 22:
            if (protocol == "TCP")
                return "Secure Shell (SSH)";
            else
                return "Unknown UDP protocol";
            break;
        case 23:
            if (protocol == "TCP")
                return "Telnet";
            else
                return "Unknown UDP protocol";
            break;
        case 25:
            if(protocol == "TCP")
                return "Simple Mail Transfer Protocol (SMTP)";
            else
                return "Unknown UDP protocol";
            break;
        case 53:
            return "Domain Name System (DNS)";
            break;
        case 67:
        case 68:
            if (protocol == "UDP")
                return "Dynamic Host Configuration Protocol (DHCP)";
            else
                return "Unknown TCP protocol";
            break;
        case 69:
            if (protocol == "UDP")
                return "Trivial File Transfer Protocol (TFTP)";
            else
                return "Unknown TCP protocol";
            break;
        case 80:
            if(protocol == "TCP")
                return "Hypertext Transfer Protocol (HTTP)";
            else
                return "Unknown UDP protocol";
            break;
        case 110:
            if(protocol == "TCP")
                return "Post Office Protocol (POP) version 3";
            else
                return "Unknown UDP protocol";
            break;
        case 123:
            if(protocol == "UDP")
                return "Network Time Protocol (NTP)";
            else
                return "Unknown TCP protocol";
            break;
        case 137:
        case 138:
        case 139:
            return "NetBIOS";
            break;
        case 143:
            if(protocol == "TCP")
                return "Internet Message Access Protocol (IMAP)";
            else
                return "Unknown UDP protocol";
            break;
        case 161:
        case 162:
            return "Simple Network Management Protocol (SNMP)";
            break;
        case 179:
            if(protocol == "TCP")
                return "Border Gateway Protocol (BGP)";
            else
                return "Unknown UDP protocol";
            break;
        case 389:
            return "Lightweight Directory Access Protocol (LDAP)";
            break;
        case 443:
        case 8443:
            if(protocol == "TCP")
                return "Hypertext Transfer Protocol over SSL/TLS (HTTPS)";
            else 
                return "Unknown UDP protocol";
            break;
        case 636:
            return "Lightweight Directory Access Protocol over TLS/SSL (LDAPS)";
            break;
        case 989:
        case 990:
            if(protocol == "TCP")
                return "FTP over TLS/SSL";
            else
                return "Unknown UDP protocol";
            break;
        
        default:
            if (protocol == "TCP")
                return "Unknown TCP protocol";
            else
                return "Unknown UDP protocol";
            break;
    }
    
}

/*
 * packetHandler decodes each received TCP or UDP packet
 * Prints the packet’s source and destination IPv4 addresses.
 * Prints the packet’s source and destination port numbers.
 * Prints the packet’s application protocol
 * Prints the packet’s TCP/UDP header length and TCP/UDP payload length in bytes.
 */
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int payload = 0;
    int headerLength = 0;
    int i;
    char *appLayProtocolSource;
    char *appLayProtocolDest;
    int retr = 0;
    

    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    /* inet_ntop
     * Convert IPv4 and IPv6 addresses from binary to text form 
     * Use AF_INET for IPv4 and AF_INET6 for IPv6
    */
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

    

    // Check if the protocol is TCP or UDP 
    // First if statement checks for TCP protocol
    if (ipHeader->ip_p == IPPROTO_TCP) {

        tcpCount++;

        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

        headerLength = tcpHeader->doff*4;

        // The below 2 lines are unused. The would be used to check if the packet is a retransmission
        unsigned int tcpack = ntohl(tcpHeader->th_ack);
        unsigned int seq = ntohl(tcpHeader->th_seq);
        
        /* ntohs:
         * The ntohs() function converts the unsigned short integer netshort from network byte order to host byte order. 
        */
        sourcePort = ntohs(tcpHeader->th_sport);
        
        destPort = ntohs(tcpHeader->th_dport);
       
        //payload = ntohs(ipHeader->ip_len);

        payload = (pkthdr->caplen -sizeof(struct ether_header) - headerLength - ipHeader->ip_hl*4);

        checkFlow(sourceIP, sourcePort, destIP, destPort, "TCP");

        tcpBytes += payload + headerLength;

        appLayProtocolSource = applicationLayerProtocol(sourcePort, "TCP");

        appLayProtocolDest = applicationLayerProtocol(destPort, "TCP");

        if (appLayProtocolSource != "Unknown TCP protocol" && appLayProtocolDest== "Unknown TCP protocol")
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocol: %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolSource);

        }
        else if (appLayProtocolSource == "Unknown TCP protocol" && appLayProtocolDest != "Unknown TCP protocol")
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocol: %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolDest);

        }
        else if(appLayProtocolSource == "Unknown TCP protocol" && appLayProtocolDest== "Unknown TCP protocol")
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocol: %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolDest);

        }
        else
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocols: %s and %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolSource, appLayProtocolDest);
        }       

    } 
    // Second if statement checks for UDP protocol
    else if (ipHeader->ip_p == IPPROTO_UDP) {

        udpCount++;

        udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

        headerLength = sizeof(struct udphdr); 

        sourcePort = ntohs(udpHeader->source);

        destPort = ntohs(udpHeader->dest);

        int ipHeaderLength = ipHeader->ip_hl * 4;

        int a = sizeof(struct ether_header) + headerLength + ipHeaderLength;

        payload = (pkthdr->caplen -a);

        checkFlow(sourceIP, sourcePort, destIP, destPort, "UDP");

        appLayProtocolSource = applicationLayerProtocol(sourcePort, "UDP");

        appLayProtocolDest = applicationLayerProtocol(destPort, "UDP");

        udpBytes += payload + headerLength;

        if (appLayProtocolSource != "Unknown UDP protocol" && appLayProtocolDest== "Unknown UDP protocol")
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocol: %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolSource);

        }
        else if (appLayProtocolSource == "Unknown UDP protocol" && appLayProtocolDest != "Unknown UDP protocol")
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocol: %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolDest);

        }
        else if(appLayProtocolSource == "Unknown UDP protocol" && appLayProtocolDest== "Unknown UDP protocol")
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocol: %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolDest);

        }
        else
        {
            printf("Src addr: %s Dest addr: %s Src port: %d Dest port: %d Header length: %d Payload: %d App Protocols: %s and %s\n",sourceIP, destIP, sourcePort, destPort, headerLength, payload, appLayProtocolSource, appLayProtocolDest);
        }
        
    } 
    totalPackets++;
}

int main(int argc, char *argv[]){

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char ch;

    if (argc < 2)
		usage();
	while ((ch = getopt(argc, argv, "hr:")) != -1) {
		switch (ch) {
		case 'r':
			fp = pcap_open_offline(optarg, errbuf);
            if (fp == NULL) {
                fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
                return 0;
            }
            /*
             * pcap_loop() processes packets from a live capture or ``savefile'' until cnt 
             * packets are processed, the end of the ``savefile'' is reached when reading from 
             * a ``savefile'', pcap_breakloop(3PCAP) is called, or an error occurs. It does not 
             * return when live packet buffer timeouts occur. A value of -1 or 0 for cnt is equivalent 
             * to infinity, so that packets are processed until another ending condition occurs. 
            */
            if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
                fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
                return 0;
            }
            printf("\n==============================================================================\n");
            printf("Total number of network flows: %d\n", totalNetFlows);
            printf("Total number of TCP network flows: %d\n", totalTCPFlows);
            printf("Total number of UDP network flows: %d\n", totalUDPFlows);
            printf("Total number of packets received: %d\n",totalPackets);
            printf("Total number of TCP packets: %d\n", tcpCount);
            printf("Total number of UDP packets: %d\n", udpCount);
            printf("Total TCP bytes: %ld\n",tcpBytes);
            printf("Total UDP bytes: %ld\n",udpBytes);
			break;
		default:
			usage();
		}
	}

	return 0;
}