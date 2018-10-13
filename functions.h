/* Copyright © 2018 James Sung. All rights reserved. */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <pcap/pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>

#include <time.h>
#include <pthread.h>

/* ARP protocol pre-defined macros in net/if_arp.h */


#define ARP_HTYPE_ETH 1
#define ARP_PTYPE_IP  0x0800
#define ARP_HLEN_ETH  6
#define ARP_PLEN_IP   4
#define ARP_OPER_RQ   1
#define ARP_OPER_RP   2


#pragma pack(push, 1)

typedef struct _my_arp_hdr
{
	uint16_t HTYPE;		// hardware type
	uint16_t PTYPE;		// protocol type
	uint8_t  HLEN;		// hardware address length
	uint8_t  PLEN;		// protocol address length
	uint16_t OPER;		// operation
	uint8_t  SHA[6];	// sender hardware address; actually uint48_t
	uint32_t SPA;		// sender protocol address
	uint8_t  THA[6];	// target hardware address; actually uint48_t
	uint32_t TPA;		// target protocol address
} my_arp_hdr;

typedef struct _my_etharp_hdr
{
	uint8_t    DMAC[6];
	uint8_t    SMAC[6];
	uint16_t   ETHTYPE;
	my_arp_hdr ARPHDR;
} my_etharp_hdr;

typedef struct _my_args_struct
{
	char dev[16];
	uint32_t sender_IP_int;
	uint32_t target_IP_int;
	uint8_t arp_reply2sender[42];
	uint8_t arp_reply2target[42];
} my_args_struct;

#pragma pack(pop)


void PRINT_USAGE(void);

void GET_MY_IP(char *attacker_IP_char, char *interface);
void PRINT_IP(char *IP_char);
void GET_MY_MAC(uint8_t *attacker_MAC_array, char *interface);
void PRINT_MAC(uint8_t *MAC_array);

void MAKE_ARPREQ_STRUCT(my_etharp_hdr *arp_struct, uint8_t *source_MAC_array, uint32_t source_IP_int, uint32_t destination_IP_int);
void MAKE_ARPREP_STRUCT(my_etharp_hdr *arp_struct, uint8_t *source_MAC_array, uint8_t *destination_MAC_array, uint32_t destination_IP_int, uint32_t target_IP_int);

bool GET_SENDER_MAC(uint8_t *sender_MAC_array, int sender_IP_int, pcap_t *handle, pcap_pkthdr *header, const uint8_t *packet);

void *BLOCK_RECOVERY(void *info);
