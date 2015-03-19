/*
 * * FILE NAME:		dns_zone_read.h
 * * STANDARD HEADER FILE
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	SEPTEMBER.29.2014
 * * DATE LAST MOD:	JANUARY.21.2015
 * *     ___________
 * *    |           | 
 * *  [[|___________|]] 
 * *    \___________/ 
 * *   __|[ ]||||[ ]|__
 * *   \_| # |||| # |_/
 * *  ___ ===Jeep=== ___ 
 * * |\/\| ''    '' |\/\|
 * * |/\/|          |/\/|
 * * |_\_|          |_\_|
 * */
/**********************************************************************/
/*
 * * MODIFIED LOG:
 * *       <date>-<description>
 * *	September.29.2014-Adapted from dns_1.h
 * *	January.21.2015-Added includes from ricks_netfpga.c
 * */
/**********************************************************************/
//Network and Structures
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
//Timestamps
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifndef _DNS_NETFPGA
#define _DNS_NETFPGA 1

//Network and Structures
#include "structs_zone_read.h" 
#include "triez_zone_read.c" 

/* NETFPGA SPECIFIC DECLARATIONS */
#define ETH_HDR_SZ 14
#define IPV4_HDR_SZ 20
#define UDP_HDR_SZ 8
#define DNS_HDR_SZ 12
//#define TYP_
#endif //end dns_zone_read.h

/* DECLARATIONS */
#define QRY_NO 1
#define DNM_SZ 255
#define LBL_SZ 63
#define SEG_SZ 17
#define LNE_SZ 1025
#define PKT_SZ 313	//byte size of UDP Packet 512 - 12(header) 500
#define MAX_IP 65507	//Max byte size of UDP IPv4 is 6507 both include header
#define UDP_PT 53
//#define UDP_PT 32000
#define IPV4STRLEN 16
#define IPV6STRLEN 46
#define IPV4BYTESZ 32
#define IPV6BYTESZ 128
#define MAXFD 64
#define THD_MX 8
//#define UDP_SZ 4096	//bit size of UDP Packet 500 bytes * 8
/* WRITE DRAM (ZONE READ SPECIFIC) */
/* WRITE DRAM (ZONE READ SPECIFIC) */
#include <net/if.h>
#include "common/nf2.h"
#include "common/nf2util.h"

#define DEFAULT_IFACE	"nf2c0"
#define BASE_MASK 0x4000000
