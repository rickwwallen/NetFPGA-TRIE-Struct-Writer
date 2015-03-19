/*
 * * FILE NAME:		triez_zone_read.h
 * * HEADER FILE FOR triez_zone_read.c
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
 * *	September.29.2014-Adapted from triez.h
 * *	January.21.2015-Commented out readZone function prototype
 * */
/**********************************************************************/
#ifndef _TRIEZ_NETFPGA_
#define _TRIEZ_NETFPGA_ 1
//#include <arpa/inet.h>
#include "dns_zone_read.h"
/* F(X) PROTOTYPES */
/* F(X) TO DAEMONIZE THE SERVER */
//int daemonInit(const char *pname, int facility);

/* F(X) TO CREATE A RESOUCE RECORD */
void createResRec(struct nf2device *nf2, unsigned *cur_pos, unsigned *next_avail, char *rec, uint32_t *ttlMin, uint16_t *rclass);

/* F(X) TO ADD TO RESOUCE RECORD */
void addResRec(struct nf2device *nf2, unsigned *cur_pos, unsigned *next_avail, char *rec, uint32_t *ttlMin, uint16_t *rclass);

/* F(X) TO CREATE A NODE IN TRIE */
void createNode(struct nf2device *nf2, unsigned *cur_pos, unsigned *next_avail, char k, int state);

/* F(X) TO ADD TO TRIE */
void addTrie(struct nf2device *nf2, unsigned root_addr, unsigned *next_avail, char *name, char *rec, uint32_t *ttlMin, uint16_t *rclass);

/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
void readZone(struct nf2device *nf2, char *fn);

/* F(X) TO CHECK DOMAIN NAME DOESN'T CONTAIN INVALID CHARACTERS */
uint16_t checkDN(char *domName);
//int checkDN(char *domName);

/*F(X) TO MAKE DOMAIN NAME UPPER CASE FOR SEARCHING */
void uDN(char *dom);

/* F(X) TO REVERSE DOMAIN NAME */
int revDN(char *DN);

#endif //end if triez_zone_read.h
