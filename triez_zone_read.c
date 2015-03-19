/*
 * * FILE NAME:		triez_zone_read.c
 * * CONTAINS ALL FUNCTIONS UTILIZED BY DNS SERVER EXCEPT THOSE PERTAINING TO
 * *	MULTITHREADING
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
 * *	September.29.2014-Adapted from triez.c
 * *	January.21.2015-Commented out readZone since file io isn't allowed and needs to occur from the host
 * *	January.25.2015-Changed allocation to use the netthreads version
 * */
/**********************************************************************/
#include "triez_zone_read.h"
#include "dns_zone_read.h"

/* F(X) TO CREATE A RESOUCE RECORD */
void createResRec(struct nf2device *nf2, unsigned *cur_pos, unsigned *next_avail, char *rec, uint32_t *ttlMin, uint16_t *rclass)
{
	int i, seg, c;
	uint8_t ipv6_addr[16];
	uint32_t ttl;
	uint16_t class;
	uint16_t type;
	A    *ars;
	NS   *nsrs;
	CNAME *cnamers;
	PTR  *ptrrs;
	MX   *mxrs;
	AAAA *aaaars;
	SOA  *soars;
	unsigned ars_addr;
	unsigned nsrs_addr;
	unsigned cnamers_addr;
	unsigned ptrrs_addr;
	unsigned mxrs_addr;
	unsigned aaaars_addr;
	unsigned soars_addr;
	unsigned temp_val;

	//writeReg(nf2, *cur_pos + sizeof(char), *next_avail);
	writeReg(nf2, *cur_pos + sizeof(unsigned), *next_avail);

	ars_addr	= *next_avail;
	nsrs_addr	= *next_avail + (sizeof(unsigned) * 1);
	cnamers_addr	= *next_avail + (sizeof(unsigned) * 2);
	ptrrs_addr	= *next_avail + (sizeof(unsigned) * 3);
	mxrs_addr	= *next_avail + (sizeof(unsigned) * 4);
	aaaars_addr	= *next_avail + (sizeof(unsigned) * 5);
	soars_addr	= *next_avail + (sizeof(unsigned) * 6);

	*next_avail	= soars_addr + sizeof(unsigned);

	writeReg(nf2, ars_addr,     (unsigned) '\0');
	writeReg(nf2, nsrs_addr,    (unsigned) '\0');
	writeReg(nf2, cnamers_addr, (unsigned) '\0');
	writeReg(nf2, ptrrs_addr,   (unsigned) '\0');
	writeReg(nf2, mxrs_addr,    (unsigned) '\0');
	writeReg(nf2, aaaars_addr,  (unsigned) '\0');
	writeReg(nf2, soars_addr,   (unsigned) '\0');

	// default TTL to 1 day will be overwritten by default value anyways
	ttl   = 86400;
	i     = 0;
	seg   = 0;
	class = 0;
	type  = 0;

	if(strcmp(rec, "") == 0)
		return;
	// Count number of delimiters
	for(i = 0; i <= strlen(rec); i++)
	{
		if(rec[i] == ',')
			seg++;
	}
	// Allocate 2d array
	char **buff = (char**) malloc(seg * sizeof (char*));
	// Variable for the current segment
	char *buff2 = (char *) malloc(LNE_SZ *sizeof(char));
	buff2 = strtok(rec, ",");

	for(i = 0; buff2 != NULL; i++)
	{
		buff[i] = malloc(strlen(buff2)*sizeof(char));
		memcpy(buff[i], buff2, strlen(buff2));
		buff2 = strtok(NULL, ",");
	}

	class = *rclass;

	if((seg-1 == 2 && strcmp(buff[0],"MX") != 0) || (seg-1 == 3 && strcmp(buff[0],"MX") == 0))
	{
		if(isdigit(buff[0][0]))
		{
			ttl = (uint32_t) atoi(buff[0]);
			c   = 1;
		}
		else
			c = 0;
	}
	else if((seg-1 == 3 && strcmp(buff[1],"MX") != 0) || (seg-1 == 4 && strcmp(buff[1],"MX") == 0))
	{
		if(isdigit(buff[0][0]))
			ttl =(uint32_t) atoi(buff[0]);
		c = 1;
	}
	else
	{
		ttl = *ttlMin;
		c   = 0;
	}

	if(ttl < *ttlMin)
		ttl = *ttlMin;

	for(; c < seg; c++)
	{
		if(strcmp(buff[c], "IN") == 0)
			class = (uint16_t) in;

		else if(strcmp(buff[c], "CS") == 0)
			class = (uint16_t) cs;

		else if(strcmp(buff[c], "CH") == 0)
			class = (uint16_t) ch;

		else if(strcmp(buff[c], "HS") == 0)
			class = (uint16_t) hs;

		else if(strcmp(buff[c], "A") == 0)
			type = (uint16_t) a;

		else if(strcmp(buff[c], "NS") == 0)
			type = (uint16_t) ns;

		else if(strcmp(buff[c], "CNAME") == 0)
			type = (uint16_t) cname;

		else if(strcmp(buff[c], "SOA") == 0)
			type = (uint16_t) soa;

		else if(strcmp(buff[c], "PTR") == 0)
			type = (uint16_t) ptr;

		else if(strcmp(buff[c], "MX") == 0)
			type = (uint16_t) mx;

		else if(strcmp(buff[c], "AAAA") == 0)
			type = (uint16_t) aaaa;
		else
			break;
	}

	switch((DnsType) type)
	{
		case a:
			writeReg(nf2, ars_addr, htonl(*next_avail));
			ars              =	(A *) malloc(sizeof(A));
			if(inet_pton(AF_INET, buff[c], &ars->address) == 1);
			else
				printf("\n\nERROR\t%s\n\n", buff[c]);
			ars->rclass      =	class;
			ars->ttl         =	ttl;
			ars->rdlen       =	sizeof(IPV4BYTESZ);
			ars->anxt        =	NULL;
			temp_val         =	(unsigned) htons(ars->rclass) <<16|htons(ars->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(ars->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(ars->address));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(ars);
			break;
		case ns:
			writeReg(nf2, nsrs_addr, htonl(*next_avail));
			nsrs             =	(NS *) malloc(sizeof(NS));
			memcpy(nsrs->nsdname, buff[c], strlen(buff[c]));
			nsrs->rclass     =	class;
			nsrs->ttl        =	ttl;
			nsrs->rdlen      =	strlen(nsrs->nsdname) + 1;
			nsrs->nsnxt      =	NULL;
			temp_val         =	(unsigned) htons(nsrs->rclass) <<16|htons(nsrs->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(nsrs->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(nsrs->nsdname); i+=4)
			{
				if(strlen(nsrs->nsdname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|nsrs->nsdname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(nsrs->nsdname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |nsrs->nsdname[i+1] <<16
							     |nsrs->nsdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(nsrs->nsdname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |nsrs->nsdname[i+2] <<16
							     |nsrs->nsdname[i+1] <<8
							     |nsrs->nsdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &nsrs->nsdname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(nsrs);
			break;
		case cname:
			writeReg(nf2, cnamers_addr, htonl(*next_avail));
			cnamers          =	(CNAME *) malloc(sizeof(CNAME));
			memcpy(cnamers->cname, buff[c], strlen(buff[c]));
			cnamers->rclass  =	class;
			cnamers->ttl     =	ttl;
			cnamers->rdlen   = 	strlen(cnamers->cname) + 1;
			temp_val         =	(unsigned) htons(cnamers->rclass) <<16|htons(cnamers->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(cnamers->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(cnamers->cname); i+=4)
			{
				if(strlen(cnamers->cname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|cnamers->cname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(cnamers->cname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |cnamers->cname[i+1] <<16
							     |cnamers->cname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(cnamers->cname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |cnamers->cname[i+2] <<16
							     |cnamers->cname[i+1] <<8
							     |cnamers->cname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &cnamers->cname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			free(cnamers);
			break;
		case soa:
			writeReg(nf2, soars_addr, htonl(*next_avail));
			soars            =	(SOA *) malloc(sizeof(SOA));
			memcpy(soars->mname, buff[c],   strlen(buff[c]));
			memcpy(soars->rname, buff[c+1], strlen(buff[c+1]));
			soars->serial    =	(uint32_t) atoi(buff[c+2]);
			soars->refresh   =	(int32_t)  atoi(buff[c+3]);
			soars->retry     =	(int32_t)  atoi(buff[c+4]);
			soars->expire    =	(int32_t)  atoi(buff[c+5]);
			soars->minimum   =	(uint32_t) atoi(buff[c+6]);
			soars->rclass    =	class;
			soars->rdlen     =	strlen(soars->mname) + 1 +
							strlen(soars->rname) + 1 +
							sizeof(soars->serial) +
							sizeof(soars->refresh) +
							sizeof(soars->expire) +
							sizeof(soars->minimum);
			(*ttlMin)        =	(uint32_t) atoi(buff[c+6]);
			(*rclass)        =	class;
			temp_val         =	(unsigned) htons(soars->rclass) <<16|htons(soars->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			//writeReg(nf2, *next_avail, (unsigned) htonl(soars->ttl));
			//*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->serial));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->refresh));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->retry));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->expire));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->minimum));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(soars->mname); i+=4)
			{
				if(strlen(soars->mname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|soars->mname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->mname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->mname[i+1] <<16
							     |soars->mname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->mname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->mname[i+2] <<16
							     |soars->mname[i+1] <<8
							     |soars->mname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &soars->mname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			for(i = 0; i <= strlen(soars->rname); i+=4)
			{
				if(strlen(soars->rname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|soars->rname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->rname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->rname[i+1] <<16
							     |soars->rname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->rname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->rname[i+2] <<16
							     |soars->rname[i+1] <<8
							     |soars->rname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &soars->rname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			free(soars);
			break;
		case ptr:
			writeReg(nf2, ptrrs_addr, htonl(*next_avail));
			ptrrs            =	(PTR *) malloc(sizeof(PTR));
			memcpy(ptrrs->ptrdname, buff[c], strlen(buff[c]));
			ptrrs->rclass    =	class;
			ptrrs->ttl       =	ttl;
			ptrrs->rdlen     =	strlen(ptrrs->ptrdname) + 1;
			temp_val         =	(unsigned) htons(ptrrs->rclass) <<16|htons(ptrrs->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(ptrrs->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(ptrrs->ptrdname); i+=4)
			{
				if(strlen(ptrrs->ptrdname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|ptrrs->ptrdname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(ptrrs->ptrdname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |ptrrs->ptrdname[i+1] <<16
							     |ptrrs->ptrdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(ptrrs->ptrdname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |ptrrs->ptrdname[i+2] <<16
							     |ptrrs->ptrdname[i+1] <<8
							     |ptrrs->ptrdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &ptrrs->ptrdname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			free(ptrrs);
			break;
		case mx:
			writeReg(nf2, mxrs_addr, htonl(*next_avail));
			mxrs             =	(MX *) malloc(sizeof(MX));
			mxrs->preference =	(uint16_t) atoi(buff[c]);
			memcpy(mxrs->exchange, buff[c+1], strlen(buff[c+1]));
			mxrs->rclass     =	class;
			mxrs->ttl        =	ttl;
			mxrs->rdlen      = 	sizeof(mxrs->preference) +
							strlen(mxrs->exchange) + 1;
			mxrs->mxnxt      =	NULL;
			temp_val         =	(unsigned) htons(mxrs->rclass) <<16|htons(mxrs->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			writeReg(nf2, *next_avail, (unsigned) htonl(mxrs->ttl));
			temp_val         =	(unsigned) 0 <<16|htons(mxrs->preference);
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			for(i = 0; i <= strlen(mxrs->exchange); i+=4)
			{
				if(strlen(mxrs->exchange)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|mxrs->exchange[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(mxrs->exchange)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |mxrs->exchange[i+1] <<16
							     |mxrs->exchange[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(mxrs->exchange)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |mxrs->exchange[i+2] <<16
							     |mxrs->exchange[i+1] <<8
							     |mxrs->exchange[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &mxrs->exchange[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(mxrs);
			break;
		case aaaa:
			writeReg(nf2, aaaars_addr, htonl(*next_avail));
			aaaars           =	(AAAA *) malloc(sizeof(AAAA));
			if(inet_pton(AF_INET6, buff[c], &aaaars->address) == 1);
			else
				printf("\n\nERROR\n\n");
			aaaars->rclass   =	class;
			aaaars->ttl      =	ttl;
			aaaars->rdlen    = 	sizeof(IPV6BYTESZ);
			aaaars->aaaanxt  =	NULL;
			temp_val         =	(unsigned) htons(aaaars->rclass) <<16|htons(aaaars->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(aaaars->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			memcpy(&ipv6_addr, &aaaars->address, sizeof(aaaars->address)); 
			temp_val         =	(unsigned) ipv6_addr[3] <<24
							  |ipv6_addr[2] <<16
							  |ipv6_addr[1] <<8
							  |ipv6_addr[0];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			temp_val         =	(unsigned) ipv6_addr[7] <<24
							  |ipv6_addr[6] <<16
							  |ipv6_addr[5] <<8
							  |ipv6_addr[4];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			temp_val         =	(unsigned) ipv6_addr[11]  <<24
							  |ipv6_addr[10]  <<16
							  |ipv6_addr[9]   <<8
							  |ipv6_addr[8];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			temp_val         =	(unsigned) ipv6_addr[15] <<24
							  |ipv6_addr[14] <<16
							  |ipv6_addr[13] <<8
							  |ipv6_addr[12];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(aaaars);
			break;
		default:
			return;
			break;
	}
	return;
}

/* F(X) TO ADD TO RESOUCE RECORD */
void addResRec(struct nf2device *nf2, unsigned *cur_pos, unsigned *next_avail, char *rec, uint32_t *ttlMin, uint16_t *rclass)
{
	int i, seg, c;
	uint8_t ipv6_addr[16];
	uint32_t ttl;
	uint16_t class;
	uint16_t type;
	A    *ars;
	NS   *nsrs;
	CNAME *cnamers;
	PTR  *ptrrs;
	MX   *mxrs;
	AAAA *aaaars;
	SOA  *soars;
	unsigned ars_addr;
	unsigned nsrs_addr;
	unsigned cnamers_addr;
	unsigned ptrrs_addr;
	unsigned mxrs_addr;
	unsigned aaaars_addr;
	unsigned soars_addr;
	unsigned temp_val;
	unsigned reg_val;
	struct two_sixteens *ts;
	int len;

	//writeReg(nf2, *cur_pos + sizeof(char), *next_avail);
	readReg(nf2, *cur_pos + sizeof(unsigned), &reg_val);

	ars_addr	= ntohl(reg_val);
	nsrs_addr	= ntohl(reg_val) + (sizeof(unsigned) * 1);
	cnamers_addr	= ntohl(reg_val) + (sizeof(unsigned) * 2);
	ptrrs_addr	= ntohl(reg_val) + (sizeof(unsigned) * 3);
	mxrs_addr	= ntohl(reg_val) + (sizeof(unsigned) * 4);
	aaaars_addr	= ntohl(reg_val) + (sizeof(unsigned) * 5);
	soars_addr	= ntohl(reg_val) + (sizeof(unsigned) * 6);

	// default TTL to 1 day will be overwritten by default value anyways
	ttl   = 86400;
	i     = 0;
	seg   = 0;
	class = 0;
	type  = 0;

	if(strcmp(rec, "") == 0)
		return;
	// Count number of delimiters
	for(i = 0; i <= strlen(rec); i++)
	{
		if(rec[i] == ',')
			seg++;
	}
	// Allocate 2d array
	char **buff = (char**) malloc(seg * sizeof (char*));
	// Variable for the current segment
	char *buff2 = (char *) malloc(LNE_SZ *sizeof(char));
	buff2 = strtok(rec, ",");

	for(i = 0; buff2 != NULL; i++)
	{
		buff[i] = malloc(strlen(buff2)*sizeof(char));
		memcpy(buff[i], buff2, strlen(buff2));
		buff2 = strtok(NULL, ",");
	}

	class = *rclass;

	if((seg-1 == 2 && strcmp(buff[0],"MX") != 0) || (seg-1 == 3 && strcmp(buff[0],"MX") == 0))
	{
		if(isdigit(buff[0][0]))
		{
			ttl = (uint32_t) atoi(buff[0]);
			c   = 1;
		}
		else
			c = 0;
	}
	else if((seg-1 == 3 && strcmp(buff[1],"MX") != 0) || (seg-1 == 4 && strcmp(buff[1],"MX") == 0))
	{
		if(isdigit(buff[0][0]))
			ttl =(uint32_t) atoi(buff[0]);
		c = 1;
	}
	else
	{
		ttl = *ttlMin;
		c   = 0;
	}

	if(ttl < *ttlMin)
		ttl = *ttlMin;

	for(; c < seg; c++)
	{
		if(strcmp(buff[c], "IN") == 0)
			class = (uint16_t) in;

		else if(strcmp(buff[c], "CS") == 0)
			class = (uint16_t) cs;

		else if(strcmp(buff[c], "CH") == 0)
			class = (uint16_t) ch;

		else if(strcmp(buff[c], "HS") == 0)
			class = (uint16_t) hs;

		else if(strcmp(buff[c], "A") == 0)
			type = (uint16_t) a;

		else if(strcmp(buff[c], "NS") == 0)
			type = (uint16_t) ns;

		else if(strcmp(buff[c], "CNAME") == 0)
			type = (uint16_t) cname;

		else if(strcmp(buff[c], "SOA") == 0)
			type = (uint16_t) soa;

		else if(strcmp(buff[c], "PTR") == 0)
			type = (uint16_t) ptr;

		else if(strcmp(buff[c], "MX") == 0)
			type = (uint16_t) mx;

		else if(strcmp(buff[c], "AAAA") == 0)
			type = (uint16_t) aaaa;
		else
			break;
	}

	switch((DnsType) type)
	{
		case a:
			readReg(nf2, ars_addr, &reg_val);
			if(ntohl(reg_val) == '\0')
				writeReg(nf2, ars_addr, htonl(*next_avail));
			else
			{
				do
				{
					ars_addr = ntohl(reg_val);
					readReg(nf2, ars_addr, &reg_val);
					ts = (struct two_sixteens*) &reg_val;
					len = (ntohs(ts->rdlen)/4) + (ntohs(ts->rdlen)%4);
					ars_addr = ars_addr + (sizeof(unsigned)*1) + len;
					readReg(nf2, ars_addr, &reg_val);
				} while(ntohl(reg_val) != '\0');
				writeReg(nf2, ars_addr, htonl(*next_avail));
			}
			ars              =	(A *) malloc(sizeof(A));
			if(inet_pton(AF_INET, buff[c], &ars->address) == 1);
			else
				printf("\n\nERROR\t%s\n\n", buff[c]);
			ars->rclass      =	class;
			ars->ttl         =	ttl;
			ars->rdlen       =	sizeof(IPV4BYTESZ);
			ars->anxt        =	NULL;
			temp_val         =	(unsigned) htons(ars->rclass) <<16|htons(ars->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(ars->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(ars->address));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(ars);
			break;
		case ns:
			readReg(nf2, nsrs_addr, &reg_val);
			if(ntohl(reg_val) == '\0')
				writeReg(nf2, nsrs_addr, htonl(*next_avail));
			else
			{
				do
				{
					nsrs_addr = ntohl(reg_val);
					readReg(nf2, nsrs_addr, &reg_val);
					ts = (struct two_sixteens*) &reg_val;
					len = (ntohs(ts->rdlen)/4) + (ntohs(ts->rdlen)%4);
					nsrs_addr = nsrs_addr + (sizeof(unsigned)*1) + len;
					readReg(nf2, nsrs_addr, &reg_val);
				} while(ntohl(reg_val) != '\0');
				writeReg(nf2, nsrs_addr, htonl(*next_avail));
			}
			nsrs             =	(NS *) malloc(sizeof(NS));
			memcpy(nsrs->nsdname, buff[c], strlen(buff[c]));
			nsrs->rclass     =	class;
			nsrs->ttl        =	ttl;
			nsrs->rdlen      =	strlen(nsrs->nsdname) + 1;
			nsrs->nsnxt      =	NULL;
			temp_val         =	(unsigned) htons(nsrs->rclass) <<16|htons(nsrs->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(nsrs->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(nsrs->nsdname); i+=4)
			{
				if(strlen(nsrs->nsdname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|nsrs->nsdname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(nsrs->nsdname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |nsrs->nsdname[i+1] <<16
							     |nsrs->nsdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(nsrs->nsdname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |nsrs->nsdname[i+2] <<16
							     |nsrs->nsdname[i+1] <<8
							     |nsrs->nsdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &nsrs->nsdname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(nsrs);
			break;
		case cname:
			readReg(nf2, cnamers_addr, &reg_val);
			if(ntohl(reg_val) == '\0')
			{
				printf("ERROR MULTIPLE CNAMEs!?!\n");
				return;
			}
			else
				writeReg(nf2, cnamers_addr, htonl(*next_avail));
			cnamers          =	(CNAME *) malloc(sizeof(CNAME));
			memcpy(cnamers->cname, buff[c], strlen(buff[c]));
			cnamers->rclass  =	class;
			cnamers->ttl     =	ttl;
			cnamers->rdlen   = 	strlen(cnamers->cname) + 1;
			temp_val         =	(unsigned) htons(cnamers->rclass) <<16|htons(cnamers->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(cnamers->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(cnamers->cname); i+=4)
			{
				if(strlen(cnamers->cname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|cnamers->cname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(cnamers->cname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |cnamers->cname[i+1] <<16
							     |cnamers->cname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(cnamers->cname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |cnamers->cname[i+2] <<16
							     |cnamers->cname[i+1] <<8
							     |cnamers->cname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &cnamers->cname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			free(cnamers);
			break;
		case soa:
			readReg(nf2, soars_addr, &reg_val);
			if(ntohl(reg_val) == '\0')
			{
				printf("ERROR TWO SOAs!?!\n");
				return;
			}
			else
				writeReg(nf2, soars_addr, htonl(*next_avail));
			soars            =	(SOA *) malloc(sizeof(SOA));
			memcpy(soars->mname, buff[c],   strlen(buff[c]));
			memcpy(soars->rname, buff[c+1], strlen(buff[c+1]));
			soars->serial    =	(uint32_t) atoi(buff[c+2]);
			soars->refresh   =	(int32_t)  atoi(buff[c+3]);
			soars->retry     =	(int32_t)  atoi(buff[c+4]);
			soars->expire    =	(int32_t)  atoi(buff[c+5]);
			soars->minimum   =	(uint32_t) atoi(buff[c+6]);
			soars->rclass    =	class;
			soars->rdlen     =	strlen(soars->mname) + 1 +
							strlen(soars->rname) + 1 +
							sizeof(soars->serial) +
							sizeof(soars->refresh) +
							sizeof(soars->expire) +
							sizeof(soars->minimum);
			(*ttlMin)        =	(uint32_t) atoi(buff[c+6]);
			(*rclass)        =	class;
			temp_val         =	(unsigned) htons(soars->rclass) <<16|htons(soars->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			//writeReg(nf2, *next_avail, (unsigned) htonl(soars->ttl));
			//*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->serial));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->refresh));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->retry));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->expire));
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(soars->minimum));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(soars->mname); i+=4)
			{
				if(strlen(soars->mname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|soars->mname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->mname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->mname[i+1] <<16
							     |soars->mname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->mname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->mname[i+2] <<16
							     |soars->mname[i+1] <<8
							     |soars->mname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &soars->mname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			for(i = 0; i <= strlen(soars->rname); i+=4)
			{
				if(strlen(soars->rname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|soars->rname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->rname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->rname[i+1] <<16
							     |soars->rname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(soars->rname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |soars->rname[i+2] <<16
							     |soars->rname[i+1] <<8
							     |soars->rname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &soars->rname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			free(soars);
			break;
		case ptr:
			readReg(nf2, ptrrs_addr, &reg_val);
			if(ntohl(reg_val) == '\0')
			{
				printf("ERROR extra PTR\n");
				return;
			}
			else
				writeReg(nf2, ptrrs_addr, htonl(*next_avail));
			ptrrs            =	(PTR *) malloc(sizeof(PTR));
			memcpy(ptrrs->ptrdname, buff[c], strlen(buff[c]));
			ptrrs->rclass    =	class;
			ptrrs->ttl       =	ttl;
			ptrrs->rdlen     =	strlen(ptrrs->ptrdname) + 1;
			temp_val         =	(unsigned) htons(ptrrs->rclass) <<16|htons(ptrrs->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(ptrrs->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			for(i = 0; i <= strlen(ptrrs->ptrdname); i+=4)
			{
				if(strlen(ptrrs->ptrdname)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|ptrrs->ptrdname[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(ptrrs->ptrdname)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |ptrrs->ptrdname[i+1] <<16
							     |ptrrs->ptrdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(ptrrs->ptrdname)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |ptrrs->ptrdname[i+2] <<16
							     |ptrrs->ptrdname[i+1] <<8
							     |ptrrs->ptrdname[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &ptrrs->ptrdname[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			free(ptrrs);
			break;
		case mx:
			readReg(nf2, mxrs_addr, &reg_val);
			if(ntohl(reg_val) == '\0')
				writeReg(nf2, mxrs_addr, htonl(*next_avail));
			else
			{
				do
				{
					mxrs_addr = ntohl(reg_val);
					readReg(nf2, mxrs_addr, &reg_val);
					ts = (struct two_sixteens*) &reg_val;
					len = (ntohs(ts->rdlen)/4) + (ntohs(ts->rdlen)%4);
					mxrs_addr = mxrs_addr + (sizeof(unsigned)*1) + len;
					readReg(nf2, mxrs_addr, &reg_val);
				} while(ntohl(reg_val) != '\0');
				writeReg(nf2, mxrs_addr, htonl(*next_avail));
			}
			mxrs             =	(MX *) malloc(sizeof(MX));
			mxrs->preference =	(uint16_t) atoi(buff[c]);
			memcpy(mxrs->exchange, buff[c+1], strlen(buff[c+1]));
			mxrs->rclass     =	class;
			mxrs->ttl        =	ttl;
			mxrs->rdlen      = 	sizeof(mxrs->preference) +
							strlen(mxrs->exchange) + 1;
			mxrs->mxnxt      =	NULL;
			temp_val         =	(unsigned) htons(mxrs->rclass) <<16|htons(mxrs->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			writeReg(nf2, *next_avail, (unsigned) htonl(mxrs->ttl));
			temp_val         =	(unsigned) 0 <<16|htons(mxrs->preference);
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			for(i = 0; i <= strlen(mxrs->exchange); i+=4)
			{
				if(strlen(mxrs->exchange)-i == 1)
				{
					//Padd
					temp_val = (unsigned) 0 <<24|mxrs->exchange[i];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(mxrs->exchange)-i == 2)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |mxrs->exchange[i+1] <<16
							     |mxrs->exchange[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else if(strlen(mxrs->exchange)-i == 3)
				{
					//Padd
					temp_val = (unsigned) 0 <<24
							     |mxrs->exchange[i+2] <<16
							     |mxrs->exchange[i+1] <<8
							     |mxrs->exchange[i+0];
					writeReg(nf2, *next_avail, temp_val);
				}
				else
				{
					memcpy(&temp_val, &mxrs->exchange[i], sizeof(unsigned));
					writeReg(nf2, *next_avail, temp_val);
				}
				*next_avail      = *next_avail + sizeof(unsigned);
			}
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(mxrs);
			break;
		case aaaa:
			readReg(nf2, aaaars_addr, &reg_val);
			if(ntohl(reg_val) == '\0')
				writeReg(nf2, aaaars_addr, htonl(*next_avail));
			else
			{
				do
				{
					aaaars_addr = ntohl(reg_val);
					readReg(nf2, aaaars_addr, &reg_val);
					ts = (struct two_sixteens*) &reg_val;
					len = (ntohs(ts->rdlen)/4) + (ntohs(ts->rdlen)%4);
					aaaars_addr = aaaars_addr + (sizeof(unsigned)*1) + len;
					readReg(nf2, aaaars_addr, &reg_val);
				} while(ntohl(reg_val) != '\0');
				writeReg(nf2, aaaars_addr, htonl(*next_avail));
			}
			aaaars           =	(AAAA *) malloc(sizeof(AAAA));
			if(inet_pton(AF_INET6, buff[c], &aaaars->address) == 1);
			else
				printf("\n\nERROR\n\n");
			aaaars->rclass   =	class;
			aaaars->ttl      =	ttl;
			aaaars->rdlen    = 	sizeof(IPV6BYTESZ);
			aaaars->aaaanxt  =	NULL;
			temp_val         =	(unsigned) htons(aaaars->rclass) <<16|htons(aaaars->rdlen);
			writeReg(nf2, *next_avail, temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) htonl(aaaars->ttl));
			*next_avail      = *next_avail + sizeof(unsigned);
			memcpy(&ipv6_addr, &aaaars->address, sizeof(aaaars->address)); 
			temp_val         =	(unsigned) ipv6_addr[3] <<24
							  |ipv6_addr[2] <<16
							  |ipv6_addr[1] <<8
							  |ipv6_addr[0];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			temp_val         =	(unsigned) ipv6_addr[7] <<24
							  |ipv6_addr[6] <<16
							  |ipv6_addr[5] <<8
							  |ipv6_addr[4];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			temp_val         =	(unsigned) ipv6_addr[11]  <<24
							  |ipv6_addr[10]  <<16
							  |ipv6_addr[9]   <<8
							  |ipv6_addr[8];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			temp_val         =	(unsigned) ipv6_addr[15] <<24
							  |ipv6_addr[14] <<16
							  |ipv6_addr[13] <<8
							  |ipv6_addr[12];
			writeReg(nf2, *next_avail, (unsigned) temp_val);
			*next_avail      = *next_avail + sizeof(unsigned);
			writeReg(nf2, *next_avail, (unsigned) '\0');
			*next_avail      = *next_avail + sizeof(unsigned);
			free(aaaars);
			break;
		default:
			return;
			break;
	}
	return;
}

/* F(X) TO CREATE A NODE IN TRIE */
void createNode(struct nf2device *nf2, unsigned *cur_pos, unsigned *next_avail, char k, int state)
{
	unsigned cur_snt_addr;
	unsigned cur_cdn_addr;
	unsigned new_val_addr;
	unsigned new_par_addr;
	unsigned new_snt_addr;
	unsigned new_spv_addr;
	unsigned new_cdn_addr;
	unsigned new_next_avail;

	cur_snt_addr = *cur_pos + (sizeof(unsigned) * 3);
	cur_cdn_addr = *cur_pos + (sizeof(unsigned) * 5);

	new_val_addr = *next_avail + (sizeof(unsigned) * 1);
	new_par_addr = *next_avail + (sizeof(unsigned) * 2); 
	new_snt_addr = *next_avail + (sizeof(unsigned) * 3); 
	new_spv_addr = *next_avail + (sizeof(unsigned) * 4); 
	new_cdn_addr = *next_avail + (sizeof(unsigned) * 5);

	if(state == 0)
	{
		writeReg(nf2, cur_cdn_addr, (unsigned) '\0');
		writeReg(nf2, new_par_addr, (unsigned) '\0');
		writeReg(nf2, new_snt_addr, (unsigned) '\0');
		writeReg(nf2, new_spv_addr, (unsigned) '\0');
		writeReg(nf2, new_cdn_addr, (unsigned) '\0');
	}
	else if(state == 1)
	{
		writeReg(nf2, cur_cdn_addr, htonl(*next_avail));
		writeReg(nf2, new_par_addr, htonl(*cur_pos));
		writeReg(nf2, new_snt_addr, (unsigned) '\0');
		writeReg(nf2, new_spv_addr, (unsigned) '\0');
		writeReg(nf2, new_cdn_addr, (unsigned) '\0');
	}
	else if(state == 2)
	{
		writeReg(nf2, cur_snt_addr, htonl(*next_avail));
		writeReg(nf2, new_par_addr, (unsigned) '\0');
		writeReg(nf2, new_snt_addr, (unsigned) '\0');
		writeReg(nf2, new_spv_addr, htonl(*cur_pos));
		writeReg(nf2, new_cdn_addr, (unsigned) '\0');
 	}
	else
		return;

	writeReg(nf2, *next_avail, (unsigned) 0 <<24|k);
	writeReg(nf2, new_val_addr, (unsigned) '\0');

	new_next_avail = *next_avail + (sizeof(unsigned) * 6); 
	*cur_pos = *next_avail;
	*next_avail = new_next_avail;
	return;
}

/* F(X) TO ADD TO TRIE */
void addTrie(struct nf2device *nf2, unsigned root_addr, unsigned *next_avail, char *name, char *rec, uint32_t *ttlMin, uint16_t *rclass)
{
	unsigned cur_pos;
	unsigned cur_sbn;
	unsigned cur_chd;
	unsigned reg_val;
	unsigned *child;
	unsigned *sibling;
	char cur_key[4];
	int i = 0;
	int stl;

	stl = strlen(name);
	cur_pos = root_addr;
	cur_sbn = root_addr + (sizeof(unsigned) * 3);
	cur_chd = root_addr + (sizeof(unsigned) * 5);

	if(root_addr == *next_avail)
	{
		//create root node
		//createNode(nf2, &root_addr, next_avail, '*', 0);
		createNode(nf2, &cur_pos, next_avail, '*', 0);
		for(i = 0; i <= stl; i++)
		{
			if(name[i+1] == '\0')
			{
				//create node case 1
				//create RR 
				createNode(nf2, &cur_pos, next_avail, name[i], 1);
				createResRec(nf2, &cur_pos, next_avail, rec, ttlMin, rclass);
			}
			else
			{
				//create node
				createNode(nf2, &cur_pos, next_avail, name[i], 1);
			}
		}
	}
	else
	{
		//child
		readReg(nf2, cur_chd, &reg_val);
		cur_pos = ntohl(reg_val); 
		//get key
		readReg(nf2, cur_pos, &reg_val);
		memcpy(&cur_key, &reg_val, sizeof(unsigned));
		//get child address
		readReg(nf2, cur_pos + (sizeof(unsigned) * 5), &reg_val);
		cur_chd = ntohl(reg_val);
		child   = (unsigned *) cur_chd;
		//get sibling address
		readReg(nf2, cur_pos + (sizeof(unsigned) * 3), &reg_val);
		cur_sbn = ntohl(reg_val);
		sibling = (unsigned *) cur_sbn;
		while(name[i] != '\0')
		{
			if(cur_key[0] == name[i])
			{
				if((name[i+1] != '\0') && (child != NULL))
				{
					//child
					readReg(nf2, cur_chd, &reg_val);
					cur_pos = ntohl(reg_val);
					//get key
					readReg(nf2, cur_pos, &reg_val);
					memcpy(&cur_key, &reg_val, sizeof(unsigned));
					//get child address
					readReg(nf2, cur_pos + (sizeof(unsigned) * 5), &reg_val);
					cur_chd = ntohl(reg_val);
					child   = (unsigned *) cur_chd;
					//get sibling address
					readReg(nf2, cur_pos + (sizeof(unsigned) * 3), &reg_val);
					cur_sbn = ntohl(reg_val);
					sibling = (unsigned *) cur_sbn;
					i++;
				}
				else if(name[i+1] == '\0')
				{
					//add the rr to plc
					addResRec(nf2, &cur_pos, next_avail, rec, ttlMin, rclass);
					i++;
				}
				else
				{
					printf("Should never be here\n");
				}
			}
			else if(sibling != NULL)
			{
				//sibling
				readReg(nf2, cur_sbn, &reg_val);
				cur_pos = ntohl(reg_val); 
				//get key
				readReg(nf2, cur_pos, &reg_val);
				memcpy(&cur_key, &reg_val, sizeof(unsigned));
				//get child address
				readReg(nf2, cur_pos + (sizeof(unsigned) * 5), &reg_val);
				cur_chd = ntohl(reg_val);
				child   = (unsigned *) cur_chd;
				//get sibling address
				readReg(nf2, cur_pos + (sizeof(unsigned) * 3), &reg_val);
				cur_sbn = ntohl(reg_val);
				sibling = (unsigned *) cur_sbn;
				//plc = plc->snt;
			}
			else
			{
				if(name[i+1] != '\0')
				{
					//add trie plc->snt then point pls->snt->spv then put rest
					//of the string down
					//sibling
					//create node case 2
					createNode(nf2, &cur_pos, next_avail, name[i], 2);
					i++;
					//add trie plc->cdn until string done
					while(name[i+1] != '\0')
					{
						//create node case 1
						createNode(nf2, &cur_pos, next_avail, name[i], 1);
						i++;
					}
					//create node case 1
					//create RR
					createNode(nf2, &cur_pos, next_avail, name[i], 1);
					createResRec(nf2, &cur_pos, next_avail, rec, ttlMin, rclass);
					i++;
					//create node case 1
					createNode(nf2, &cur_pos, next_avail, name[i], 1);
				}
				else
				{
					//create node case 2
					//create RR
					createNode(nf2, &cur_pos, next_avail, name[i], 2);
					createResRec(nf2, &cur_pos, next_avail, rec, ttlMin, rclass);
					i++;
					//create node case 1
					createNode(nf2, &cur_pos, next_avail, name[i], 1);
				}
			}
		}
	}
	return;
}

/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
void readZone(struct nf2device *nf2, char *fn)
{
	FILE *fp;
	char buff;
	char domNme[DNM_SZ];
	char domNme2[DNM_SZ];
	char rR[LNE_SZ];
	char rR2[LNE_SZ];
	int i;
	uint32_t dTtl = 0; //default ttl gets redefined by SOA
	uint16_t dClass = 0; //default class gets redefined by SOA
	unsigned root;
	unsigned next_avail;

	root       = BASE_MASK;
	next_avail = BASE_MASK;
	printf("Address of ROOT: %X \n\n", root);

	if((fp = fopen(fn, "r")) == NULL)
	{
		printf("Error: can't open the file %s\n", fn);
		return;
	}

	while(!feof(fp))
	{
		buff = fgetc(fp);
		if(buff == EOF)
			break;

		// If line is a comment then ignore it
		else if(buff == ';')
		{
			while(buff != '\n' && buff != EOF)
				buff = fgetc(fp);
		}

		// Read in Domain Name
		if(buff != '\t' && buff != ' ' && buff != '\n')
		{
			i = 0;
			strcpy(domNme,"");
			while(buff != ';' && buff != '(' && buff != '\t' && buff != ' ' && buff != EOF)
			{
				domNme[i] = buff;
				i++;
				buff = fgetc(fp);
			}
			domNme[i] = '\0';
			strcpy(domNme2, domNme);
			revDN(domNme);
		}

		// Read in Resource Record
		strcpy(rR2,"");
		while(buff != '\n' && buff != EOF)
		{
			if(buff == ';' || buff == '(');
			else
				buff = fgetc(fp);
			// Reached the beginning of a comment therefore ignore ignore the rest of the line
			if(buff == ';')
			{
				while(buff != '\n' && buff != EOF)
					buff = fgetc(fp);
			}
			// Reached the beginning of a multilined statement, this usually is with the SOA
			else if(buff == '(')
			{
				while(buff != ')')
				{
					// Reached the beginning of a comment so we can ignore the rest of the line
					if(buff == ';')
					{
						while(buff != '\n' && buff != EOF)
							buff = fgetc(fp);
					}
					buff = fgetc(fp);
					i = 0;
					strcpy(rR, "");
					while(buff != ';' && buff != ')' && buff != '\t' && buff != ' ' && buff != '\n' && buff != EOF)
					{
						rR[i] = buff;
						i++;
						buff = fgetc(fp);
					}
					rR[i] = '\0';
					if(strcmp(rR, "") != 0)
					{
						strcat(rR2, rR);
						strcat(rR2, ",");
					}
				}
			}
			else
			{
				i = 0;
				strcpy(rR, "");
				while(buff != ';' && buff != '(' && buff != '\t' && buff != ' ' && buff != '\n' && buff != EOF)
				{
					rR[i] = buff;
					i++;
					buff = fgetc(fp);
				}
				rR[i] = '\0';
				if(strcmp(rR, "" ) != 0)
				{
					strcat(rR2, rR);
					strcat(rR2, ",");
				}
			}
		}
		//This is where we call to make trie but before do we need to put the chars into RR's?
		if(strcmp(rR2, "") != 0)
			if(checkDN(domNme2) == 0)
				addTrie(nf2, root, &next_avail, domNme, rR2, &dTtl, &dClass);
		//{
			//rrs = createResRec(rR2, &dTtl, &dClass);
			//if(rrs != NULL)
			//{
			//	if(rrs->ptrrs != NULL)
			//		addTrie(root, domNme, rrs);
			//	else if(checkDN(domNme2) == 0)
			//		addTrie(root, domNme, rrs);
			//}
		//}

	}

	fclose(fp);
	return;
}

/* F(X) TO CHECK DOMAIN NAME DOESN'T CONTAIN INVALID CHARACTERS */
uint16_t checkDN(char *domName)
//int checkDN(char *domName)
{
	int i;
	int sz;
	int de = 0;

	sz = strlen(domName);
	for(i = 0; i < sz; i++)
	{
		if(de > 63)
			return (uint16_t) 1;
		else if((i == 0) || (de == 0))
		{
			if((isdigit(domName[i]) == 0) || (domName[i] == '-'))
				return (uint16_t) 1;
			else if((isalpha(domName[i]) == 0) || (domName[i] == '-'))
				de++;
			else if(domName[i] == '.')
			{
				if((i == 0) && (sz > 1))
					return (uint16_t) 1;
				else
					de = 0;
			}
			else
				return (uint16_t) 1;
		}
		else if((isalnum(domName[i]) == 0) || (domName[i] == '-'))
			de++;
		else if(domName[i] == '.')
			de = 0;
		else
			return (uint16_t) 1;
	}
	return (uint16_t) 0;
}

/*F(X) TO MAKE DOMAIN NAME UPPER FOR COMPARISON AND APPENDS A '.' IF NOT AT THE END*/
void uDN(char *dom)
{
	int i;
	char *u = (char *) malloc(sizeof(char) * strlen(dom) + 1);

	for(i = 0; i <= strlen(dom); i++)
		u[i] = toupper(dom[i]);

	if(dom[strlen(dom)-1] != '.' && dom[0] != '@')
	{
		u[strlen(dom)] = '.';
		u[strlen(dom)+1] = '\0';
	}

	strcpy(dom, u);

	return;
}

/* F(X) TO REVERSE DOMAIN NAME */
int revDN(char *DN)
{
	int i = 0;
	int sz = 0;
	int seg = 0;
	char tmp[DNM_SZ] = "";
	char last = DN[strlen(DN) - 1];

	if (strcmp(DN, "") == 0)
		return 1;
	else if(strcmp(DN, ".") == 0)
		return 0;
	// Count number of delimiters
	for(i=0; i <= strlen(DN); i++)
	{
		if(DN[i] == '.')
			seg++;
	}
	// Allocate 2d array
	char **label = (char**) malloc(seg * sizeof (char*));
	// Variable for the current label
	char *curLabel = strtok(DN, ".");

	for(i = 0; curLabel != NULL; i++)
	{
		label[i] = malloc(strlen(curLabel)*sizeof(char));
		//label[i] = strdup(curLabel);
		memcpy(label[i], curLabel, strlen(curLabel));
		curLabel = strtok(NULL, ".");
	}
	// Reverse domain name
	sz = i-1;
	if(last == '.')
		strcat(tmp, ".");
	for(i = sz; i >= 0; i--)
	{
		if(i != sz)
			strcat(tmp, ".");
		strcat(tmp, label[i]);
	}
	// Deallocate 2d array
	for(i = 0; i < seg; i++)
		free(label[i]);
	free(label);
	// Put the reversed domain name back into the variable passed in
	strcpy(DN, tmp);

	return 0;
}
