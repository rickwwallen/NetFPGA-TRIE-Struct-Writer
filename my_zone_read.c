/*
 * * FILE NAME:		my_zone_read.c
 * * READS ZONE FILE AND PLACES ON NETFPGA MEMORY DRAM?
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	JANUARY.21.2015
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
 * *	January.21.2015-Initial create
 * *		-Pulled readZone from triez_netfpga.c
 * */
/**********************************************************************/
#include "dns_netfpga.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <net/if.h>
#include <stdio.h>
#include "common/nf2.h"
#include "common/nf2util.h"

#define DEFAULT_IFACE	"nf2c0"
#define BASE_MASK 0x4000000

static struct nf2device nf2;

FILE * f_in = NULL;

void writeRegisters(int,char**);

/* F(X) TO CREATE A RESOUCE RECORD */
RR *createResRec(char *rec, uint32_t *ttlMin, uint16_t *rclass)
{
	int i, seg, c;
	uint32_t ttl;
	uint16_t class;
	uint16_t type;

	RR	*resrec;
	resrec = (RR *) malloc(sizeof(RR));

	resrec->ars	= NULL;
	resrec->nsrs	= NULL;
	resrec->cnamers	= NULL;
	resrec->ptrrs	= NULL;
	resrec->mxrs	= NULL;
	resrec->aaaars	= NULL;
	resrec->soars	= NULL;

	// default TTL to 1 day will be overwritten by default value anyways
	ttl = 86400;
	i = 0;
	seg = 0;
	class = 0;
	type = 0;

	if(strcmp(rec, "") == 0)
		return NULL;
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
		//buff[i] = strdup(buff2);
		memcpy(buff[i], buff2, strlen(buff2));
		buff2 = strtok(NULL, ",");
	}

	class = *rclass;

	if((seg-1 == 2 && strcmp(buff[0],"MX") != 0) || (seg-1 == 3 && strcmp(buff[0],"MX") == 0))
	{
		if(myisdigit(buff[0][0]))
		{
			ttl =(uint32_t) atoi(buff[0]);
			c = 1;
		}
		else
			c = 0;
	}
	else if((seg-1 == 3 && strcmp(buff[1],"MX") != 0) || (seg-1 == 4 && strcmp(buff[1],"MX") == 0))
	{
		if(myisdigit(buff[0][0]))
			ttl =(uint32_t) atoi(buff[0]);
		c = 1;
	}
	else
	{
		ttl = *ttlMin;
		c = 0;
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
			resrec->ars =		(A *) malloc(sizeof(A));
			if(inet_pton(AF_INET, buff[c], &resrec->ars->address) == 1);
			//if(my_inet_pton(AF_INET, buff[c], &resrec->ars->address) == 1);
			else
				//log("\n\nERROR\t%s\n\n", buff[c]);
			//resrec->ars->address =		strdup(buff[c]);
			resrec->ars->rclass =		class;
			resrec->ars->ttl =		ttl;
			resrec->ars->rdlen = 		sizeof(IPV4BYTESZ);
			//resrec->ars->rdlen = 		strlen(resrec->ars->address) +
			//				1;
			resrec->ars->anxt =		NULL;
			break;
		case ns:
			resrec->nsrs =		(NS *) malloc(sizeof(NS));
			//resrec->nsrs->nsdname =		strdup(buff[c]);
			memcpy(resrec->nsrs->nsdname, buff[c], strlen(buff[c]));
			resrec->nsrs->rclass =		class;
			resrec->nsrs->ttl =		ttl;
			resrec->nsrs->rdlen = 		strlen(resrec->nsrs->nsdname) + 1;
			resrec->nsrs->nsnxt =		NULL;
			break;
		case cname:
			resrec->cnamers =		(CNAME *) malloc(sizeof(CNAME));
			//resrec->cnamers->cname =	strdup(buff[c]);
			memcpy(resrec->cnamers->cname, buff[c], strlen(buff[c]));
			resrec->cnamers->rclass =	class;
			resrec->cnamers->ttl =		ttl;
			resrec->cnamers->rdlen = 	strlen(resrec->cnamers->cname) + 1;
			break;
		case soa:
			resrec->soars =			(SOA *) malloc(sizeof(SOA));
			//resrec->soars->mname =		strdup(buff[c]);
			//resrec->soars->rname =		strdup(buff[c+1]);
			memcpy(resrec->soars->mname, buff[c], strlen(buff[c]));
			memcpy(resrec->soars->rname, buff[c+1], strlen(buff[c+1]));
			resrec->soars->serial =		(uint32_t) atoi(buff[c+2]);
			resrec->soars->refresh =	(int32_t) atoi(buff[c+3]);
			resrec->soars->retry =		(int32_t) atoi(buff[c+4]);
			resrec->soars->expire =		(int32_t) atoi(buff[c+5]);
			resrec->soars->minimum =	(uint32_t) atoi(buff[c+6]);
			resrec->soars->rclass =		class;
			resrec->soars->rdlen =		strlen(resrec->soars->mname) + 1 +
							strlen(resrec->soars->rname) + 1 +
							sizeof(resrec->soars->serial) +
							sizeof(resrec->soars->refresh) +
							sizeof(resrec->soars->expire) +
							sizeof(resrec->soars->minimum);
			(*ttlMin) = (uint32_t) atoi(buff[c+6]);
			(*rclass) = class;
			break;
		case ptr:
			resrec->ptrrs =			(PTR *) malloc(sizeof(PTR));
			//resrec->ptrrs->ptrdname =	strdup(buff[c]);
			memcpy(resrec->ptrrs->ptrdname, buff[c], strlen(buff[c]));
			resrec->ptrrs->rclass =		class;
			resrec->ptrrs->ttl =		ttl;
			resrec->ptrrs->rdlen = 		strlen(resrec->ptrrs->ptrdname) + 1;
			break;
		case mx:
			resrec->mxrs =			(MX *) malloc(sizeof(MX));
			resrec->mxrs->preference =	(uint16_t) atoi(buff[c]);
			//resrec->mxrs->exchange =	strdup(buff[c+1]);
			memcpy(resrec->mxrs->exchange, buff[c+1], strlen(buff[c+1]));
			resrec->mxrs->rclass =		class;
			resrec->mxrs->ttl =		ttl;
			resrec->mxrs->rdlen = 		sizeof(resrec->mxrs->preference) +
							strlen(resrec->mxrs->exchange) + 1;
			resrec->mxrs->mxnxt =		NULL;
			break;
		case aaaa:
			resrec->aaaars =		(AAAA *) malloc(sizeof(AAAA));
			if(inet_pton(AF_INET6, buff[c], &resrec->aaaars->address) == 1);
			//if(my_inet_pton(AF_INET6, buff[c], &resrec->aaaars->address) == 1);
			else
				//log("\n\nERROR\n\n");
			//resrec->aaaars->address =	strdup(buff[c]);
			resrec->aaaars->rclass =	class;
			resrec->aaaars->ttl =		ttl;
			resrec->aaaars->rdlen = 	sizeof(IPV6BYTESZ);
			//resrec->aaaars->rdlen = 	strlen(resrec->aaaars->address) +
			//				1;
			resrec->aaaars->aaaanxt = NULL;
			break;
		default:
			return NULL;
			break;
	}

	return resrec;
}

/* F(X) TO CREATE A NODE IN TRIE */
Trie *createNode(char k, RR *v)
{
	Trie *node;
	node = (Trie *) malloc(sizeof(Trie));

	RR      *resrec;

	node->key = k;
	node->par = NULL;
	node->snt = NULL;
	node->spv = NULL;
	node->cdn = NULL;
	if(v != NULL)
		node->val = v;
	else
	{
		resrec = (RR *) malloc(sizeof(RR));

		resrec->ars     = NULL;
		resrec->nsrs    = NULL;
		resrec->cnamers = NULL;
		resrec->ptrrs   = NULL;
		resrec->mxrs    = NULL;
		resrec->aaaars  = NULL;
		resrec->soars   = NULL;

		node->val = resrec;
	}

	return node;
}

/* F(X) TO ADD TO TRIE */
void addTrie(Trie *root, char *name, RR *resrec)
{
	Trie *plc = NULL;
	int i = 0;
	int stl;
	struct arec     *aptr;
	struct nsrec    *nsptr;
	struct mxrec    *mxptr;
	struct aaaarec  *aaaaptr;

	stl = strlen(name);
	plc = root;
	if(plc->cdn == NULL)
	{
		for(i = 0; i <= stl; i++)
		{
			if(name[i+1] == '\0')
			{
				plc->cdn = createNode(name[i],resrec);
				plc->cdn->par = plc;
				plc =  plc->cdn;
			}
			else
			{
				plc->cdn = createNode(name[i], NULL);
				plc->cdn->par = plc;
				plc = plc->cdn;
			}
		}
	}
	else
	{
		plc = plc->cdn;
		while(name[i] != '\0')
		{
			if(plc->key == name[i])
			{
				if((name[i+1] != '\0') && (plc->cdn != NULL))
				{
					plc = plc->cdn;
					i++;
				}
				else if(name[i+1] == '\0')
				{
					//add the rr to plc
					if(resrec->ars != NULL)
					{
						aptr = plc->val->ars;
						if(aptr == NULL)
						{
							plc->val->ars = (A *) malloc(sizeof(A));
							plc->val->ars = resrec->ars;
						}
						else
						{
							while(aptr->anxt != NULL)
								aptr = aptr->anxt;
							aptr->anxt = resrec->ars;
						}
					}
					else if(resrec->nsrs != NULL)
					{
						nsptr = plc->val->nsrs;
						if(nsptr == NULL)
						{
							plc->val->nsrs = (NS *) malloc(sizeof(NS));
							plc->val->nsrs = resrec->nsrs;
						}
						else
						{
							while(nsptr->nsnxt != NULL)
								nsptr = nsptr->nsnxt;
							nsptr->nsnxt = resrec->nsrs;
						}
					}
					else if(resrec->cnamers != NULL)
					{
						if(plc->val->cnamers == NULL)
						{
							plc->val->cnamers = (CNAME *) malloc(sizeof(CNAME) + resrec->cnamers->rdlen);
							plc->val->cnamers = resrec->cnamers;
						}
					}
					else if(resrec->ptrrs != NULL)
					{
						if(plc->val->ptrrs == NULL)
						{
							plc->val->ptrrs = (PTR *) malloc(sizeof(PTR) + resrec->ptrrs->rdlen);
							plc->val->ptrrs = resrec->ptrrs;
						}
					}
					else if(resrec->mxrs != NULL)
					{
						mxptr = plc->val->mxrs;
						if(mxptr == NULL)
						{
							plc->val->mxrs = (MX *) malloc(sizeof(MX) + resrec->mxrs->rdlen);
							plc->val->mxrs = resrec->mxrs;
						}
						else
						{
							while(mxptr->mxnxt != NULL)
								mxptr->mxnxt = mxptr->mxnxt;
							mxptr = resrec->mxrs;
						}
					}
					else
					{
						aaaaptr = plc->val->aaaars;
						if(aaaaptr == NULL)
						{
							plc->val->aaaars = (AAAA *) malloc(sizeof(AAAA));
							plc->val->aaaars = resrec->aaaars;
						}
						else
						{
							while(aaaaptr->aaaanxt != NULL)
								aaaaptr = aaaaptr->aaaanxt;
							aaaaptr->aaaanxt = resrec->aaaars;
						}
					}
					i++;
				}
				else
				{
					//log("Should never be here\n");
				}
			}
			else if(plc->snt != NULL)
				plc = plc->snt;
			else
			{
				if(name[i+1] != '\0')
				{
					//add trie plc->snt then point pls->snt->spv then put rest
					//of the string down
					plc->snt = createNode(name[i], NULL);
					plc->snt->spv = plc;
					plc = plc->snt;
					i++;
					//add trie plc->cdn until string done
					while(name[i+1] != '\0')
					{
						plc->cdn = createNode(name[i], NULL);
						plc->cdn->par = plc;
						plc = plc->cdn;
						i++;
					}
					plc->cdn = createNode(name[i], resrec);
					plc->cdn->par = plc;
					plc = plc->cdn;
					i++;
					plc->cdn = createNode(name[i], NULL);
					plc->cdn->par = plc;
					plc = plc->cdn;
				}
				else
				{
					plc->snt = createNode(name[i], resrec);
					plc->snt->spv = plc;
					plc = plc->snt;
					i++;
					plc->cdn = createNode(name[i], NULL);
					plc->cdn->par = plc;
					plc = plc->cdn;
				}
			}
		}
	}
	return;
}

/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
Trie *readZone(char *fn)
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
	RR *rrs;
	Trie *root;

	root = createNode('*',  NULL);

	if((fp = fopen(fn, "r")) == NULL)
		return NULL;

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
		{
			rrs = createResRec(rR2, &dTtl, &dClass);
			if(rrs != NULL)
			{
				if(rrs->ptrrs != NULL)
					addTrie(root, domNme, rrs);
				else if(checkDN(domNme2) == 0)
					addTrie(root, domNme, rrs);
			}
		}

	}

	fclose(fp);
	return root;
}



int main(int argc, char *argv[])
{

	unsigned value;
	unsigned addr;
	nf2.device_name=DEFAULT_IFACE;

	addr = BASE_MASK;
	printf("Address of DRAM: %X \n\n", addr);

	if(argc != 1)
	{	
		printf("usage: %s please, indicate the zone file to load", argv[0]);
		return -1;

	}
	
	if(check_iface(&nf2))
		exit(1);
	if(openDescriptor(&nf2))
		exit(1);

	f_in=fopen(argv[1],"r");

	if (f_in==NULL) 
	{
		printf("Error: can't open the file %s\n", argv[1]);
		exit(1);
	}	
	
	printf("Start to store the nodes in DRAM\n\n");
	while(!feof(f_in)) 
	{
			fscanf(f_in, "%x %x", &addr, &value);
			writeReg(&nf2, addr, value);
			addr=addr+4;
	}

	closeDescriptor(&nf2);
	
	return 0;
}
