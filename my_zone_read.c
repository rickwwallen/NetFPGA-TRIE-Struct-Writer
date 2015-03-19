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
 * *		-Pulled readZone from triez_zone_read.c
 * */
/**********************************************************************/
#include "dns_zone_read.h"

//FILE * f_in = NULL;
void writeRegisters(int,char**);

int main(int argc, char *argv[])
{

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

	printf("Start to store the nodes in DRAM\n\n");
	readZone(&nf2, argv[1]);

	closeDescriptor(&nf2);
	
	return 0;
}
