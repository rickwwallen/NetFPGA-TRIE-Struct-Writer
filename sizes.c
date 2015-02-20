#include "dns_netfpga.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define DEFAULT_IFACE	"nf2c0"
#define BASE_MASK 0x4000000

int main()
{
	printf("char:%d\n", sizeof(char));
	printf("unsigned:%d\n", sizeof(unsigned));
	printf("rr*:%d\n", sizeof(struct rr*));
	printf("Trie*:%d\n", sizeof(struct trieptr*));
	printf("Trie:%d\n", sizeof(Trie));
	printf("Trie:%d\n", sizeof(Trie));
	printf("arec:%d\n", sizeof(struct arec));                                                  
	printf("nsrec:%d\n", sizeof(struct nsrec));                                                 
	printf("cnamerec:%d\n", sizeof(struct cnamerec));                                              
	printf("ptrrec:%d\n", sizeof(struct ptrrec));                                                
	printf("mxrec:%d\n", sizeof(struct mxrec));                                                 
	printf("aaaarec:%d\n", sizeof(struct aaaarec));
	printf("soarec:%d\n", sizeof(struct soarec)); 
	return 0;
}
