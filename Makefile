#
# 
#

CFLAGS = -m32 -g -Wall
#CFLAGS = -g -Wall
CC = gcc

# Location of binary files
BINDIR ?= /usr/local/bin

# Location of common files
COMMON = common/

all : common my_zone_read

my_zone_read : my_zone_read.o common/nf2util.o 
	$(CC) $(CFLAGS) my_zone_read.o common/nf2util.o -o my_zone_read

common:
	$(MAKE) -C $(COMMON)

clean :
	rm -rf my_zone_read *.o

install: my_zone_read
	install my_zone_read $(BINDIR)

.PHONY: all clean install

