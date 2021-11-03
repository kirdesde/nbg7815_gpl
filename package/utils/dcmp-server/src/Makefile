CC	= gcc
LD  = ld
CFLAG = -DMY_MALLOC -Wall -g -O2 -pthread -DDECOMP_MODULE_RAR5

DECOMP 	= decomp_server
D_OBJS	= decomp_server.o handler_rar.o handler_rar5.o mymalloc.o handler_zip.o \
    zlib/inflate.o zlib/adler32.o zlib/crc32.o zlib/inffast.o zlib/inftrees.o zlib/zutil.o \
    rar/unrar.o rar/unrarfilter.o rar/unrarppm.o rar/unrarvm.o rar/unrarcmd.o \
    rar/unrar20.o rar/unrardata.o rar5/unrar5.o

#-----------------------------------------------------------------------
all:	$(DECOMP)

$(DECOMP):    $(D_OBJS)
	$(CC) $(CFLAG) $(D_OBJS) -o $@
#	$(STRIP) $(DECOMP)

.c.o:
	$(CC) $(CFLAG) -c $? -o $@

# Clean up build products.
clean:
	-@rm -f $(D_OBJS) $(DECOMP) *.bak


