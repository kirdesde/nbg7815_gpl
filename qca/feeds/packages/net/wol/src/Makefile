all: wolipq

wolipq: wolipq.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) wolipq.c -lnetfilter_queue -lnfnetlink
clear:
	rm -f *.o wolipq
