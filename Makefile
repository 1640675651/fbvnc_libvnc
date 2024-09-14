CC = cc
CFLAGS = -Wall -O2
LDFLAGS = -lvncclient

OBJS = fbvnc.o draw.o

all: fbvnc
.c.o:
	$(CC) -c $(CFLAGS) $<
fbvnc: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
clean:
	rm -f *.o fbvnc
