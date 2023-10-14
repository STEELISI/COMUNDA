CFLAGS = -g -fpermissive

PROGS = tag stats

all: $(PROGS)

stats: stats.cc
	g++ -o stats $(CFLAGS) stats.cc -lpcap

tag: tag.cc utils.cc utils.h
	g++ -o tag $(CFLAGS) tag.cc utils.cc

clean:
	-rm -f $(PROGS)
