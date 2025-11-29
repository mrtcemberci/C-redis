CC = gcc
CFLAGS = -Wall -Werror -O3
LDFLAGS = -pthread

all: throughput latency

throughput: throughput.c
	$(CC) $(CFLAGS) throughput.c -o throughput $(LDFLAGS)

latency: latency.c
	$(CC) $(CFLAGS) latency.c -o latency $(LDFLAGS)

.PHONY: clean
clean:
	rm -f throughput latency *.o