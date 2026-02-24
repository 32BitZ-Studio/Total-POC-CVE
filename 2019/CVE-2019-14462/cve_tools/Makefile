# CVE Attack Tools Makefile
# For defensive security research only.

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lm

TOOLS = cve_14462_attack cve_20685_attack cve_0367_attack tcp_segmentation_attack latency_benchmark

.PHONY: all clean

all: $(TOOLS)

cve_14462_attack: cve_14462_attack.c
	$(CC) $(CFLAGS) -o $@ $<

cve_20685_attack: cve_20685_attack.c
	$(CC) $(CFLAGS) -o $@ $<

cve_0367_attack: cve_0367_attack.c
	$(CC) $(CFLAGS) -o $@ $<

tcp_segmentation_attack: tcp_segmentation_attack.c
	$(CC) $(CFLAGS) -o $@ $<

latency_benchmark: latency_benchmark.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TOOLS)
