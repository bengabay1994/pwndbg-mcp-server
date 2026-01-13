CC = gcc
CFLAGS = -g -O0 -fno-stack-protector -no-pie -z execstack
BUILDDIR ?= .

.PHONY: all clean

all: $(BUILDDIR)/simple $(BUILDDIR)/heap_test

$(BUILDDIR)/simple: simple.c
	$(CC) $(CFLAGS) -o $@ $<

$(BUILDDIR)/heap_test: heap_test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BUILDDIR)/simple $(BUILDDIR)/heap_test
