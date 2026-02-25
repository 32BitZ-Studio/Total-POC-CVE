CC ?= gcc
CFLAGS ?= -O2 -fPIC -fsanitize=address
CFLAGS += -D_GNU_SOURCE -fno-strict-aliasing -Wall -Wextra \
					-Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
					-Wdeclaration-after-statement -Wno-missing-field-initializers \
					-Wno-ununsed-function -Wno-unused-parameter

lib = netconsd/ncrx/libncrx.o
recv = netconsd/ncrx/ncrx.o

all: ncrx
ncrx: $(lib) $(recv)
	$(CC) $(CFLAGS) -o $@ $(lib) $(recv)
clean:
	rm $(lib) $(recv) ./ncrx
