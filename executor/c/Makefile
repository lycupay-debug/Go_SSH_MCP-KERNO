CC ?= cc
CFLAGS += -O2 -Wall -Wextra -Wpedantic -D_GNU_SOURCE
CPPFLAGS += -I/usr/local/include -I/usr/local/include/json-c
LDLIBS += -L/usr/local/lib -ljson-c
OUT ?= ../../bin/host-executor

all: $(OUT)

$(OUT): executor.c executor_impl.inc
	mkdir -p ../../bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $(OUT) executor.c $(LDLIBS)

clean:
	rm -f $(OUT)

.PHONY: all clean
