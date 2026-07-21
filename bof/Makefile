CFLAGS := -c -Os -fno-asynchronous-unwind-tables -masm=intel \
          -fno-stack-protector -mno-stack-arg-probe -Wall

CC_X64 ?= x86_64-w64-mingw32-gcc
CC_X86 ?= i686-w64-mingw32-gcc

all: get_gdid.x64.o get_gdid.x86.o

get_gdid.x64.o: get_gdid.c beacon.h
	$(CC_X64) $(CFLAGS) $< -o $@

get_gdid.x86.o: get_gdid.c beacon.h
	$(CC_X86) $(CFLAGS) $< -o $@

clean:
	rm -f get_gdid.x64.o get_gdid.x86.o

.PHONY: all clean
