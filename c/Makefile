CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -municode
LDLIBS ?= -ladvapi32 -lncrypt -lbcrypt -liphlpapi
TARGET := get_gdid.exe

$(TARGET): get_gdid.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: clean
