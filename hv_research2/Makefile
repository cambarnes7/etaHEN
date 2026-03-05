#
# PS5 Offset Discovery Tool (hv_research2) - Makefile
#
# Build: make
# Send:  make test PS5_HOST=<your_ps5_ip>
# Clean: make clean
#

PS5_HOST ?= ps5
PS5_PORT ?= 9021

PS5_PAYLOAD_SDK ?= /home/user/etaHEN/ps5-payload-sdk/installed

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := hv_research2.elf

CFLAGS := -Wall -Werror -Wno-unused-function -O1

all: kmod $(ELF)

kmod:
	$(MAKE) -C kmod

$(ELF): main.c kmod/hv_kmod.ko
	$(CC) $(CFLAGS) -o $@ main.c -lSceSystemService

kmod/hv_kmod.ko: kmod
	@true

clean:
	rm -f $(ELF)
	$(MAKE) -C kmod clean

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

.PHONY: all kmod clean test
