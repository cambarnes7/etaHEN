#
# PS5 Hypervisor Research Tool - Makefile
#
# Build: make           (builds both hv_research.elf and hv_research2.elf)
# Send:  make test PS5_HOST=<your_ps5_ip>
# Clean: make clean
#

PS5_HOST ?= ps5
PS5_PORT ?= 9021

PS5_PAYLOAD_SDK ?= /home/user/ps5-payload-sdk/ps5-payload-sdk

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined. Set it to your ps5-payload-sdk install path)
endif

ELF  := hv_research.elf
ELF2 := hv_research2.elf

CFLAGS := -Wall -Werror -Wno-unused-function -O1

# Build the kernel module first, then both ELFs
all: kmod $(ELF) $(ELF2)

# Build the kernel module (FreeBSD KLD)
kmod:
	$(MAKE) -C kmod

# Build the main payload ELF (embeds kmod/hv_kmod.ko via .incbin)
$(ELF): main.c kmod/hv_kmod.ko
	$(CC) $(CFLAGS) -o $@ main.c -lSceSystemService

# Build doreti_iret discovery tool (standalone, no kmod needed)
$(ELF2): main2.c
	$(CC) $(CFLAGS) -o $@ main2.c -lSceSystemService -lpthread

# Convenience target: ensure kmod .ko exists
kmod/hv_kmod.ko: kmod
	@true

clean:
	rm -f $(ELF) $(ELF2)
	$(MAKE) -C kmod clean

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

test2: $(ELF2)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

.PHONY: all kmod clean test test2
