#
# PS5 Hypervisor Research Tool - Makefile
#
# Build: make
# Send:  make test PS5_HOST=<your_ps5_ip>
# Clean: make clean
#

PS5_HOST ?= ps5
PS5_PORT ?= 9021

PS5_PAYLOAD_SDK ?= /home/user/ps5-payload-sdk/installed

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined. Set it to your ps5-payload-sdk install path)
endif

ELF := hv_research.elf

CFLAGS := -Wall -Werror -Wno-unused-function -O1

# Build the kernel module first, then the main ELF (which embeds it)
all: kmod $(ELF)

# Build the kernel module (FreeBSD KLD)
kmod:
	$(MAKE) -C kmod

# Build the main payload ELF (embeds kmod/hv_kmod.ko via .incbin)
$(ELF): main.c kmod/hv_kmod.ko
	$(CC) $(CFLAGS) -o $@ main.c

# Convenience target: ensure kmod .ko exists
kmod/hv_kmod.ko: kmod
	@true

clean:
	rm -f $(ELF)
	$(MAKE) -C kmod clean

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

.PHONY: all kmod clean test
