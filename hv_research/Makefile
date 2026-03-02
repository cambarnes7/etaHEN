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

all: $(ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
