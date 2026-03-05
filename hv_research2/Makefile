#
# PS5 Offset Discovery Tool (hv_research2) - Makefile
#
# Build: make
# Send:  make test PS5_HOST=<your_ps5_ip>
# Clean: make clean
#
# kstuff-no-fpkg (kekcall support):
#   make kstuff    - build kstuff-no-fpkg's kstuff.elf
#   make deploy-kstuff PS5_HOST=<ip> - send kstuff.elf to PS5
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
KSTUFF_DIR := kstuff-no-fpkg-repo/ps5_kernel_research/kstuff-no-fpkg

CFLAGS := -Wall -Werror -Wno-unused-function -O1

all: kmod $(ELF)

kmod:
	$(MAKE) -C kmod

$(ELF): main.c kmod/hv_kmod.ko
	$(CC) $(CFLAGS) -o $@ main.c -lSceSystemService

kmod/hv_kmod.ko: kmod
	@true

# Build kstuff-no-fpkg (provides kekcall: kmem_alloc, kproc_create, etc.)
# Requires PS5_PAYLOAD_SDK to be set (uses Pacbrew SDK toolchain)
kstuff: $(KSTUFF_DIR)/ps5-kstuff-ldr/kstuff.elf

$(KSTUFF_DIR)/ps5-kstuff-ldr/kstuff.elf:
	PS5_PAYLOAD_SDK=$(PS5_PAYLOAD_SDK) $(MAKE) -C $(KSTUFF_DIR)/ps5-kstuff-ldr

# Deploy kstuff.elf to /data/etaHEN/kstuff.elf on PS5
# etaHEN loads custom kstuff from this path on boot (overrides built-in)
deploy-kstuff: $(KSTUFF_DIR)/ps5-kstuff-ldr/kstuff.elf
	@echo "Deploying kstuff-no-fpkg to PS5 at $(PS5_HOST)..."
	@echo "Copy $(KSTUFF_DIR)/ps5-kstuff-ldr/kstuff.elf to /data/etaHEN/kstuff.elf on PS5"
	@echo "Then reboot to load kstuff-no-fpkg instead of etaHEN's built-in kstuff"

clean:
	rm -f $(ELF)
	$(MAKE) -C kmod clean

clean-kstuff:
	$(MAKE) -C $(KSTUFF_DIR)/ps5-kstuff-ldr clean

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

.PHONY: all kmod clean clean-kstuff test kstuff deploy-kstuff
