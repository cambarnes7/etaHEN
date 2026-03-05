#
# PS5 Offset Discovery - Kernel Module Build
#
# Builds two targets:
#   hv_kmod.ko  - FreeBSD KLD (for kldload fallback)
#   hv_flat.bin - Flat binary (for kstuff kekcall loading)
#

CC := clang
OBJCOPY := objcopy

KO := hv_kmod.ko
FLAT_ELF := hv_flat.elf
FLAT_BIN := hv_flat.bin

# Common kernel-mode flags
KFLAGS := --target=x86_64-unknown-freebsd \
          -D_KERNEL \
          -std=c11 \
          -Os \
          -Wall -Werror \
          -Wno-unused-function \
          -ffreestanding \
          -fno-builtin \
          -nostdlib \
          -fno-stack-protector \
          -fno-plt \
          -fno-common \
          -march=znver2 \
          -mno-red-zone \
          -mno-mmx \
          -mno-sse \
          -msoft-float

# KLD-specific: no-pic, kernel model
KLD_FLAGS := $(KFLAGS) -fno-pic -mcmodel=kernel

# Flat binary: PIC, small model (loaded at arbitrary kernel VA)
FLAT_FLAGS := $(KFLAGS) -fPIC -fpie -mcmodel=small

all: $(KO) $(FLAT_BIN)

$(KO): hv_kld.c
	$(CC) $(KLD_FLAGS) -c -o $@ $<
	@echo "Kernel module built: $(KO) ($$(stat -c %s $(KO)) bytes)"

$(FLAT_BIN): hv_flat.c linker.x
	$(CC) $(FLAT_FLAGS) -c -o hv_flat.o hv_flat.c
	$(CC) $(FLAT_FLAGS) -nostartfiles -Xlinker -T ./linker.x \
		-Wl,--build-id=none -Wl,--gc-sections -o $(FLAT_ELF) hv_flat.o
	$(OBJCOPY) -S -O binary $(FLAT_ELF) $(FLAT_BIN)
	@echo "Flat binary built: $(FLAT_BIN) ($$(stat -c %s $(FLAT_BIN)) bytes)"

clean:
	rm -f *.o $(KO) $(FLAT_ELF) $(FLAT_BIN)

.PHONY: all clean
