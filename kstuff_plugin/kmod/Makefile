#
# PS5 APIC Ops Plugin - Kernel Module Build
#
# Builds flat binary for kstuff kekcall loading.
#

CC := clang
OBJCOPY := objcopy

FLAT_ELF := apic_kmod.elf
FLAT_BIN := apic_kmod.bin

# Kernel-mode flags: PIC, freestanding, no stdlib
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
          -msoft-float \
          -fPIC -fpie -mcmodel=small

all: $(FLAT_BIN)

$(FLAT_BIN): apic_kmod.c linker.x
	$(CC) $(KFLAGS) -c -o apic_kmod.o apic_kmod.c
	$(CC) $(KFLAGS) -nostartfiles -Xlinker -T ./linker.x \
		-Wl,--build-id=none -Wl,--gc-sections -o $(FLAT_ELF) apic_kmod.o
	$(OBJCOPY) -S -O binary $(FLAT_ELF) $(FLAT_BIN)
	@echo "Flat binary built: $(FLAT_BIN) ($$(stat -c %s $(FLAT_BIN)) bytes)"

clean:
	rm -f *.o $(FLAT_ELF) $(FLAT_BIN)

.PHONY: all clean
