#
# PS5 HV Research - Kernel Module Build
#
# Builds a flat binary (.bin) for loading into PS5 kernel memory.
# Uses system clang with bare-metal target (no OS dependencies).
#

CC := clang
LD := ld.lld
OBJCOPY := llvm-objcopy

ELF := hv_kmod.elf
BIN := hv_kmod.bin

# Kernel-mode compilation flags (matches ps5-kld-sdk approach)
CFLAGS := --target=x86_64-unknown-none-elf \
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
          -fPIC \
          -mcmodel=small \
          -march=znver2 \
          -mno-red-zone \
          -mno-mmx \
          -mno-sse \
          -msoft-float \
          -ffunction-sections \
          -fdata-sections

LDFLAGS := -T linker.x \
           --gc-sections \
           --build-id=none

all: $(BIN)

$(ELF): hv_kmod.o
	$(LD) $(LDFLAGS) -o $@ $^

hv_kmod.o: hv_kmod.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(ELF)
	$(OBJCOPY) -S -O binary $< $@
	@echo "Kernel module built: $(BIN) ($$(stat -c %s $(BIN)) bytes)"

clean:
	rm -f *.o $(ELF) $(BIN)

.PHONY: all clean
