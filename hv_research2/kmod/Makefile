#
# PS5 HV Research 2 - Kernel Module Build (KLD)
#
# Builds a FreeBSD kernel loadable module (.ko) for loading via kldload(2).
# The .ko is an ET_REL ELF object file - the kernel linker handles
# relocation, memory allocation, and SYSINIT dispatch.
#

CC := clang

KO := hv_kmod2.ko

# Kernel-mode compilation flags for FreeBSD KLD
CFLAGS := --target=x86_64-unknown-freebsd \
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
          -fno-pic \
          -fno-common \
          -mcmodel=kernel \
          -march=znver2 \
          -mno-red-zone \
          -mno-mmx \
          -mno-sse \
          -msoft-float

all: $(KO)

$(KO): hv_kld2.c
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "Kernel module built: $(KO) ($$(stat -c %s $(KO)) bytes)"

clean:
	rm -f *.o $(KO)

.PHONY: all clean
