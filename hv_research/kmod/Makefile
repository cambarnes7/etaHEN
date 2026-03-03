#
# PS5 HV Research - Kernel Module Build (KLD)
#
# Builds a FreeBSD kernel loadable module (.ko) for loading via kldload(2).
# The .ko is an ET_REL ELF object file - the kernel linker handles
# relocation, memory allocation, and SYSINIT dispatch.
#

CC := clang

KO := hv_kmod.ko

# Kernel-mode compilation flags for FreeBSD KLD
# - target: FreeBSD x86_64 (sets ELF OSABI correctly)
# - mcmodel=kernel: negative 2GB addressing (kernel VA space)
# - mno-red-zone: kernel code must not use red zone
# - msoft-float: no FPU in kernel context
# - -c: produce ET_REL object (the .ko format)
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

# Compile directly to .ko (ET_REL ELF with relocations intact)
# No linking step - the kernel linker handles everything
$(KO): hv_kld.c
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "Kernel module built: $(KO) ($$(stat -c %s $(KO)) bytes)"

clean:
	rm -f *.o $(KO)

.PHONY: all clean
