#
# PS5 Offset Discovery - Kernel Module Build (KLD)
#

CC := clang

KO := hv_kmod.ko

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

$(KO): hv_kld.c
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "Kernel module built: $(KO) ($$(stat -c %s $(KO)) bytes)"

clean:
	rm -f *.o $(KO)

.PHONY: all clean
