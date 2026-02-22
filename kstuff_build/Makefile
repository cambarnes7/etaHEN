ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -I.

all: kstuff.elf

kstuff.elf: payload_bin.c main.c sqlite_triggers.c sqlite3.h
	$(CC) $(CFLAGS) -o $@ main.c sqlite_triggers.c -lSceSystemService -Wl,--unresolved-symbols=ignore-all
	strip $@

clean:
	rm -f *.o *.elf
