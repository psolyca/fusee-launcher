
CROSS_COMPILE = arm-none-eabi-

# Use our cross-compile prefix to set up our basic cross compile environment.
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

CFLAGS = \
	-mtune=arm7tdmi \
	-mlittle-endian \
	-fno-stack-protector \
	-fno-common \
	-fno-builtin \
	-ffreestanding \
	-std=gnu99 \
	-Werror \
	-Wall \
	-Wno-error=unused-function \
	-fomit-frame-pointer \
	-g \
	-Os

LDFLAGS =

all: intermezzo.bin dump-sbk-via-usb.bin

ENTRY_POINT_ADDRESS := 0x4000A000

# Provide the definitions used in the intermezzo stub.
DEFINES := \
	-DENTRY_POINT_ADDRESS=$(ENTRY_POINT_ADDRESS)

intermezzo.elf: intermezzo.o
	$(LD) -T intermezzo.lds --defsym LOAD_ADDR=$(ENTRY_POINT_ADDRESS) $(LDFLAGS) $^ -o $@

intermezzo.o: intermezzo.S
	$(CC) $(CFLAGS) $(DEFINES) $< -c -o $@

dump-sbk-via-usb.elf: dump-sbk-via-usb.o
	$(LD) -T dump-sbk-via-usb.lds --defsym LOAD_ADDR=$(ENTRY_POINT_ADDRESS) $(LDFLAGS) $^ -o $@

dump-sbk-via-usb.o: dump-sbk-via-usb.S
	$(CC) $(CFLAGS) $(DEFINES) $< -c -o $@

%.bin: %.elf
	$(OBJCOPY) -v -O binary $< $@

clean:
	rm -f *.o *.elf *.bin

.PHONY: all clean
