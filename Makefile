
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

LDFLAGS +=

SUBDIRS := payloads

TEGRA := $(filter tegra%,$(MAKECMDGOALS))

$(TEGRA):
	$(MAKE) -C $(SUBDIRS) $@

all: intermezzo

intermezzo: intermezzo.bin

intermezzo.elf: intermezzo.o
	$(LD) -T intermezzo.lds $(LDFLAGS) $^ -o $@

intermezzo.o: intermezzo.S
	$(CC) $(CFLAGS) $< -c -o $@

%.bin: %.elf
	$(OBJCOPY) -v -O binary $< $@

clean:
	rm -f *.o *.elf *.bin
	$(MAKE) -C $(SUBDIRS) clean

.PHONY: all clean intermezzo
