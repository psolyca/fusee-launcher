//
// Payload launcher stub.
//

#define COLOR_0 0x00F00003
#define COLOR_1 0x0F000003
#define COLOR_2 0xF0000003
#define COLOR_3 0x0FF00003
#define COLOR_4 0xF0F00003
#define COLOR_5 0xFF000003
#define COLOR_6 0xFFF00003
#define COLOR_7 0xAAF00003
#define COLOR_8 0xAFA00003
#define COLOR_9 0xFAA00003
#define COLOR_A 0x33300003
#define COLOR_B 0x06F00003
#define COLOR_C 0x14800003
#define COLOR_D 0x00300003
#define COLOR_E 0x03000003
#define COLOR_F 0xB6000003

#define PMC_BASE 0x7000E400
#define _REG(base, off) ((base) + (off))
#define PMC(off) _REG(PMC_BASE, off)
#define PMC_SCRATCH0 0x50
#define PMC_SCRATCH200 0x840

; #define REBOOT_RCM

; #define PANIC_COLOR

.globl _start

.section ".text"
_start:

#ifdef PANIC_COLOR
    // set panic color
    ldr r0, = PMC(PMC_SCRATCH200)
    mov r1, #COLOR_2
    str r1, [r0]
#endif

    ldr r0, = PMC(PMC_SCRATCH0)
#ifndef REBOOT_RCM
    // clear PMC_SCRATCH0 to avoid rebooting into RCM
    mov r1, #0
#else
    // set RCM bit
    mov r1, #(1 << 1)
#endif
    str r1, [r0]

    // reset
    ldr r0, =PMC(0)
    mov r1, #(1 << 4)
    str r1, [r0]

spin:
    b spin
