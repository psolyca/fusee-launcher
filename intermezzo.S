//
// Payload launcher stub.
//

#define IROM_START 0xfff00000
#define IROM_SIZE (48 * 1024)

#define IRAM_START 0x40000000
#define IRAM_END (IRAM_START + 256 * 1024)
#define MINILOADER_ENTRY 0x4000F000
#define FILL_START (MINILOADER_ENTRY + 1024)

#define IROM_COPY_ADDR 0x4002f000

#define PMC_BASE 0x7000E400
#define _REG(base, off) ((base) + (off))
#define PMC(off) _REG(PMC_BASE, off)
#define PMC_SCRATCH0 0x50

#define write_ep1_in_sync (0x001069F8 + 1)
#define usb_reset_ep1 (0x001064CA + 1)

//#define SAY_HELLO

//#define REBOOT_RCM

//#define FILL_IRAM

//#define COPY_IROM_TO_IRAM

    .globl _start

    .section ".text"
_start:

#ifdef FILL_IRAM
    bl fill_iram
#endif

#ifdef COPY_IROM_TO_IRAM
    ldr r0, =IROM_COPY_ADDR
    mov r1, #IROM_START
    mov r2, #IROM_SIZE
    bl copy
#endif

#ifdef SAY_HELLO
    ldr r0, =hello_str
    mov r1, #hello_str_len
    sub r2, sp, #4
    sub sp, sp, #4
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #4
    mov r0, #0
    mov r1, #1
    ldr ip, =usb_reset_ep1
    mov lr, pc
    bx ip
#endif

    ldr r0, =PMC(PMC_SCRATCH0)
#ifndef REBOOT_RCM
    // set bit to indicate exploit success
    mov r1, #0x10000000
#else
    // set RCM bit
    mov r1, #(1 << 1)
#endif
    str r1, [r0]

    // reset
    ldr r0, =PMC(0)
    mov r1, #(1 << 4)
    str r1, [r0]

    // uboot NOPs for some reason
    mov r0, r0

L_spin:
    b L_spin


#ifdef FILL_IRAM
    .globl fill_iram
fill_iram:
    ldr r0, =FILL_START
    ldr r1, =IRAM_END
L_fill_word:
    ldr r2, =#0x13371337
    str r2, [r0], #4
    cmp r0, r1
    bne L_fill_word
    bx lr
#endif

#ifdef COPY_IROM_TO_IRAM
//
// Simple block copy.
//   r0 = destination address
//   r1 = source address
//   r2 = length in bytes
// Destroys r0-r3.
//
    .globl copy
copy:

    // Copy the word...
    ldr r3, [r1], #4
    str r3, [r0], #4

    // And continue while we have words left to copy.
    subs r2, r2, #4
    bne copy

    // Once we're done, return.
    bx lr
#endif

#ifdef SAY_HELLO
    .globl  hello_str
    .type   hello_str, %object
    .size   hello_str, Lhello_str_end - hello_str
    .align 4
hello_str:
    .asciz "hello, world\n"
Lhello_str_end:
    .equ    hello_str_len, . - hello_str
#endif

