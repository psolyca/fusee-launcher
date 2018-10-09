//
// Payload launcher stub.
//

    .section ".textrwx", "awx"

    .globl _start
_start:

    // First, we'll need to move ourselves _out_ of the target area.
    // We'll copy down into the IRAM.
    ldr r0, intermezzo_reloc_addr
    adr r1, post_relocation
    mov r2, #(intermezzo_end - post_relocation)
    bl  copy

    // Jump to the start of RAM, which should now contain the post-relocation code.
    ldr r0, intermezzo_reloc_addr
    bx  r0


// start on a word boundry for the copy
    .p2align 2
post_relocation:

    // Next, we'll copy our payload down to the appropriate relocaiton address.
    ldr r0, intermezzo_start_addr
    mov r1, #(intermezzo_end - _start)
    add r4, r0, r1
    mov r1, r4
    ldr r2, payload_first_length
    bl  copy

    ldr r2, payload_second_length
    beq jump_to_payload
    ldr r0, intermezzo_start_addr
    ldr r1, payload_first_length
    add r0, r0, r1
    add r1, r4, r1
    add r1, r1, #4
    bl  copy

jump_to_payload:
    // Finally, jump into the relocated target.
    ldr r0, intermezzo_start_addr
    bx r0


//
// Simple block copy.
//   r0 = destination address
//   r1 = source address
//   r2 = length in bytes
// Destroys r0-r3.
//
copy:

    // Copy the word...
    ldr r3, [r1], #4
    str r3, [r0], #4

    // And continue while we have words left to copy.
    subs r2, r2, #4
    bne copy

    // Once we're done, return.
    bx lr

    .globl intermezzo_start_addr
intermezzo_start_addr:
    # .word 0xDEADBEE0
    .word 0x50004000

    .globl intermezzo_reloc_addr
intermezzo_reloc_addr:
    # .word 0xBAADF000
    .word 0x60003000

    .globl payload_first_length
payload_first_length:
    # .word 0xFACEC0C0
    .word 0x70002000

    .globl payload_second_length
payload_second_length:
    # .word 0xCAFED000
    .word 0x80001000

// emit the lit pool before end padding
// should be empty
litpool:
    .ltorg

// end on a word boundry
    .p2align 2

    .global intermezzo_end
intermezzo_end:
