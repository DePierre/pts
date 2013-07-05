#ifndef PAYLOAD_H_INCLUDED
#define PAYLOAD_H_INCLUDED

#include <stdint.h>

/* FIXME:
    Payload isn't correctly written into the file
    Must be a conversion problem */
uint8_t x86_32_jump_far[7] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, /* 0: MOV EAX, 0 */
    0xFF, 0xE0,                   /* 5: JMP EAX */
};

#endif /* PAYLOAD_H_INCLUDED */
