#ifndef PELOADER_H_INCLUDED
#define PELOADER_H_INCLUDED

#include <stdint.h>

typedef struct {
    unsigned int size;
    int offset_oep;

    uint8_t *payload;
} Struct_Loader;

typedef Struct_Loader* Loader;

int init_loader(Loader loader, const uint8_t *payload, const int offset_oep);

#endif /* PELOADER_H_INCLUDED */
