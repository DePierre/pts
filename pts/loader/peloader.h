#ifndef PELOADER_H_INCLUDED
#define PELOADER_H_INCLUDED

typedef struct Struct_Loader {
    const unsigned int size;
    const unsigned int oep;

    const char *payload;
} Struct_Loader* Loader;

int init_loader(Loader loader, const char *payload, const unsigned int oep);

#endif /* PELOADER_H_INCLUDED */
