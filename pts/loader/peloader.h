#ifndef PELOADER_H_INCLUDED
#define PELOADER_H_INCLUDED

typedef struct {
    unsigned int size;
    unsigned int oep;

    char *payload;
} Struct_Loader;

typedef Struct_Loader* Loader;

int init_loader(Loader loader, const int *payload, const unsigned int oep);

#endif /* PELOADER_H_INCLUDED */
