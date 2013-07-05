#ifndef PEPACKER_H_INCLUDED
#define PEPACKER_H_INCLUDED

#include <peloader.h>

int add_section(const char *filename, Loader loader);
int write_loader(const char *filename, Loader loader);
void redirect_ep(const char *filename, uint32_t new_ep);

#endif /* PEPACKER_H_INCLUDED */
