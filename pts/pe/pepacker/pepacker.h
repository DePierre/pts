#ifndef PEPACKER_H_INCLUDED
#define PEPACKER_H_INCLUDED

#include <peloader.h>

int add_section(const char *filename, Loader loader);
int write_loader(const char *filename, Loader loader);

#endif /* PEPACKER_H_INCLUDED */
