#ifndef PEPACKER32_H_INCLUDED
#define PEPACKER32_H_INCLUDED

#include <pestruct.h>
#include <peloader.h>

unsigned int pack32(PE32 *pe32, Loader loader);
unsigned int append_loader32(PE32 *pe32, Loader loader);
unsigned int add_section32(PE32 *pe32, Loader loader);
unsigned int save_section32(const PE32 pe32);
unsigned int write_loader32(const PE32 pe32, const Loader loader);
unsigned int save_dump32(const PE32 pe32);

#endif /* PEPACKER32_H_INCLUDED */
