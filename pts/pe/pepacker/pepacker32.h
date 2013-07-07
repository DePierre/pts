#ifndef PEPACKER32_H_INCLUDED
#define PEPACKER32_H_INCLUDED

#include <pestruct.h>
#include <peloader.h>

int add_section32(PE32 *pe32, Loader loader);
int save_section32(const PE32 pe32);
void write_loader32(const PE32 pe32, const Loader loader);

#endif /* PEPACKER32_H_INCLUDED */
