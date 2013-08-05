#ifndef PEPACKER64_H_INCLUDED
#define PEPACKER64_H_INCLUDED

#include <pestruct.h>
#include <peloader.h>

int pack64(PE64 *pe64, Loader loader);
int append_loader64(PE64 *pe64, Loader loader);
int add_section64(PE64 *pe64, Loader loader);
int save_section64(const PE64 pe64);
int write_loader64(const PE64 pe64, const Loader loader);
int save_dump64(const PE64 pe64);

#endif /* PEPACKER64_H_INCLUDED */
