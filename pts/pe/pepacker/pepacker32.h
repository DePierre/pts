#ifndef PEPACKER32_H_INCLUDED
#define PEPACKER32_H_INCLUDED

#include <pestruct.h>
#include <peloader.h>

int add_section32(const char *filename, const Loader loader);
int save_section32(const char *filename, const PIMAGE_OPTIONAL_HEADER32 optional_header, PIMAGE_FILE_HEADER coff_header, PIMAGE_SECTION_HEADER new_section);

#endif /* PEPACKER32_H_INCLUDED */
