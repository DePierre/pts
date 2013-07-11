#ifndef PEVIEWER_H
#define PEVIEWER_H

#include <pestruct.h>

int is_pe(const char *filename);
int get_arch_pe(const char *filename);

void get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest);

int cmp_section_by_name(const char *filename, uint32_t offset, const char *name, uint16_t nb_sections, PIMAGE_SECTION_HEADER dest);

uint32_t get_alignment(uint32_t value, uint32_t alignment);

#endif /* PEVIEWER_H */
