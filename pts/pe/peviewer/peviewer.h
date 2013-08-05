#ifndef PEVIEWER_H
#define PEVIEWER_H

#include <pestruct.h>

int is_pe(const char *filename);
int get_arch_pe(const char *filename);
int get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest);
uint32_t get_alignment(uint32_t value, uint32_t alignment);

#endif /* PEVIEWER_H */
