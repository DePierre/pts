#ifndef PEVIEWER_H
#define PEVIEWER_H

#define ARCH32 1
#define ARCH64 2

int is_pe(const char *filename);
int get_architecture(const char *filename);

void get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest);

int cmp_section_by_name(const char *filename, uint32_t offset, const char *name, uint16_t nb_sections, PIMAGE_SECTION_HEADER dest);

#endif /* PEVIEWER_H */
