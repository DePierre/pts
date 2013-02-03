#ifndef PEVIEWER_H
#define PEVIEWER_H

#define ARCH32 1
#define ARCH64 2

int is_pe(const char *filename);
int get_architecture(const char *filename);

void get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest);
void get_first_section_header(const char *filename, PIMAGE_SECTION_HEADER dest);

void get_pe_header32(const char *filename, PIMAGE_NT_HEADERS32 dest);
void get_coff_header32(const char *filename, PIMAGE_FILE_HEADER dest);
void get_optional_header32(const char *filename, PIMAGE_OPTIONAL_HEADER32 dest);

void get_pe_header64(const char *filename, PIMAGE_NT_HEADERS64 dest);
void get_coff_header64(const char *filename, PIMAGE_FILE_HEADER dest);
void get_optional_header64(const char *filename, PIMAGE_OPTIONAL_HEADER64 dest);

#endif /* PEVIEWER_H */
