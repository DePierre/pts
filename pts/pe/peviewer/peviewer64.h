#ifndef PEVIEWER64_H
#define PEVIEWER64_H

void get_pe_header64(const char *filename, PIMAGE_NT_HEADERS64 dest);
void get_coff_header64(const char *filename, PIMAGE_FILE_HEADER dest);
void get_optional_header64(const char *filename, PIMAGE_OPTIONAL_HEADER64 dest);
void get_first_section_header64(const char *filename, PIMAGE_SECTION_HEADER dest);

int get_section_by_name64(const char *filename, const char *name, PIMAGE_SECTION_HEADER dest);

#endif /* PEVIEWER64_H */
