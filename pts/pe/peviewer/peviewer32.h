#ifndef PEVIEWER32_H
#define PEVIEWER32_H

void get_pe_header32(const char *filename, PIMAGE_NT_HEADERS32 dest);
void get_coff_header32(const char *filename, PIMAGE_FILE_HEADER dest);
void get_optional_header32(const char *filename, PIMAGE_OPTIONAL_HEADER32 dest);
void get_first_section_header32(const char *filename, PIMAGE_SECTION_HEADER dest);
void get_last_section_header32(const char *filename, PIMAGE_SECTION_HEADER dest);

int get_section_by_name32(const char *filename, const char *name, PIMAGE_SECTION_HEADER dest);

#endif /* PEVIEWER32_H */
