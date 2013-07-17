#ifndef PEVIEWER32_H
#define PEVIEWER32_H

int  get_pe_header32(const char *filename, PIMAGE_NT_HEADERS32 dest);
int  get_coff_header32(const char *filename, PIMAGE_FILE_HEADER dest);
int  get_optional_header32(const char *filename, PIMAGE_OPTIONAL_HEADER32 dest);

int get_sections_headers32(const char *filename, PIMAGE_SECTION_HEADER *sections_headers, const unsigned int nb_sections);

int dump_pe32(const char *filename, PE32 *pe32);
void delete_pe32(PE32 *pe32);

int check_free_sections_headers_space(const PE32 pe32);
int get_available_section_space(const PE32 pe32);
int get_code_section(const PE32 pe32);

#endif /* PEVIEWER32_H */
