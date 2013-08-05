#ifndef PEVIEWER64_H
#define PEVIEWER64_H

int get_pe_header64(const char *filename, PIMAGE_NT_HEADERS64 dest);
int get_coff_header64(const char *filename, PIMAGE_FILE_HEADER dest);
int get_optional_header64(const char *filename, PIMAGE_OPTIONAL_HEADER64 dest);

int get_sections_headers64(const char *filename, PIMAGE_SECTION_HEADER *sections_headers, const unsigned int nb_sections);

int dump_pe64(const char *filename, PE64 *pe64);
void delete_pe64(PE64 *pe64);

int check_free_sections_headers_space64(const PE64 pe64);
int get_available_section_space64(const PE64 pe64);
int get_code_section64(const PE64 pe64);

#endif /* PEVIEWER64_H */
