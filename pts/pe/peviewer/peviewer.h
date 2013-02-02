#ifndef PEVIEWER_H
#define PEVIEWER_H

int is_pe(const char *filename);
void get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest);
void get_pe_header(const char *filename, PIMAGE_NT_HEADERS dest);
void get_coff_header(const char *filename, PIMAGE_FILE_HEADER dest);

#endif /* PEVIEWER_H */
