#ifndef PEVIEWER_H
#define PEVIEWER_H
#include <pestruct.h>
int is_pe(const char *filename);
PIMAGE_DOS_HEADER get_dos_header(const char *filename);
#endif /* PEVIEWER_H */
