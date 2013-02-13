#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elfviewer.h>
#include <elfviewer64.h>

void get_elf_header64(const char *filename, PElf64_Ehdr dest)
{
    FILE *elf_file = NULL;

    elf_file = fopen(filename, "rb");
    fread((void *)dest, sizeof(Elf64_Ehdr), 1, elf_file);

    fclose(elf_file);
}
