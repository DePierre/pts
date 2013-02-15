#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elfstruct.h>
#include <elfviewer.h>

/*! \arg \c filename name of the ELF file
 * \returns 1 if the file is a correct ELF one, 0 otherwise
 */
int is_elf(const char *filename)
{
    FILE *elf_file = NULL;
    unsigned char file_ident[4] = {0};
    int res = 0;

    elf_file = fopen(filename, "rb");

    if (elf_file == NULL)
    {
        printf("error: cannot open the file\n");
        exit(-1);
    }

    fread((void *)file_ident, sizeof(unsigned char), 4, elf_file);

    if (file_ident[EI_MAG0] == ELFMAG0 && \
            file_ident[EI_MAG1] == ELFMAG1 && \
            file_ident[EI_MAG2] == ELFMAG2 && \
            file_ident[EI_MAG3] == ELFMAG3)
        res = 1;

    fclose(elf_file);
    return res;
}

/*! \arg \c filename name of the ELF file
 * \returns ELFCLASS32 (1) if it's a 32bits application
 * \returns ELFCLASS64 (2) if it's a 64bits application
 * \returns ELFCLASSNONE (0) otherwise
 */
int get_arch_elf(const char *filename)
{
    FILE *elf_file = NULL;
    unsigned char architecture = 0;
    int res = -1;

    elf_file = fopen(filename, "rb");
    /* Move the cursor to the File class byte of ELF header */
    fseek(elf_file, sizeof(unsigned char) * EI_CLASS, SEEK_SET);
    /* Read the class */
    fread((void *)&architecture, sizeof(unsigned char), 1, elf_file);
    if (architecture != ELFCASS32 && \
            architecture != ELFCLASS64)
        res = ELFCLASSNONE;
    else
        res = (int)architecture;

    fclose(elf_file);
    return res;
}
