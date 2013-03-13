#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pestruct.h>
#include <peviewer.h>

/*! \arg \c filename name of the PE file
 * \returns 1 if the file is a correct PE one, 0 otherwise
 */
int is_pe(const char *filename)
{
    FILE *pe_file = NULL;
    uint32_t signature= 0;
    int res = 0;
    PIMAGE_DOS_HEADER dos_header = NULL;

    pe_file = fopen(filename, "rb");

    /* Check if the file has been correcly opened */
    if (pe_file == NULL)
    {
        printf("error: cannot open the file\n");
        exit(-1);
    }

    fclose(pe_file);
    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    /* Read the image dos header of the file */
    get_dos_header(filename, dos_header);
    /* Check the magic number of the file */
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("error: not a valid PE file\n");
        exit(-1);
    }
    pe_file = open(filename, "rb");
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    /* Check the signature number of the file */
    fread((void *)&signature, sizeof(uint32_t), 1, pe_file);
    res = (signature == IMAGE_NT_SIGNATURE) ? 1 : 0;

    free(dos_header);
    fclose(pe_file);
    return res;
}

/*! \arg \c filename name of the PE file
 * \returns PECLASS32 (1) if it's a 32bits application
 * \returns PECLASS64 (2) if it's a 64bits application
 * \returns PECLASSNONE (0) otherwise
 */
int get_arch_pe(const char *filename)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    int res = PECLASSNONE;
    uint16_t architecture = 0;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    get_dos_header(filename, dos_header);
    pe_file = fopen(filename, "rb");
    /* Move the cursor to the field Magic of the Optional header */
    fseek(pe_file, dos_header->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER), SEEK_SET);
    /* Read the first field of the COFF header */
    fread((void *)&architecture, sizeof(uint16_t), 1, pe_file);
    if (architecture == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        res = PECLASS32;
    else if (architecture == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        res = PECLASS64;

    free(dos_header);
    fclose(pe_file);
    return res;
}

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the dos header
 */
void get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest)
{
    FILE *pe_file = NULL;

    pe_file = fopen(filename, "rb");
    /* Read the image dos header of the file */
    fread((void *)dest, sizeof(IMAGE_DOS_HEADER), 1, pe_file);

    fclose(pe_file);
}

/*! \arg \c filename name of the PE file
 *  \arg \c offset offset of the first section header
 *  \arg \c name name of the section the user wants
 *  \arg \c nb_sections the number of the sections in the file
 *  \arg \c dest destination to write the section
 * \returns 0 if failed
 * \returns 1 if succeed
 */
int cmp_section_by_name(const char *filename, uint32_t offset, const char *name, uint16_t nb_sections, PIMAGE_SECTION_HEADER dest)
{
    FILE *pe_file = NULL;
    PIMAGE_SECTION_HEADER section_header = NULL;
    int res = 0;
    uint16_t i = 0;

    section_header = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));

    pe_file = fopen(filename, "rb");
    fseek(pe_file, offset, SEEK_CUR);
    /* We read the first section */
    fread((void *)section_header, sizeof(IMAGE_SECTION_HEADER), 1, pe_file);

    /* We read every section name to find the one */
    while (strcmp(name, (char *)section_header->Name) && i < nb_sections)
    {
        fread((void *)section_header, sizeof(IMAGE_SECTION_HEADER), 1, pe_file);
        i = i + 1;
    }

    /* If the last section we have read is the one, we copy it into the dest */
    if (!strcmp(name, (char *)section_header->Name))
    {
        memcpy(dest, section_header, sizeof(IMAGE_SECTION_HEADER));
        res = 1;
    }

    free(section_header);
    fclose(pe_file);
    return res;
}
