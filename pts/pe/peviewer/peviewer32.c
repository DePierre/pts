#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pestruct.h>
#include <peviewer.h>
#include <peviewer32.h>

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the pe header
 */
void get_pe_header32(const char *filename, PIMAGE_NT_HEADERS32 dest)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    get_dos_header(filename, dos_header);
    pe_file = fopen(filename, "rb");
    /* Move the cursor to the beginning of IMAGE_NT_HEADERS */
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    fread((void *)dest, sizeof(IMAGE_NT_HEADERS32), 1, pe_file);

    free(dos_header);
    fclose(pe_file);
}

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the coff header
 */
void get_coff_header32(const char *filename, PIMAGE_FILE_HEADER dest)
{
    PIMAGE_NT_HEADERS32 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS32)calloc(1, sizeof(IMAGE_NT_HEADERS32));
    get_pe_header32(filename, pe_header);
    /* IMAGE_NT_HEADERS32 contains the coff header so we just have to copy it into the dest */
    memcpy(dest, &pe_header->FileHeader, sizeof(IMAGE_FILE_HEADER));

    free(pe_header);
}

/*! \arg \c filename of the PE file
 *  \arg \c dest destination to write the optional header
 */
void get_optional_header32(const char *filename, PIMAGE_OPTIONAL_HEADER32 dest)
{
    PIMAGE_NT_HEADERS32 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS32)calloc(1, sizeof(IMAGE_NT_HEADERS32));
    get_pe_header32(filename, pe_header);
    /* IMAGE_NT_HEADERS32 contains the Optional header */
    memcpy(dest, &pe_header->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32));

    free(pe_header);
}

/*! \arg \c filename of the PE file
 *  \arg \c dest destination to write the first section header
 */
void get_first_section_header32(const char *filename, PIMAGE_SECTION_HEADER dest)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    uint32_t offset_section = 0;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));

    get_dos_header(filename, dos_header);
    get_coff_header32(filename, coff_header);

    /* Offset leads now to the Signature of IMAGE_NT_HEADERS */
    offset_section = dos_header->e_lfanew;
    /* Offset leads now to the OptionalHeader of IMAGE_NT_HEADERS */
    offset_section = offset_section + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    /* Offset leads now to the first section header */
    offset_section = offset_section + coff_header->SizeOfOptionalHeader;

    pe_file = fopen(filename, "rb");
    fseek(pe_file, offset_section, SEEK_SET);
    fread((void *)dest, sizeof(IMAGE_SECTION_HEADER), 1, pe_file);

    free(coff_header);
    free(dos_header);
    fclose(pe_file);
}

void get_last_section_header32(const char *filename, PIMAGE_SECTION_HEADER dest) {
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    uint32_t offset_section = 0;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));

    get_dos_header(filename, dos_header);
    get_coff_header32(filename, coff_header);

    /* Offset leads now to the Signature of IMAGE_NT_HEADERS */
    offset_section = dos_header->e_lfanew;
    /* Offset leads now to the OptionalHeader of IMAGE_NT_HEADERS */
    offset_section = offset_section + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    /* Offset leads now to the last section header */
    offset_section = offset_section + coff_header->SizeOfOptionalHeader;
    offset_section = offset_section + (coff_header->NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER);

    pe_file = fopen(filename, "rb");
    fseek(pe_file, offset_section, SEEK_SET);
    fread((void *)dest, sizeof(IMAGE_SECTION_HEADER), 1, pe_file);

    free(coff_header);
    free(dos_header);
    fclose(pe_file);
}


/*! \arg \c filename of the PE file
 *  \arg \c name the name of the section
 *  \arg \c dest destination to write the first section header
 *  \returns 0 if it failed
 *  \returns 1 if it succeed
 */
int get_section_by_name32(const char *filename, const char *name, PIMAGE_SECTION_HEADER dest)
{
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    PIMAGE_SECTION_HEADER section_header = NULL;
    int res = 0;
    uint32_t current_offset = 0;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));
    section_header = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));

    get_dos_header(filename, dos_header);
    get_coff_header32(filename, coff_header);

    /* Offset leads to the first section */
    current_offset = dos_header->e_lfanew + \
                     sizeof(uint32_t) + \
                     sizeof(IMAGE_FILE_HEADER) + \
                     coff_header->SizeOfOptionalHeader;

    if (cmp_section_by_name(
            filename,
            current_offset,
            name,
            coff_header->NumberOfSections,
            section_header)) {
        memcpy(dest, section_header, sizeof(IMAGE_SECTION_HEADER));
        res = 1;
    }

    free(section_header);
    free(coff_header);
    free(dos_header);
    return res;
}
