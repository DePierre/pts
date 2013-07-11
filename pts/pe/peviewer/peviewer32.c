#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pestruct.h>
#include <peviewer.h>
#include <peviewer32.h>

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the pe header
 *  \return 0 if it fails
 *  \return 1 otherwise
 */
int get_pe_header32(const char *filename, PIMAGE_NT_HEADERS32 dest)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if (dos_header == NULL) {
        perror("Error: cannot allocate memory for dos header");
        return 0;
    }
    get_dos_header(filename, dos_header);
    if (dos_header == NULL) {
        fputs("Cannot read DOS header", stderr);
        free(dos_header);
        return 0;
    }
    pe_file = fopen(filename, "rb");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        free(dos_header);
        return 0;
    }
    /* Move the cursor to the beginning of IMAGE_NT_HEADERS */
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    fread((void *)dest, sizeof(IMAGE_NT_HEADERS32), 1, pe_file);

    free(dos_header);
    fclose(pe_file);
    return 1;
}

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the coff header
 *  \return 0 if it fails
 *  \return 1 otherwise
 */
int get_coff_header32(const char *filename, PIMAGE_FILE_HEADER dest)
{
    PIMAGE_NT_HEADERS32 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS32)calloc(1, sizeof(IMAGE_NT_HEADERS32));
    if (pe_header == NULL) {
        perror("Error: cannot allocate memory for pe header");
        return 0;
    }
    get_pe_header32(filename, pe_header);
    if (pe_header == NULL) {
        fputs("Cannot read PE header", stderr);
        free(pe_header);
        return 0;
    }

    /* IMAGE_NT_HEADERS32 contains the coff header so we just have to copy it into the dest */
    memcpy(dest, &pe_header->FileHeader, sizeof(IMAGE_FILE_HEADER));

    free(pe_header);
    return 1;
}

/*! \arg \c filename of the PE file
 *  \arg \c dest destination to write the optional header
 *  \return 0 if it fails
 *  \return 1 otherwise
 */
int get_optional_header32(const char *filename, PIMAGE_OPTIONAL_HEADER32 dest)
{
    PIMAGE_NT_HEADERS32 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS32)calloc(1, sizeof(IMAGE_NT_HEADERS32));
    if (pe_header == NULL) {
        perror("Error: cannot allocate memory for pe header");
        return 0;
    }
    get_pe_header32(filename, pe_header);
    if (pe_header == NULL) {
        fputs("Cannot read PE header", stderr);
        free(pe_header);
        return 0;
    }
    /* IMAGE_NT_HEADERS32 contains the Optional header */
    memcpy(dest, &pe_header->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32));

    free(pe_header);
    return 1;
}

/*! \arg \c filename of the PE file
 *  \arg \c dest destination to write the sections headers
 *  \return 0 if it fails
 *  \return 1 otherwise
 */
int get_sections_headers32(const char *filename, PIMAGE_SECTION_HEADER *sections_headers, const unsigned int nb_sections) {
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    uint32_t offset_section = 0;
    unsigned int i = 0;

    if (sections_headers == NULL) {
        fputs("Structure SECTION cannot be null", stderr);
        return 0;
    }

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if (dos_header == NULL) {
        perror("Error: cannot allocate memory for dos header");
        return 0;
    }
    coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));
    if (coff_header == NULL) {
        perror("Error: cannot allocate memory for coff header");
        free(dos_header);
        return 0;
    }

    get_dos_header(filename, dos_header);
    if (dos_header == NULL) {
        fputs("Cannot read DOS header", stderr);
        free(coff_header);
        free(dos_header);
        return 0;
    }
    get_coff_header32(filename, coff_header);
    if (coff_header == NULL) {
        fputs("Cannot read COFF header", stderr);
        free(coff_header);
        free(dos_header);
        return 0;
    }

    /* Offset leads now to the Signature of IMAGE_NT_HEADERS */
    offset_section = dos_header->e_lfanew;
    /* Offset leads now to the OptionalHeader of IMAGE_NT_HEADERS */
    offset_section = offset_section + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    /* Offset leads now to the first section header */
    offset_section = offset_section + coff_header->SizeOfOptionalHeader;

    pe_file = fopen(filename, "rb");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        free(dos_header);
        free(coff_header);
        return 0;
    }
    fseek(pe_file, offset_section, SEEK_SET);
    for (i = 0; i < nb_sections; i = i + 1)
        fread((void *)sections_headers[i], sizeof(IMAGE_SECTION_HEADER), 1, pe_file);

    free(coff_header);
    free(dos_header);
    fclose(pe_file);

    return 1;
}

/*! \arg \c filename of the PE file
 *  \arg \c pe32 destination to write the pe file dump
 *  \return 0 if it fails
 *  \return 1 otherwise
 */
int dump_pe32(const char *filename, PE32 *pe32) {
    unsigned int i = 0;

    *pe32 = (PE32)calloc(1, sizeof(Struct_PE32));
    if (*pe32 == NULL) {
        perror("Error: cannot allocate memory for PE32");
        return 0;
    }

    (*pe32)->filename = (char *)calloc(strlen(filename), sizeof(char));
    if ((*pe32)->filename == NULL) {
        perror("Error: cannot allocate memory for filename");
        free(*pe32);
        return 0;
    }

    memcpy((void *)(*pe32)->filename, filename, strlen(filename) * sizeof(char));

    printf("[+] Dumping PE headers from %s\n", (*pe32)->filename);

    (*pe32)->dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if ((*pe32)->dos_header == NULL) {
        perror("Error: cannot allocate memory for DOS header");
        free((void *)(*pe32)->filename);
        free(*pe32);
        return 0;
    }
    printf("[+] Dumping DOS header\n");
    (*pe32)->offset_dos_header = 0x0;
    get_dos_header(filename, (*pe32)->dos_header);
    printf("\tOffset 0x%X\n", (*pe32)->offset_dos_header);
    printf("\tSize %d\n", sizeof(IMAGE_DOS_HEADER));

    (*pe32)->pe_header = (PIMAGE_NT_HEADERS32)calloc(1, sizeof(IMAGE_NT_HEADERS32));
    if ((*pe32)->pe_header == NULL) {
        perror("Error: cannot allocate memory for PE header");
        free((*pe32)->dos_header);
        free((void *)(*pe32)->filename);
        free(*pe32);
        return 0;
    }
    printf("[+] Dumping PE header\n");
    (*pe32)->offset_pe_header = (*pe32)->dos_header->e_lfanew;
    get_pe_header32(filename, (*pe32)->pe_header);
    printf("\tOffset 0x%X\n", (*pe32)->offset_pe_header);
    printf("\tSize %d\n", sizeof(IMAGE_NT_HEADERS32));

    (*pe32)->coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));
    if ((*pe32)->coff_header == NULL) {
        perror("Error: cannot allocate memory for COFF header");
        free((*pe32)->pe_header);
        free((*pe32)->dos_header);
        free((void *)(*pe32)->filename);
        free(*pe32);
        return 0;
    }
    printf("[+] Dumping COFF header\n");
    (*pe32)->offset_coff_header = (*pe32)->offset_pe_header + sizeof(uint32_t);
    get_coff_header32(filename, (*pe32)->coff_header);
    printf("\tOffset 0x%X\n", (*pe32)->offset_coff_header);
    printf("\tSize %d\n", sizeof(IMAGE_FILE_HEADER));

    (*pe32)->optional_header = (PIMAGE_OPTIONAL_HEADER32)calloc(1, sizeof(IMAGE_OPTIONAL_HEADER32));
    if ((*pe32)->optional_header == NULL) {
        perror("Error: cannot allocate memory for OPTIONAL header");
        free((*pe32)->coff_header);
        free((*pe32)->pe_header);
        free((*pe32)->dos_header);
        free((void *)(*pe32)->filename);
        free(*pe32);
        return 0;
    }
    printf("[+] Dumping OPTIONAL header\n");
    (*pe32)->offset_optional_header = (*pe32)->offset_coff_header + sizeof(IMAGE_FILE_HEADER);
    get_optional_header32(filename, (*pe32)->optional_header);
    printf("\tOffset 0x%X\n", (*pe32)->offset_optional_header);
    printf("\tSize %d\n", sizeof(IMAGE_OPTIONAL_HEADER32));

    (*pe32)->offset_first_section_header = (*pe32)->offset_optional_header + (*pe32)->coff_header->SizeOfOptionalHeader;
    (*pe32)->number_of_sections = (*pe32)->coff_header->NumberOfSections;
    (*pe32)->sections_headers = (PIMAGE_SECTION_HEADER *)calloc((*pe32)->number_of_sections, sizeof(PIMAGE_SECTION_HEADER));
    for (i = 0; i < (*pe32)->number_of_sections; i = i + 1)
        (*pe32)->sections_headers[i] = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));

    if ((*pe32)->sections_headers == NULL) {
        perror("Error: cannot allocate memory for SECTIONS headers");
        free((*pe32)->optional_header);
        free((*pe32)->coff_header);
        free((*pe32)->pe_header);
        free((*pe32)->dos_header);
        free((void *)(*pe32)->filename);
        free(*pe32);
        return 0;
    }
    printf("[+] Dumping SECTIONS headers\n");
    printf("\tNumber of sections %d\n", (*pe32)->number_of_sections);
    printf("\tOffset of the first section 0x%X\n", (*pe32)->offset_first_section_header);
    get_sections_headers32(filename, (*pe32)->sections_headers, (*pe32)->number_of_sections);

    for (i = 0; i < (*pe32)->number_of_sections; i = i + 1)
        printf("\tSection %s\n", (*pe32)->sections_headers[i]->Name);

    return 1;
}

/*! \arg \c pe32 destination to be free
 */
void delete_pe32(PE32 *pe32) {
    unsigned int i = 0;
    for (i = 0; i < (*pe32)->number_of_sections; i = i + 1)
        free((*pe32)->sections_headers[i]);
    free((*pe32)->sections_headers);

    free((*pe32)->optional_header);
    free((*pe32)->coff_header);
    free((*pe32)->pe_header);
    free((*pe32)->dos_header);
    free((void *)(*pe32)->filename);
    free(*pe32);
}

/*! \arg \c pe32 dump of the PE file's headers
 *  \return 0 if there is no free space for a new section header
 *  \return 1 otherwise
 */
int check_free_sections_headers_space(const PE32 pe32) {
    unsigned int offset_end_sections_headers = 0;
    unsigned int offset_start_raw_code = 0;
    unsigned int i = 0;

    if (pe32 == NULL) {
        fputs("PE32 structure cannot be NULL", stderr);
        return 0;
    }

    /* Find the offset of the end of the current sections headers */
    offset_end_sections_headers = pe32->offset_first_section_header + \
                                  pe32->number_of_sections * sizeof(IMAGE_SECTION_HEADER);

    /* Find the start address of the first code */
    offset_start_raw_code = pe32->sections_headers[0]->Misc.PhysicalAddress;
    for (i = 1; i < pe32->number_of_sections; i = i + 1)
        if (pe32->sections_headers[i]->Misc.PhysicalAddress < offset_start_raw_code)
            offset_start_raw_code = pe32->sections_headers[i]->Misc.PhysicalAddress;

    /* If there is enough space for a new section header */
    if (offset_start_raw_code - offset_end_sections_headers > sizeof(IMAGE_SECTION_HEADER))
        return 1;

    return 0;
}

/*! \argc \c pe32dump of the PE file's headers
 *  \return id of the code section's header
 *  \return -1 if none found
 */
int get_code_section(const PE32 pe32) {
    unsigned int i = 0;
    int id = -1;

    if (pe32 == NULL) {
        fputs("PE32 structure cannot be NULL", stderr);
        return -1;
    }

    while (id == -1) {
        /* AND logic between the section's characteristics and executable code */
        if (pe32->sections_headers[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            id = i;
        i = i + 1;
    }

    return id;
}
