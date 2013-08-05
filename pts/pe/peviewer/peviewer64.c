#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errors.h>
#include <pestruct.h>
#include <peviewer.h>
#include <peviewer64.h>

/**
 * \fn int get_pe_header64(const char *filename, PIMAGE_NT_HEADERS64 dest)
 * \brief Dump the PE header from a PE file.
 *
 * \param filename The name of the PE file.
 * \param dest A valid pointer to an IMAGE_NT_HEADERS64.
 *
 * \return ALLOCATION_ERROR if allocations fail.
 * \return FILE_ERROR if it cannot handle the file.
 * \return DOS_HEADER_ERROR if it cannot dump the DOS header.
 * \return NOT_EXECUTABLE if the file is not an executable file.
 * \return OBJ_FILE if the file is an OBJ file.
 * \return INVALID_PE_SIGNATURE if the OPTIONAL header signature is corrupted.
 * \return SUCCESS otherwise.
 */
int get_pe_header64(const char *filename, PIMAGE_NT_HEADERS64 dest) {
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if (dos_header == NULL) {
        perror("Error: cannot allocate memory for dos header");
        return ALLOCATION_ERROR;
    }
    get_dos_header(filename, dos_header);
    if (dos_header == NULL) {
        fputs("Cannot read DOS header", stderr);
        free(dos_header);
        return DOS_HEADER_ERROR;
    }
    pe_file = fopen(filename, "rb");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        free(dos_header);
        return FILE_ERROR;
    }
    /* Move the cursor to the beginning of IMAGE_NT_HEADERS */
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    fread((void *)dest, sizeof(IMAGE_NT_HEADERS64), 1, pe_file);

    if (!(dest->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        fputs("Error: the file is not an executable file", stderr);
        free(dos_header);
        fclose(pe_file);
        return NOT_EXECUTABLE;
    }

    if (!dest->FileHeader.SizeOfOptionalHeader) {
        fputs("Error: the file is an OBJ file", stderr);
        free(dos_header);
        fclose(pe_file);
        return OBJ_FILE;
    }

    if (dest->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fputs("Error: Optional header signature is corrupted", stderr);
        free(dos_header);
        fclose(pe_file);
        return INVALID_PE_SIGNATURE;
    }

    free(dos_header);
    fclose(pe_file);
    return SUCCESS;
}

/**
 * \fn int get_coff_header64(const char *filename, PIMAGE_FILE_HEADER dest)
 * \brief Dump the COFF header from a PE file.
 *
 * \param filename The name of the PE file.
 * \param dest A valid pointer to an IMAGE_FILE_HEADER.
 *
 * \return ALLOCATION_ERROR if allocations fail.
 * \return PE_HEADER_ERROR if it cannot dump the PE header.
 * \return NOT_EXECUTABLE if the file is not an executable file.
 * \return OBJ_FILE if the file is an OBJ file.
 * \return SUCCESS otherwise.
 */
int get_coff_header64(const char *filename, PIMAGE_FILE_HEADER dest) {
    PIMAGE_NT_HEADERS64 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS64)calloc(1, sizeof(IMAGE_NT_HEADERS64));
    if (pe_header == NULL) {
        perror("Error: cannot allocate memory for pe header");
        return ALLOCATION_ERROR;
    }
    get_pe_header64(filename, pe_header);
    if (pe_header == NULL) {
        fputs("Cannot read PE header", stderr);
        free(pe_header);
        return PE_HEADER_ERROR;
    }

    /* IMAGE_NT_HEADERS64 contains the coff header so we just have to copy it into the dest */
    memcpy(dest, &pe_header->FileHeader, sizeof(IMAGE_FILE_HEADER));

    if (!(pe_header->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        fputs("Error: the file is not an executable file", stderr);
        free(pe_header);
        return NOT_EXECUTABLE;
    }

    if (!pe_header->FileHeader.SizeOfOptionalHeader) {
        fputs("Error: the file is an OBJ file", stderr);
        free(pe_header);
        return OBJ_FILE;
    }

    free(pe_header);
    return SUCCESS;
}

/**
 * \fn int get_optional_header64(const char *filename, PIMAGE_OPTIONAL_HEADER64 dest)
 * \brief Dump the OPTIONAL header from a PE file.
 *
 * \param filename The name of the PE file.
 * \param dest A valid pointer to an IMAGE_OPTIONAL_HEADER64.
 *
 * \return ALLOCATION_ERROR if allocations fail.
 * \return PE_HEADER_ERROR if it cannot dump the PE header.
 * \return INVALID_PE_SIGNATURE if the OPTIONAL header signature is corrupted.
 * \return SUCCESS otherwise.
 */
int get_optional_header64(const char *filename, PIMAGE_OPTIONAL_HEADER64 dest) {
    PIMAGE_NT_HEADERS64 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS64)calloc(1, sizeof(IMAGE_NT_HEADERS64));
    if (pe_header == NULL) {
        perror("Error: cannot allocate memory for pe header");
        return ALLOCATION_ERROR;
    }
    get_pe_header64(filename, pe_header);
    if (pe_header == NULL) {
        fputs("Cannot read PE header", stderr);
        free(pe_header);
        return PE_HEADER_ERROR;
    }

    if (pe_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fputs("Error: Optional header signature is corrupted", stderr);
        free(pe_header);
        return INVALID_PE_SIGNATURE;
    }

    /* IMAGE_NT_HEADERS64 contains the Optional header */
    memcpy(dest, &pe_header->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER64));

    free(pe_header);
    return SUCCESS;
}

/**
 * \fn int get_sections_headers64(const char *filename, PIMAGE_SECTION_HEADER *sections_headers, const unsigned int nb_sections)
 * \brief Dump the SECTION headers from a PE file.
 *
 * \param filename The name of the PE file.
 * \param sections_headers A valid array of IMAGE_SECTION_HEADER.
 * \param nb_sections The number of sections to dump
 *
 * \return NULL_POINTER if sections_headers is NULL.
 * \return ALLOCATION_ERROR if allocations fail.
 * \return FILE_ERROR if it cannot handle the file.
 * \return DOS_HEADER_ERROR if it cannot dump the DOS header.
 * \return COFF_HEADER_ERROR if it cannot dump the COFF header.
 * \return NOT_EXECUTABLE if the file is not an executable file.
 * \return OBJ_FILE if the file is an OBJ file.
 * \return SUCCESS otherwise.
 */
int get_sections_headers64(const char *filename, PIMAGE_SECTION_HEADER *sections_headers, const unsigned int nb_sections) {
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    uint32_t offset_section = 0;
    unsigned int i = 0;

    if (sections_headers == NULL) {
        fputs("Structure SECTION cannot be null", stderr);
        return NULL_POINTER;
    }

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if (dos_header == NULL) {
        perror("Error: cannot allocate memory for dos header");
        return ALLOCATION_ERROR;
    }

    coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));
    if (coff_header == NULL) {
        perror("Error: cannot allocate memory for coff header");
        free(dos_header);
        return ALLOCATION_ERROR;
    }

    get_dos_header(filename, dos_header);
    if (dos_header == NULL) {
        fputs("Cannot read DOS header", stderr);
        free(coff_header);
        free(dos_header);
        return DOS_HEADER_ERROR;
    }

    get_coff_header64(filename, coff_header);
    if (coff_header == NULL) {
        fputs("Cannot read COFF header", stderr);
        free(coff_header);
        free(dos_header);
        return COFF_HEADER_ERROR;
    }

    if (!(coff_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        fputs("Error: the file is not an executable file", stderr);
        free(coff_header);
        free(dos_header);
        return NOT_EXECUTABLE;
    }

    if (!coff_header->SizeOfOptionalHeader) {
        fputs("Error: the file is an OBJ file", stderr);
        free(coff_header);
        free(dos_header);
        return OBJ_FILE;
    }

    /* Offset leads now to the Signature of IMAGE_NT_HEADERS */
    offset_section = dos_header->e_lfanew;
    /* Offset leads now to the OptionalHeader of IMAGE_NT_HEADERS */
    offset_section = offset_section + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    /* Offset leads now to the first section header */
    offset_section = offset_section + sizeof(IMAGE_OPTIONAL_HEADER64);

    pe_file = fopen(filename, "rb");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        free(dos_header);
        free(coff_header);
        return FILE_ERROR;
    }
    fseek(pe_file, offset_section, SEEK_SET);
    for (i = 0; i < nb_sections; i = i + 1)
        fread((void *)sections_headers[i], sizeof(IMAGE_SECTION_HEADER), 1, pe_file);

    free(coff_header);
    free(dos_header);
    fclose(pe_file);

    return SUCCESS;
}

/**
 * \fn int dump_pe64(const char *filename, PE64 *pe64)
 * \brief Dump all the headers from a PE file.
 *
 * \todo Handle the errors from the called functions.
 *
 * \param filename The name of the PE file.
 * \param dest A valid pointer to a PE64 structure.
 *
 * \return ALLOCATION_ERROR if allocations fail.
 * \return NOT_EXECUTABLE if the file is not an executable file.
 * \return OBJ_FILE if the file is an OBJ file.
 * \return INVALID_PE_SIGNATURE if the OPTIONAL header signature is corrupted.
 * \return SUCCESS otherwise.
 */
int dump_pe64(const char *filename, PE64 *pe64) {
    unsigned int i = 0;

    *pe64 = (PE64)calloc(1, sizeof(Struct_PE64));
    if (*pe64 == NULL) {
        perror("Error: cannot allocate memory for PE64");
        return ALLOCATION_ERROR;
    }

    (*pe64)->filename = (char *)calloc(strlen(filename), sizeof(char));
    if ((*pe64)->filename == NULL) {
        perror("Error: cannot allocate memory for filename");
        free(*pe64);
        return ALLOCATION_ERROR;
    }

    memcpy((void *)(*pe64)->filename, filename, strlen(filename) * sizeof(char));

    printf("[+] Dumping PE headers from %s\n", (*pe64)->filename);

    (*pe64)->dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if ((*pe64)->dos_header == NULL) {
        perror("Error: cannot allocate memory for DOS header");
        free((void *)(*pe64)->filename);
        free(*pe64);
        return ALLOCATION_ERROR;
    }
    printf("[+] Dumping DOS header\n");
    (*pe64)->offset_dos_header = 0x0;
    get_dos_header(filename, (*pe64)->dos_header);
    printf("\tOffset 0x%X\n", (*pe64)->offset_dos_header);
    printf("\tSize %d\n", sizeof(IMAGE_DOS_HEADER));

    (*pe64)->pe_header = (PIMAGE_NT_HEADERS64)calloc(1, sizeof(IMAGE_NT_HEADERS64));
    if ((*pe64)->pe_header == NULL) {
        perror("Error: cannot allocate memory for PE header");
        free((*pe64)->dos_header);
        free((void *)(*pe64)->filename);
        free(*pe64);
        return ALLOCATION_ERROR;
    }
    printf("[+] Dumping PE header\n");
    (*pe64)->offset_pe_header = (*pe64)->dos_header->e_lfanew;
    get_pe_header64(filename, (*pe64)->pe_header);
    printf("\tOffset 0x%X\n", (*pe64)->offset_pe_header);
    printf("\tSize %d\n", sizeof(IMAGE_NT_HEADERS64));

    (*pe64)->coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));
    if ((*pe64)->coff_header == NULL) {
        perror("Error: cannot allocate memory for COFF header");
        free((*pe64)->pe_header);
        free((*pe64)->dos_header);
        free((void *)(*pe64)->filename);
        free(*pe64);
        return ALLOCATION_ERROR;
    }
    printf("[+] Dumping COFF header\n");
    (*pe64)->offset_coff_header = (*pe64)->offset_pe_header + sizeof(uint32_t);
    get_coff_header64(filename, (*pe64)->coff_header);

    if (!((*pe64)->coff_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        fputs("Error: the file is not an executable file", stderr);
        free((*pe64)->coff_header);
        free((*pe64)->pe_header);
        free((*pe64)->dos_header);
        free((void *)(*pe64)->filename);
        free(*pe64);
        return NOT_EXECUTABLE;
    }

    if (!(*pe64)->coff_header->SizeOfOptionalHeader) {
        fputs("Error: the file is an OBJ file", stderr);
        free((*pe64)->coff_header);
        free((*pe64)->pe_header);
        free((*pe64)->dos_header);
        free((void *)(*pe64)->filename);
        free(*pe64);
        return OBJ_FILE;
    }

    printf("\tOffset 0x%X\n", (*pe64)->offset_coff_header);
    printf("\tSize %d\n", sizeof(IMAGE_FILE_HEADER));

    (*pe64)->optional_header = (PIMAGE_OPTIONAL_HEADER64)calloc(1, sizeof(IMAGE_OPTIONAL_HEADER64));
    if ((*pe64)->optional_header == NULL) {
        perror("Error: cannot allocate memory for OPTIONAL header");
        free((*pe64)->coff_header);
        free((*pe64)->pe_header);
        free((*pe64)->dos_header);
        free((void *)(*pe64)->filename);
        free(*pe64);
        return ALLOCATION_ERROR;
    }
    printf("[+] Dumping OPTIONAL header\n");
    (*pe64)->offset_optional_header = (*pe64)->offset_coff_header + sizeof(IMAGE_FILE_HEADER);
    get_optional_header64(filename, (*pe64)->optional_header);
    printf("\tOffset 0x%X\n", (*pe64)->offset_optional_header);
    printf("\tSize %d\n", sizeof(IMAGE_OPTIONAL_HEADER64));

    if ((*pe64)->optional_header->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fputs("Error: Optional header signature is corrupted", stderr);
        free((*pe64)->optional_header);
        free((*pe64)->coff_header);
        free((*pe64)->pe_header);
        free((*pe64)->dos_header);
        free((void *)(*pe64)->filename);
        free(*pe64);
        return INVALID_PE_SIGNATURE;
    }

    (*pe64)->offset_first_section_header = (*pe64)->offset_optional_header + sizeof(IMAGE_OPTIONAL_HEADER64);
    (*pe64)->number_of_sections = (*pe64)->coff_header->NumberOfSections;
    (*pe64)->sections_headers = (PIMAGE_SECTION_HEADER *)calloc((*pe64)->number_of_sections, sizeof(PIMAGE_SECTION_HEADER));
    for (i = 0; i < (*pe64)->number_of_sections; i = i + 1)
        (*pe64)->sections_headers[i] = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));

    if ((*pe64)->sections_headers == NULL) {
        perror("Error: cannot allocate memory for SECTIONS headers");
        free((*pe64)->optional_header);
        free((*pe64)->coff_header);
        free((*pe64)->pe_header);
        free((*pe64)->dos_header);
        free((void *)(*pe64)->filename);
        free(*pe64);
        return ALLOCATION_ERROR;
    }
    printf("[+] Dumping SECTIONS headers\n");
    printf("\tNumber of sections %d\n", (*pe64)->number_of_sections);
    printf("\tOffset of the first section 0x%X\n", (*pe64)->offset_first_section_header);
    get_sections_headers64(filename, (*pe64)->sections_headers, (*pe64)->number_of_sections);

    for (i = 0; i < (*pe64)->number_of_sections; i = i + 1)
        printf("\tSection %s\n", (*pe64)->sections_headers[i]->Name);

    return SUCCESS;
}

/**
 * \fn void delete_pe64(PE64 *pe64)
 * \brief Free a PE64 structure.
 *
 * \param pe64 the structure to be free.
 */
void delete_pe64(PE64 *pe64) {
    unsigned int i = 0;
    for (i = 0; i < (*pe64)->number_of_sections; i = i + 1)
        free((*pe64)->sections_headers[i]);
    free((*pe64)->sections_headers);
    (*pe64)->sections_headers = NULL;

    free((*pe64)->optional_header);
    (*pe64)->optional_header = NULL;
    free((*pe64)->coff_header);
    (*pe64)->coff_header = NULL;
    free((*pe64)->pe_header);
    (*pe64)->pe_header = NULL;
    free((*pe64)->dos_header);
    (*pe64)->dos_header = NULL;
    free((void *)(*pe64)->filename);
    free(*pe64);
    *pe64 = NULL;
}

/**
 * \fn int check_free_sections_headers_space(const PE64 pe64)
 * \brief Check if there is enough free space between the last section header
 * and the first section for a new section header.
 *
 * \param pe64 Dump of the PE headers.
 *
 * \return NULL_POINTER if sections_headers is NULL.
 * \return SUCCESS if there is enough space for a new section header.
 * \return NO_FREE_SPACE_IN_SECTIONS_HEADERS otherwise.
 */
int check_free_sections_headers_space64(const PE64 pe64) {
    unsigned int offset_end_sections_headers = 0;
    unsigned int offset_start_raw_code = 0;
    unsigned int i = 0;

    if (pe64 == NULL) {
        fputs("PE64 structure cannot be NULL", stderr);
        return NULL_POINTER;
    }

    /* Find the offset of the end of the current sections headers */
    offset_end_sections_headers = pe64->offset_first_section_header + \
                                  pe64->number_of_sections * sizeof(IMAGE_SECTION_HEADER);

    /* Find the start address of the first code */
    offset_start_raw_code = pe64->sections_headers[0]->Misc.PhysicalAddress;
    for (i = 1; i < pe64->number_of_sections; i = i + 1)
        if (pe64->sections_headers[i]->Misc.PhysicalAddress < offset_start_raw_code)
            offset_start_raw_code = pe64->sections_headers[i]->Misc.PhysicalAddress;

    /* If there is enough space for a new section header */
    if (offset_start_raw_code - offset_end_sections_headers > sizeof(IMAGE_SECTION_HEADER))
        return SUCCESS;

    return NO_FREE_SPACE_IN_SECTIONS_HEADERS;
}

/**
 * \fn int get_available_section_space(const PE64 pe64)
 * \brief Compute the free available space at the end of the code section.
 *
 * \param pe64 Dump of the PE headers.
 *
 * \return NULL_POINTER if pe64 is NULL.
 * \return NO_CODE_SECTION_FOUND if the code section cannot be found.
 * \return The amount of free space otherwise.
 */
int get_available_section_space64(const PE64 pe64) {
    int id = 0;

    id = get_code_section64(pe64);
    if (id == NO_CODE_SECTION_FOUND) {
        fputs("Invalid ID of the code section", stderr);
        return NO_CODE_SECTION_FOUND;
    }
    else if (id == NULL_POINTER) {
        fputs("PE64 cannot be NULL", stderr);
        return NULL_POINTER;
    }

    return get_alignment(pe64->sections_headers[id]->Misc.VirtualSize, pe64->optional_header->FileAlignment);
}

/**
 * \fn int get_code_section(const PE64 pe64)
 * \brief Find the index of the code section.
 *
 * \param pe64 Dump of the PE headers.
 *
 * \return NULL_POINTER if pe64 is NULL.
 * \return NO_CODE_SECTION_FOUND if the code section cannot be found.
 * \return The id of the code section.
 */
int get_code_section64(const PE64 pe64) {
    unsigned int i = 0;
    int id = NO_CODE_SECTION_FOUND;

    if (pe64 == NULL) {
        fputs("PE64 structure cannot be NULL", stderr);
        return NULL_POINTER;
    }

    while (id == NO_CODE_SECTION_FOUND) {
        /* AND logic between the section's characteristics and executable code */
        if (pe64->sections_headers[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            id = i;
        i = i + 1;
    }

    return id;
}
