#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errors.h>
#include <peviewer.h>

/**
 * \fn int is_pe(const char *filename).
 * \brief Test if filename is a valid PE file.
 *
 * \param filename The name of the PE file.
 *
 * \return ALLOCATION_ERROR if allocations fail.
 * \return FILE_ERROR if it cannot handle the file.
 * \return INVALID_PE_SIGNATURE if the signature is not valid.
 * \return SUCCESS if it is a valid PE file.
 */
int is_pe(const char *filename)
{
    FILE *pe_file = NULL;
    uint32_t signature= 0;
    int res = INVALID_PE_SIGNATURE;
    PIMAGE_DOS_HEADER dos_header = NULL;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if (dos_header == NULL) {
        perror("Error: cannot allocate memory for dos header");
        return ALLOCATION_ERROR;
    }
    /* Read the image dos header of the file */
    get_dos_header(filename, dos_header);
    if (dos_header == NULL) {
        fputs("Cannot read DOS header", stderr);
        free(dos_header);
        return ALLOCATION_ERROR;
    }

    /* Check the magic number of the file */
    if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
        pe_file = fopen(filename, "rb");
        if (pe_file == NULL) {
            perror("Error: cannot open the file");
            free(dos_header);
            return FILE_ERROR;
        }
        fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
        fread((void *)&signature, sizeof(uint32_t), 1, pe_file);

        /* Check the signature number of the file */
        if (signature == IMAGE_NT_SIGNATURE)
            res = SUCCESS;

        fclose(pe_file);
    }

    free(dos_header);
    return res;
}

/**
 * \fn int get_arch_pe(const char *filename)
 * \brief Retrieve the architecture of filename.
 *
 * \param filename The name of the valid PE file.
 *
 * \return ALLOCATION_ERROR if allocations fail.
 * \return FILE_ERROR if it cannot handle the file.
 * \return DOS_HEADER_ERROR if it cannot dump the DOS header.
 * \return PECLASS32 if it is a 32bits application.
 * \return PECLASS64 if it is a 64bits application.
 * \return PECLASSNONE otherwise.
 */
int get_arch_pe(const char *filename)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    int res = PECLASSNONE;
    uint16_t architecture = 0;

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

/**
 * \fn int get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest)
 * \brief Dump the DOS header from filename.
 *
 * \param filename The name of a valid PE file.
 * \param dest A pointer where to save the DOS header.
 *
 * \return FILE_ERROR if it cannot handle the file.
 * \return SUCCESS otherwise.
 */
int get_dos_header(const char *filename, PIMAGE_DOS_HEADER dest)
{
    FILE *pe_file = NULL;

    pe_file = fopen(filename, "rb");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return FILE_ERROR;
    }
    /* Read the image dos header of the file */
    fread((void *)dest, sizeof(IMAGE_DOS_HEADER), 1, pe_file);

    fclose(pe_file);
    return SUCCESS;
}

/**
 * \fn uint32_t get_alignment(uint32_t value, uint32_t alignment)
 * \brief Compute the aligned value of value according to alignment.
 *
 * \param value The value to be aligned.
 * \param alignment The alignment value.
 *
 * \return The aligned value of value according to alignment.
 */
uint32_t get_alignment(uint32_t value, uint32_t alignment)
{
    if (!(value % alignment))
        return value;
    else
        return ((value / alignment) + 1) * alignment;
}
