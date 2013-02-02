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

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    /* Read the image dos header of the file */
    fread((void *)dos_header, sizeof(IMAGE_DOS_HEADER), 1, pe_file);
    /* Check the magic number of the file */
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("error: not a valid PE file\n");
        exit(-1);
    }
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    /* Check the signature number of the file */
    fread((void *)&signature, sizeof(uint32_t), 1, pe_file);
    res = (signature == IMAGE_NT_SIGNATURE) ? 1 : 0;

    free(dos_header);
    fclose(pe_file);
    return res;
}

/*! \arg \c filename name of the PE file
 * \returns ARCH32 if it's a 32bits application
 * \returns ARCH64 if it's a 64bits application
 * \returns -1 if unknown
 */
int get_architecture(const char *filename)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    int res = -1;
    uint16_t architecture = 0;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    get_dos_header(filename, dos_header);
    pe_file = fopen(filename, "rb");
    /* Move the cursor to the field Magic of the Optional header */
    fseek(pe_file, dos_header->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER), SEEK_SET);
    /* Read the first field of the COFF header */
    fread((void *)&architecture, sizeof(uint16_t), 1, pe_file);
    if (architecture == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        res = ARCH32;
    else if (architecture == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        res = ARCH64;

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
 *  \arg \c dest destination to write the pe header
 */
void get_pe_header64(const char *filename, PIMAGE_NT_HEADERS64 dest)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    get_dos_header(filename, dos_header);
    pe_file = fopen(filename, "rb");
    /* Move the cursor to the beginning of IMAGE_NT_HEADERS */
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    fread((void *)dest, sizeof(IMAGE_NT_HEADERS64), 1, pe_file);

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

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the coff header
 */
void get_coff_header64(const char *filename, PIMAGE_FILE_HEADER dest)
{
    PIMAGE_NT_HEADERS64 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS64)calloc(1, sizeof(IMAGE_NT_HEADERS64));
    get_pe_header64(filename, pe_header);
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
 *  \arg \c dest destination to write the optional header
 */
void get_optional_header64(const char *filename, PIMAGE_OPTIONAL_HEADER64 dest)
{
    PIMAGE_NT_HEADERS64 pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS64)calloc(1, sizeof(IMAGE_NT_HEADERS64));
    get_pe_header64(filename, pe_header);
    /* IMAGE_NT_HEADERS32 contains the Optional header */
    memcpy(dest, &pe_header->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER64));

    free(pe_header);
}
