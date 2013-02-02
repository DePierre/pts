#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pestruct.h>
#include <peviewer.h>

/*! \arg \c filename name of the PE file
 * \returns 1 if the file is a correct PE one, 0 otherwise
 */
int is_pe(const char *filename)
{
    FILE *pe_file = NULL;
    unsigned int signature = 0;
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
    fgets((void *)dos_header, sizeof(IMAGE_DOS_HEADER), pe_file);
    /* Check the magic number of the file */
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("error: not a valid PE file\n");
        exit(-1);
    }
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    /* Check the signature number of the file */
    fgets((void *)&signature, sizeof(unsigned int), pe_file);
    res = (signature == IMAGE_NT_SIGNATURE) ? 1 : 0;

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
    fgets((void *)dest, sizeof(IMAGE_DOS_HEADER), pe_file);

    fclose(pe_file);
}

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the pe header
 */
void get_pe_header(const char *filename, PIMAGE_NT_HEADERS dest)
{
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    get_dos_header(filename, dos_header);
    pe_file = fopen(filename, "rb");
    /* Move the cursor to the beginning of IMAGE_NT_HEADERS */
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    fgets((void *)dest, sizeof(IMAGE_NT_HEADERS), pe_file);

    free(dos_header);
    fclose(pe_file);
}

/*! \arg \c filename name of the PE file
 *  \arg \c dest destination to write the coff header
 */
void get_coff_header(const char *filename, PIMAGE_FILE_HEADER dest)
{
    PIMAGE_NT_HEADERS pe_header = NULL;

    pe_header = (PIMAGE_NT_HEADERS)calloc(1, sizeof(IMAGE_NT_HEADERS));
    get_pe_header(filename, pe_header);
    /* IMAGE_NT_HEADERS contains the coff header so we just have to copy it into the dest */
    memcpy(dest, &pe_header->FileHeader, sizeof(IMAGE_FILE_HEADER));

    free(pe_header);
}
