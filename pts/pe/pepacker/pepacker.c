#include <stdlib.h>
#include <stdio.h>

#include <pestruct.h>
#include <peviewer.h>
#include <pepacker.h>
#include <pepacker32.h>
#include <peloader.h>

int add_section(const char *filename, Loader loader) {
    switch (get_arch_pe(filename)) {
        case PECLASS32:
            add_section32(filename, loader);
            break;
        default:
            fputs("Error: unknow architecture", stderr);
            return 0;
    }

    return 1;
}

int write_loader(const char *filename, Loader loader) {
    switch (get_arch_pe(filename)) {
        case PECLASS32:
            write_loader32(filename, loader);
            break;
        default:
            fputs("Error: unknow architecture", stderr);
            return 0;
    }

    return 1;
}

void redirect_ep(const char *filename, uint32_t new_ep) {
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if (dos_header == NULL) {
        perror("Error: cannot allocate memory for dos header");
        exit(1);
    }
    get_dos_header(filename, dos_header);
    if (dos_header == NULL) {
        fputs("Cannot read DOS header", stderr);
        exit(1);
    }

    pe_file = fopen(filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        exit(1);
    }

    /* Move the cursor to the IMAGE_OPTIONAL_HEADER EntryPoint field*/
    fseek(
        pe_file,
        dos_header->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + \
        sizeof(uint16_t) + sizeof(unsigned char) * 2 + sizeof(uint32_t) * 3,
        SEEK_SET
    );
    fwrite((void *)&new_ep, sizeof(uint32_t), 1, pe_file);

    free(dos_header);
    fclose(pe_file);
}
