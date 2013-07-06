#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pepacker32.h>
#include <pepacker.h>
#include <pestruct.h>
#include <peviewer.h>
#include <peviewer32.h>

int add_section32(const char *filename, Loader loader) {
    PIMAGE_SECTION_HEADER new_section = NULL;
    PIMAGE_OPTIONAL_HEADER32 optional_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    PIMAGE_SECTION_HEADER last_section_header = NULL;
    const uint32_t section_size = loader->length * sizeof(*loader->payload) + sizeof(uint32_t) + 1;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t new_ep = 0;

    /* Allocate the new section for the binary */
    new_section = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));
    if (new_section == NULL) {
        perror("Error: cannot allocate memory for the new section");
        return 0;
    }


    optional_header = (PIMAGE_OPTIONAL_HEADER32)calloc(1, sizeof(IMAGE_OPTIONAL_HEADER32));
    if (optional_header == NULL) {
        perror("Error: cannot allocate memory for the optional header");
        free(new_section);
        return 0;
    }
    get_optional_header32(filename, optional_header);
    section_alignment = optional_header->SectionAlignment;
    file_alignment = optional_header->FileAlignment;

    last_section_header = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));
    if (last_section_header == NULL) {
        perror("Error: cannot allocate memory for the coff header");
        free(new_section);
        free(optional_header);
        return 0;
    }
    get_last_section_header32(filename, last_section_header);

    /* Fields of the new section */
    memcpy(new_section->Name, ".packer", 7);
    new_section->VirtualAddress = get_alignment(
        last_section_header->VirtualAddress + last_section_header->Misc.VirtualSize,
        section_alignment
    );
    /* TODO: check if VirtualSize needs to be aligned */
    new_section->Misc.VirtualSize = section_size;
    new_section->SizeOfRawData = get_alignment(
        section_size,
        file_alignment
    );
    new_section->PointerToRawData = get_alignment(
        last_section_header->PointerToRawData + last_section_header->SizeOfRawData,
        file_alignment
    );
    new_section->Characteristics = IMAGE_SCN_MEM_EXECUTE | \
                                   IMAGE_SCN_MEM_READ | \
                                   IMAGE_SCN_CNT_CODE;
    new_section->PointerToRelocations = 0x0;
    new_section->PointerToLinenumbers = 0x0;
    new_section->NumberOfRelocations = 0x0;
    new_section->NumberOfLinenumbers = 0x0;

    /* Update the PE header */
    coff_header = (PIMAGE_FILE_HEADER)calloc(1, sizeof(IMAGE_FILE_HEADER));
    if (coff_header == NULL) {
        perror("Error: cannot allocate memory for the coff header");
        free(new_section);
        free(optional_header);
        free(last_section_header);
        return 0;
    }
    get_coff_header32(filename, coff_header);

    coff_header->NumberOfSections = coff_header->NumberOfSections + 0x1;
    optional_header->SizeOfImage = get_alignment(
        optional_header->SizeOfImage + section_size,
        section_alignment
    );
    optional_header->SizeOfHeaders = get_alignment(
        optional_header->SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER),
        file_alignment
    );
    /* Update the payload */
    new_ep = optional_header->ImageBase + optional_header->AddressOfEntryPoint;
    memcpy(&loader->payload[loader->offset_oep], &new_ep, sizeof(uint32_t));

    save_section32(filename, optional_header, coff_header, new_section);

    free(new_section);
    free(optional_header);
    free(last_section_header);
    free(coff_header);
    return 1;
}

/*! Save the new headers into the file.
 */
int save_section32(const char *filename, const PIMAGE_OPTIONAL_HEADER32 optional_header, PIMAGE_FILE_HEADER coff_header, PIMAGE_SECTION_HEADER new_section) {
    FILE *pe_file = NULL;
    PIMAGE_DOS_HEADER dos_header = NULL;
    uint32_t offset_last_section = 0;

    dos_header = (PIMAGE_DOS_HEADER)calloc(1, sizeof(IMAGE_DOS_HEADER));
    if (dos_header == NULL) {
        perror("Error: cannot allocate memory for dos header");
        return 0;
    }
    get_dos_header(filename, dos_header);
    if (dos_header == NULL) {
        fputs("Cannot read DOS header", stderr);
        return 0;
    }

    pe_file = fopen(filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return 0;
    }
    /* Move the cursor to the IMAGE_FILE_HEADER32 */
    fseek(pe_file, dos_header->e_lfanew + sizeof(uint32_t), SEEK_SET);
    /* Write the new COFF header */
    fwrite((void *)coff_header, sizeof(IMAGE_FILE_HEADER), 1, pe_file);
    printf("[+] COFF header has been saved\n");
    /* Write the new Optional header */
    fwrite((void *)optional_header, sizeof(IMAGE_OPTIONAL_HEADER32), 1, pe_file);
    printf("[+] Optional header has been saved\n");

    /* Compute offset of the last section */
    offset_last_section = dos_header->e_lfanew + \
                          sizeof(uint32_t) + \
                          sizeof(IMAGE_FILE_HEADER) + \
                          coff_header->SizeOfOptionalHeader + \
                          (coff_header->NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER);
    fseek(pe_file, offset_last_section, SEEK_SET);
    /* TODO: add the section without overwritting the file */
    fwrite((void *)new_section, sizeof(IMAGE_SECTION_HEADER), 1, pe_file);
    printf("[+] New section header has been saved (offset: %X)\n", offset_last_section);
    printf("[*] Name of the section: %s\n", new_section->Name);

    free(dos_header);
    fclose(pe_file);

    redirect_ep(filename, new_section->VirtualAddress);

    return 1;
}

void write_loader32(const char *filename, Loader loader) {
    PIMAGE_OPTIONAL_HEADER32 optional_header = NULL;
    FILE *pe_file = NULL;
    unsigned int filled = 0;
    unsigned int i = 0;
    const uint8_t null = 0x00;

    pe_file = fopen(filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        exit(1);
    }

    fseek(pe_file, 0, SEEK_END);
    fwrite((void *)loader->payload, loader->length * sizeof(*loader->payload), 1, pe_file);

    fclose(pe_file);
    optional_header = (PIMAGE_OPTIONAL_HEADER32)calloc(1, sizeof(IMAGE_OPTIONAL_HEADER32));
    if (optional_header == NULL) {
        perror("Error: cannot allocate memory for optional header");
        exit(1);
    }
    get_optional_header32(filename, optional_header);
    if (optional_header == NULL) {
        fputs("Cannot read optional header", stderr);
        exit(1);
    }

    /* Fill the rest of the section */
    filled = optional_header->FileAlignment - loader->length * sizeof(*loader->payload);
    pe_file = fopen(filename, "rb+");
    fseek(pe_file, 0, SEEK_END);
    for (i = 0; i < filled; i = i + 1)
        fwrite(&null, sizeof(null), 1, pe_file);

    fclose(pe_file);
}
