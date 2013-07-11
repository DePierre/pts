#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pepacker32.h>
#include <pestruct.h>
#include <peviewer.h>
#include <peviewer32.h>

/*! \arg \c pe32 a pointer to the PE headers dump
 *  \arg \c loader the loader to add
 *  \return 0 if it fails
 *  \return 1 otherwise
 */
int add_section32(PE32 *pe32, Loader loader) {
    PIMAGE_SECTION_HEADER new_section = NULL;
    PIMAGE_OPTIONAL_HEADER32 optional_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    PIMAGE_SECTION_HEADER last_section_header = NULL;
    const uint32_t section_size = loader->length * sizeof(*loader->payload) + sizeof(uint32_t) + 1;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t new_ep = 0;

    if (!check_free_sections_headers_space(*pe32)) {
        fputs("Error: not enough space to add a new section", stderr);
        return 0;
    }

    /* Allocate the new section for the binary */
    new_section = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));
    if (new_section == NULL) {
        perror("Error: cannot allocate memory for the new section");
        return 0;
    }


    section_alignment = (*pe32)->optional_header->SectionAlignment;
    file_alignment = (*pe32)->optional_header->FileAlignment;

    last_section_header = (*pe32)->sections_headers[(*pe32)->number_of_sections - 1];

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

    /* Update the payload */
    new_ep = (*pe32)->optional_header->ImageBase + (*pe32)->optional_header->AddressOfEntryPoint;
    memcpy(&loader->payload[loader->offset_oep], &new_ep, sizeof(uint32_t));

    /* Update the PE header */
    (*pe32)->number_of_sections = (*pe32)->number_of_sections + 1;
    (*pe32)->coff_header->NumberOfSections = (*pe32)->coff_header->NumberOfSections + 1;
    (*pe32)->optional_header->SizeOfImage = get_alignment(
        (*pe32)->optional_header->SizeOfImage + section_size,
        section_alignment
    );
    (*pe32)->optional_header->SizeOfHeaders = get_alignment(
        (*pe32)->optional_header->SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER),
        file_alignment
    );
    (*pe32)->optional_header->AddressOfEntryPoint = new_section->VirtualAddress;

    /* Add the new section to the PE headers */
    (*pe32)->sections_headers = (PIMAGE_SECTION_HEADER *)realloc((void *)(*pe32)->sections_headers, (*pe32)->number_of_sections * sizeof(PIMAGE_SECTION_HEADER));
    if ((*pe32)->sections_headers == NULL) {
        perror("Error: cannot re-allocate memory for the new section in PE32");
        free(new_section);
        return 0;
    }

    (*pe32)->sections_headers[(*pe32)->number_of_sections - 1] = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));
    if ((*pe32)->sections_headers[(*pe32)->number_of_sections - 1] == NULL) {
        perror("Error: cannot allocate memory for the new section in PE32");
        free(new_section);
        return 0;
    }
    memcpy(
        (void *)(*pe32)->sections_headers[(*pe32)->number_of_sections - 1],
        new_section,
        sizeof(IMAGE_SECTION_HEADER)
    );

    save_section32(*pe32);

    free(new_section);
    free(optional_header);
    free(last_section_header);
    free(coff_header);
    return 1;
}

/*! Save the new headers into the file.
 */
int save_section32(const PE32 pe32) {
    FILE *pe_file = NULL;
    unsigned int offset_last_section = 0;

    pe_file = fopen(pe32->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return 0;
    }
    /* Move the cursor to the IMAGE_FILE_HEADER32 */
    fseek(pe_file, pe32->offset_coff_header, SEEK_SET);
    /* Write the new COFF header */
    fwrite((void *)pe32->coff_header, sizeof(IMAGE_FILE_HEADER), 1, pe_file);
    printf("[+] COFF header has been saved\n");
    /* Write the new Optional header */
    fwrite((void *)pe32->optional_header, sizeof(IMAGE_OPTIONAL_HEADER32), 1, pe_file);
    printf("[+] Optional header has been saved\n");

    /* Compute offset of the last section */
    offset_last_section = pe32->offset_first_section_header + (pe32->number_of_sections - 1) * sizeof(IMAGE_SECTION_HEADER);
    fseek(pe_file, offset_last_section, SEEK_SET);
    /* TODO: add the section without overwritting the file */
    fwrite((void *)pe32->sections_headers[pe32->number_of_sections - 1], sizeof(IMAGE_SECTION_HEADER), 1, pe_file);
    printf("[+] New section header has been saved (offset: %X)\n", offset_last_section);
    printf("[*] Name of the section: %s\n", pe32->sections_headers[pe32->number_of_sections - 1]->Name);

    fclose(pe_file);

    return 1;
}

void write_loader32(const PE32 pe32, const Loader loader) {
    FILE *pe_file = NULL;
    unsigned int filled = 0;
    unsigned int i = 0;
    const uint8_t null = 0x00;

    pe_file = fopen(pe32->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        exit(1);
    }

    fseek(pe_file, 0, SEEK_END);
    fwrite((void *)loader->payload, loader->length * sizeof(*loader->payload), 1, pe_file);

    /* Fill the rest of the section */
    filled = pe32->optional_header->FileAlignment - loader->length * sizeof(*loader->payload);
    for (i = 0; i < filled; i = i + 1)
        fwrite(&null, sizeof(null), 1, pe_file);

    fclose(pe_file);
}
