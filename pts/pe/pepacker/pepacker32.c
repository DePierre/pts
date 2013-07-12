#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pepacker32.h>
#include <pestruct.h>
#include <peviewer.h>
#include <peviewer32.h>

/**
 * \fn unsigned int pack32(PE32 *pe32, Loader loader)
 * \brief Pack the PE file with the loader.
 *
 * \param pe32 Dump of the PE headers.
 * \param loader Payload to add in pe32.
 *
 * \return 0 if it fails, 1 otherwise.
 */
unsigned int pack32(PE32 *pe32, Loader loader) {
    unsigned int free_space = 0;
    unsigned int error = 0;

    free_space = get_available_section_space(*pe32);
    printf("[+] Packing method:\n");
    if (free_space >= (loader->length * sizeof(*loader->payload))) {
        printf("\tAppend payload to the code section\n");
        error = append_loader32(pe32, loader);
    }
    else {
        printf("\tAdd a new section for the payload\n");
        error = add_section32(pe32, loader);
        error = write_loader32(*pe32, loader);
    }

    return error;
}

/**
 * \fn unsigned int append_loader32(PE32 *pe32, Loader loader)
 * \brief Append the payload at the end of the code section.
 *
 * \param pe32 Dump of the PE headers.
 * \param loader Payload to add in pe32.
 *
 * \return 0 if it fails, 1 otherwise.
 */
unsigned int append_loader32(PE32 *pe32, Loader loader) {
    FILE *pe_file = NULL;
    unsigned int offset_start_free_space = 0;
    unsigned int id = 0;
    uint32_t oep = 0;

    id = get_code_section(*pe32);
    offset_start_free_space = (*pe32)->sections_headers[id]->PointerToRawData + \
                              (*pe32)->sections_headers[id]->Misc.VirtualSize;

    /* Update payload */
    oep = (*pe32)->optional_header->ImageBase + (*pe32)->optional_header->AddressOfEntryPoint;
    memcpy(&loader->payload[loader->offset_oep], &oep, sizeof(uint32_t));

    /* Update headers */
    (*pe32)->optional_header->AddressOfEntryPoint = (*pe32)->sections_headers[id]->VirtualAddress + \
                                                    (*pe32)->sections_headers[id]->Misc.VirtualSize;
    (*pe32)->sections_headers[id]->Misc.VirtualSize = (*pe32)->sections_headers[id]->Misc.VirtualSize + \
                                                     loader->length * sizeof(*loader->payload);

    save_dump32(*pe32);

    pe_file = fopen((*pe32)->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: Cannot open the file");
        return 0;
    }

    fseek(pe_file, offset_start_free_space, SEEK_SET);
    fwrite((void *)loader->payload, loader->length * sizeof(*loader->payload), 1, pe_file);

    fclose(pe_file);
    return 1;
}

/**
 * \fn unsigned int add_section32(PE32 *pe32, Loader loader)
 * \brief Create a new section for the payload.
 *
 * \param pe32 Dump of the PE headers.
 * \param loader Payload to add in pe32.
 *
 * \return 0 if it fails, 1 otherwise.
 */
unsigned int add_section32(PE32 *pe32, Loader loader) {
    PIMAGE_SECTION_HEADER new_section = NULL;
    PIMAGE_OPTIONAL_HEADER32 optional_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    PIMAGE_SECTION_HEADER last_section_header = NULL;
    const uint32_t section_size = loader->length * sizeof(*loader->payload) + sizeof(uint32_t) + 1;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t oep = 0;

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
    oep = (*pe32)->optional_header->ImageBase + (*pe32)->optional_header->AddressOfEntryPoint;
    memcpy(&loader->payload[loader->offset_oep], &oep, sizeof(uint32_t));

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

    save_dump32(*pe32);
    save_section32(*pe32);

    free(new_section);
    free(optional_header);
    free(last_section_header);
    free(coff_header);
    return 1;
}

/**
 * \fn unsigned int save_section32(const PE32 pe32)
 * \brief Save the last section header into the file.
 *
 * \param pe32 Dump of the PE headers.
 *
 * \return 0 if it fails, 1 otherwise.
 */
unsigned int save_section32(const PE32 pe32) {
    FILE *pe_file = NULL;
    unsigned int offset_last_section = 0;

    pe_file = fopen(pe32->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return 0;
    }

    /* Compute offset of the last section */
    offset_last_section = pe32->offset_first_section_header + (pe32->number_of_sections - 1) * sizeof(IMAGE_SECTION_HEADER);
    fseek(pe_file, offset_last_section, SEEK_SET);
    /* TODO: add the section without overwritting the file */
    fwrite((void *)pe32->sections_headers[pe32->number_of_sections - 1], sizeof(IMAGE_SECTION_HEADER), 1, pe_file);
    printf("[+] New section header has been saved (offset: 0x%X)\n", offset_last_section);
    printf("\tName of the new section: %s\n", pe32->sections_headers[pe32->number_of_sections - 1]->Name);

    fclose(pe_file);

    return 1;
}

/**
 * \fn unsigned int write_loader32(const PE32 pe32, const Loader loader)
 * \brief Save the payload into the file
 *
 * \param pe32 Dump of the PE headers.
 * \param loader Payload to add in pe32.
 *
 * \return 0 if it fails, 1 otherwise.
 */
unsigned int write_loader32(const PE32 pe32, const Loader loader) {
    FILE *pe_file = NULL;
    unsigned int filled = 0;
    unsigned int i = 0;
    const uint8_t null = 0x00;

    pe_file = fopen(pe32->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return 0;
    }

    fseek(pe_file, 0, SEEK_END);
    fwrite((void *)loader->payload, loader->length * sizeof(*loader->payload), 1, pe_file);
    printf("[+] Save payload\n");

    /* Fill the rest of the section */
    filled = pe32->optional_header->FileAlignment - loader->length * sizeof(*loader->payload);
    for (i = 0; i < filled; i = i + 1)
        fwrite(&null, sizeof(null), 1, pe_file);

    fclose(pe_file);
    return 1;
}

/**
 * \fn unsigned int save_dump32(const PE32 pe32)
 * \brief Save all the PE headers into the file.
 *
 * \param pe32 Dump of the PE headers.
 *
 * \return 0 if it fails, 1 otherwise.
 */
unsigned int save_dump32(const PE32 pe32) {
    FILE *pe_file = NULL;
    unsigned int i = 0;

    pe_file = fopen(pe32->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return 0;
    }

    printf("[+] Save the new PE headers:\n");
    fseek(pe_file, pe32->offset_dos_header, SEEK_SET);
    fwrite((void *)pe32->dos_header, sizeof(IMAGE_DOS_HEADER), 1, pe_file);
    printf("\tDOS header saved\n");

    fseek(pe_file, pe32->offset_pe_header, SEEK_SET);
    fwrite((void *)pe32->pe_header, sizeof(IMAGE_NT_HEADERS32), 1, pe_file);
    printf("\tPE header saved\n");

    fseek(pe_file, pe32->offset_coff_header, SEEK_SET);
    fwrite((void *)pe32->coff_header, sizeof(IMAGE_FILE_HEADER), 1, pe_file);
    printf("\tCOFF header saved\n");

    fseek(pe_file, pe32->offset_optional_header, SEEK_SET);
    fwrite((void *)pe32->optional_header, sizeof(IMAGE_OPTIONAL_HEADER32), 1, pe_file);
    printf("\tOPTIONAL header saved\n");

    fseek(pe_file, pe32->offset_first_section_header, SEEK_SET);
    for (i = 0; i < pe32->number_of_sections; i = i + 1) {
        fwrite((void *)pe32->sections_headers[i], sizeof(IMAGE_SECTION_HEADER), 1, pe_file);
        printf("\tSECTION header saved (%s)\n", pe32->sections_headers[i]->Name);
    }

    fclose(pe_file);
    return 1;
}
