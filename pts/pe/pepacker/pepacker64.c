#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <errors.h>
#include <pepacker64.h>
#include <pestruct.h>
#include <peviewer.h>
#include <peviewer64.h>

/**
 * \fn int pack64(PE64 *pe64, Loader loader)
 * \brief Pack the PE file with the loader.
 *
 * \todo Process the errors.
 *
 * \param pe64 Dump of the PE headers.
 * \param loader Payload to add in pe64.
 *
 * \return The error code from the called functions.
 */
int pack64(PE64 *pe64, Loader loader) {
    unsigned int free_space = 0;
    unsigned int error = 0;

    free_space = get_available_section_space64(*pe64);
    printf("[+] Packing method:\n");
    if (free_space >= (loader->length * sizeof(*loader->payload))) {
        printf("\tAppend payload to the code section\n");
        error = append_loader64(pe64, loader);
    }
    else {
        printf("\tAdd a new section for the payload\n");
        error = add_section64(pe64, loader);
        error = write_loader64(*pe64, loader);
    }

    return error;
}

/**
 * \fn int append_loader64(PE64 *pe64, Loader loader)
 * \brief Append the payload at the end of the code section.
 *
 * \param pe64 Dump of the PE headers.
 * \param loader Payload to add in pe64.
 *
 * \return FILE_ERROR if it cannot handle the file.
 * \return SUCCESS if it succeeds.
 */
int append_loader64(PE64 *pe64, Loader loader) {
    FILE *pe_file = NULL;
    unsigned int offset_start_free_space = 0;
    unsigned int id = 0;
    uint32_t oep = 0;

    id = get_code_section64(*pe64);
    offset_start_free_space = (*pe64)->sections_headers[id]->PointerToRawData + \
                              (*pe64)->sections_headers[id]->Misc.VirtualSize;

    /* Update payload */
    oep = (*pe64)->optional_header->ImageBase + (*pe64)->optional_header->AddressOfEntryPoint;
    memcpy(&loader->payload[loader->offset_oep], &oep, sizeof(uint32_t));

    /* Update headers */
    (*pe64)->optional_header->AddressOfEntryPoint = (*pe64)->sections_headers[id]->VirtualAddress + \
                                                    (*pe64)->sections_headers[id]->Misc.VirtualSize;
    (*pe64)->sections_headers[id]->Misc.VirtualSize = (*pe64)->sections_headers[id]->Misc.VirtualSize + \
                                                     loader->length * sizeof(*loader->payload);

    save_dump64(*pe64);

    pe_file = fopen((*pe64)->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: Cannot open the file");
        return FILE_ERROR;
    }

    fseek(pe_file, offset_start_free_space, SEEK_SET);
    fwrite((void *)loader->payload, loader->length * sizeof(*loader->payload), 1, pe_file);

    fclose(pe_file);
    return SUCCESS;
}

/**
 * \fn int add_section64(PE64 *pe64, Loader loader)
 * \brief Create a new section for the payload.
 *
 * \param pe64 Dump of the PE headers.
 * \param loader Payload to add in pe64.
 *
 * \return NO_FREE_SPACE_IN_SECTIONS_HEADERS if there is no available space for a new section header.
 * \return ALLOCATION_ERROR if it cannot allocate memory.
 * \return SUCCESS if it succeeds.
 */
int add_section64(PE64 *pe64, Loader loader) {
    PIMAGE_SECTION_HEADER new_section = NULL;
    PIMAGE_OPTIONAL_HEADER64 optional_header = NULL;
    PIMAGE_FILE_HEADER coff_header = NULL;
    PIMAGE_SECTION_HEADER last_section_header = NULL;
    const uint32_t section_size = loader->length * sizeof(*loader->payload) + sizeof(uint32_t) + 1;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t oep = 0;

    if (check_free_sections_headers_space64(*pe64)) {
        fputs("Error: not enough space to add a new section", stderr);
        return NO_FREE_SPACE_IN_SECTIONS_HEADERS;
    }

    /* Allocate the new section for the binary */
    new_section = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));
    if (new_section == NULL) {
        perror("Error: cannot allocate memory for the new section");
        return ALLOCATION_ERROR;
    }


    section_alignment = (*pe64)->optional_header->SectionAlignment;
    file_alignment = (*pe64)->optional_header->FileAlignment;

    last_section_header = (*pe64)->sections_headers[(*pe64)->number_of_sections - 1];

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
    oep = (*pe64)->optional_header->ImageBase + (*pe64)->optional_header->AddressOfEntryPoint;
    memcpy(&loader->payload[loader->offset_oep], &oep, sizeof(uint32_t));

    /* Update the PE header */
    (*pe64)->number_of_sections = (*pe64)->number_of_sections + 1;
    (*pe64)->coff_header->NumberOfSections = (*pe64)->coff_header->NumberOfSections + 1;
    (*pe64)->optional_header->SizeOfImage = get_alignment(
        (*pe64)->optional_header->SizeOfImage + section_size,
        section_alignment
    );
    (*pe64)->optional_header->SizeOfHeaders = get_alignment(
        (*pe64)->optional_header->SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER),
        file_alignment
    );
    (*pe64)->optional_header->AddressOfEntryPoint = new_section->VirtualAddress;

    /* Add the new section to the PE headers */
    (*pe64)->sections_headers = (PIMAGE_SECTION_HEADER *)realloc((void *)(*pe64)->sections_headers, (*pe64)->number_of_sections * sizeof(PIMAGE_SECTION_HEADER));
    if ((*pe64)->sections_headers == NULL) {
        perror("Error: cannot re-allocate memory for the new section in PE64");
        free(new_section);
        return ALLOCATION_ERROR;
    }

    (*pe64)->sections_headers[(*pe64)->number_of_sections - 1] = (PIMAGE_SECTION_HEADER)calloc(1, sizeof(IMAGE_SECTION_HEADER));
    if ((*pe64)->sections_headers[(*pe64)->number_of_sections - 1] == NULL) {
        perror("Error: cannot allocate memory for the new section in PE64");
        free(new_section);
        return ALLOCATION_ERROR;
    }
    memcpy(
        (void *)(*pe64)->sections_headers[(*pe64)->number_of_sections - 1],
        new_section,
        sizeof(IMAGE_SECTION_HEADER)
    );

    save_dump64(*pe64);
    save_section64(*pe64);

    free(new_section);
    free(optional_header);
    free(last_section_header);
    free(coff_header);
    return SUCCESS;
}

/**
 * \fn int save_section64(const PE64 pe64)
 * \brief Save the last section header into the file.
 *
 * \param pe64 Dump of the PE headers.
 *
 * \return FILE_ERROR if it cannot handle the file.
 * \return SUCCESS if it succeeds.
 */
int save_section64(const PE64 pe64) {
    FILE *pe_file = NULL;
    unsigned int offset_last_section = 0;

    pe_file = fopen(pe64->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return FILE_ERROR;
    }

    /* Compute offset of the last section */
    offset_last_section = pe64->offset_first_section_header + (pe64->number_of_sections - 1) * sizeof(IMAGE_SECTION_HEADER);
    fseek(pe_file, offset_last_section, SEEK_SET);
    /* TODO: add the section without overwritting the file */
    fwrite((void *)pe64->sections_headers[pe64->number_of_sections - 1], sizeof(IMAGE_SECTION_HEADER), 1, pe_file);
    printf("[+] New section header has been saved (offset: 0x%X)\n", offset_last_section);
    printf("\tName of the new section: %s\n", pe64->sections_headers[pe64->number_of_sections - 1]->Name);

    fclose(pe_file);

    return SUCCESS;
}

/**
 * \fn int write_loader64(const PE64 pe64, const Loader loader)
 * \brief Save the payload into the file.
 *
 * \param pe64 Dump of the PE headers.
 * \param loader Payload to add in pe64.
 *
 * \return FILE_ERROR if it cannot handle the file.
 * \return SUCCESS if it succeeds.
 */
int write_loader64(const PE64 pe64, const Loader loader) {
    FILE *pe_file = NULL;
    unsigned int filled = 0;
    unsigned int i = 0;
    const uint8_t null = 0x00;

    pe_file = fopen(pe64->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return FILE_ERROR;
    }

    fseek(pe_file, 0, SEEK_END);
    fwrite((void *)loader->payload, loader->length * sizeof(*loader->payload), 1, pe_file);
    printf("[+] Save payload\n");

    /* Fill the rest of the section */
    filled = pe64->optional_header->FileAlignment - loader->length * sizeof(*loader->payload);
    for (i = 0; i < filled; i = i + 1)
        fwrite(&null, sizeof(null), 1, pe_file);

    fclose(pe_file);
    return SUCCESS;
}

/**
 * \fn int save_dump64(const PE64 pe64)
 * \brief Save all the PE headers into the file.
 *
 * \param  pe64 Dump of the PE headers.
 *
 * \return FILE_ERROR if it cannot handle the file.
 * \return SUCCESS if it succeeds.
 */
int save_dump64(const PE64 pe64) {
    FILE *pe_file = NULL;
    unsigned int i = 0;

    pe_file = fopen(pe64->filename, "rb+");
    if (pe_file == NULL) {
        perror("Error: cannot open the file");
        return FILE_ERROR;
    }

    printf("[+] Save the new PE headers:\n");
    fseek(pe_file, pe64->offset_dos_header, SEEK_SET);
    fwrite((void *)pe64->dos_header, sizeof(IMAGE_DOS_HEADER), 1, pe_file);
    printf("\tDOS header saved\n");

    fseek(pe_file, pe64->offset_pe_header, SEEK_SET);
    fwrite((void *)pe64->pe_header, sizeof(IMAGE_NT_HEADERS64), 1, pe_file);
    printf("\tPE header saved\n");

    fseek(pe_file, pe64->offset_coff_header, SEEK_SET);
    fwrite((void *)pe64->coff_header, sizeof(IMAGE_FILE_HEADER), 1, pe_file);
    printf("\tCOFF header saved\n");

    fseek(pe_file, pe64->offset_optional_header, SEEK_SET);
    fwrite((void *)pe64->optional_header, sizeof(IMAGE_OPTIONAL_HEADER64), 1, pe_file);
    printf("\tOPTIONAL header saved\n");

    fseek(pe_file, pe64->offset_first_section_header, SEEK_SET);
    for (i = 0; i < pe64->number_of_sections; i = i + 1) {
        fwrite((void *)pe64->sections_headers[i], sizeof(IMAGE_SECTION_HEADER), 1, pe_file);
        printf("\tSECTION header saved (%s)\n", pe64->sections_headers[i]->Name);
    }

    fclose(pe_file);
    return SUCCESS;
}
