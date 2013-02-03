#ifndef PESTRUCT_H
#define PESTRUCT_H

#include <stdint.h>

/* These defines describe the meanings of the bits in the Characteristics field */
#define IMAGE_FILE_RELOCS_STRIPPED      0x0001 /* No relocation info */
#define IMAGE_FILE_EXECUTABLE_IMAGE     0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED   0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED  0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM    0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE  0x0020
#define IMAGE_FILE_16BIT_MACHINE        0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO    0x0080
#define IMAGE_FILE_32BIT_MACHINE        0x0100
#define IMAGE_FILE_DEBUG_STRIPPED       0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP      0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP    0x0800
#define IMAGE_FILE_SYSTEM               0x1000
#define IMAGE_FILE_DLL                  0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY       0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI    0x8000

/* These are the settings of the Machine field. */
#define IMAGE_FILE_MACHINE_UNKNOWN      0
#define IMAGE_FILE_MACHINE_I386         0x014c
#define IMAGE_FILE_MACHINE_ARM          0x01c0
#define IMAGE_FILE_MACHINE_AMD64        0x8664

#define IMAGE_DOS_SIGNATURE 0x5A4D /* MZ */
#define IMAGE_NT_SIGNATURE 0x00004550 /* PE00 */
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

/* Max length of the section name */
#define IMAGE_SIZEOF_SHORT_NAME 8
/* These are the value of Magic from Optional header to know if it's wether 32
 * bits or 64 bits application */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B

typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;      /* 00: MZ Header signature */
    uint16_t e_cblp;       /* 02: Bytes on last page of file */
    uint16_t e_cp;         /* 04: Pages in file */
    uint16_t e_crlc;       /* 06: Relocations */
    uint16_t e_cparhdr;    /* 08: Size of header in paragraphs */
    uint16_t e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    uint16_t e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    uint16_t e_ss;         /* 0e: Initial (relative) SS value */
    uint16_t e_sp;         /* 10: Initial SP value */
    uint16_t e_csum;       /* 12: Checksum */
    uint16_t e_ip;         /* 14: Initial IP value */
    uint16_t e_cs;         /* 16: Initial (relative) CS value */
    uint16_t e_lfarlc;     /* 18: File address of relocation table */
    uint16_t e_ovno;       /* 1a: Overlay number */
    uint16_t e_res[4];     /* 1c: Reserved words */
    uint16_t e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
    uint16_t e_oeminfo;    /* 26: OEM information; e_oemid specific */
    uint16_t e_res2[10];   /* 28: Reserved words */
    uint32_t e_lfanew;      /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUnitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinprImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfVersion;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperationgSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
    unsigned char Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#endif /* PESTRUCT_H */
