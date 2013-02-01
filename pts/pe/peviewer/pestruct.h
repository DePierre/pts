#ifndef PESTRUCT_H
#define PESTRUCT_H

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

typedef struct _IMAGE_DOS_HEADER {
    unsigned short e_magic;      /* 00: MZ Header signature */
    unsigned short e_cblp;       /* 02: Bytes on last page of file */
    unsigned short e_cp;         /* 04: Pages in file */
    unsigned short e_crlc;       /* 06: Relocations */
    unsigned short e_cparhdr;    /* 08: Size of header in paragraphs */
    unsigned short e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    unsigned short e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    unsigned short e_ss;         /* 0e: Initial (relative) SS value */
    unsigned short e_sp;         /* 10: Initial SP value */
    unsigned short e_csum;       /* 12: Checksum */
    unsigned short e_ip;         /* 14: Initial IP value */
    unsigned short e_cs;         /* 16: Initial (relative) CS value */
    unsigned short e_lfarlc;     /* 18: File address of relocation table */
    unsigned short e_ovno;       /* 1a: Overlay number */
    unsigned short e_res[4];     /* 1c: Reserved words */
    unsigned short e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
    unsigned short e_oeminfo;    /* 26: OEM information; e_oemid specific */
    unsigned short e_res2[10];   /* 28: Reserved words */
    unsigned long e_lfanew;      /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    unsigned long VirtualAddress;
    unsigned long Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
    unsigned short Machine;
    unsigned short NumberOfSections;
    unsigned long TimeDateStamp;
    unsigned long PointerToSymbolTable;
    unsigned long NumberOfSymbols;
    unsigned short SizeOfOptionalHeader;
    unsigned short Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
    unsigned short Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    unsigned long SizeOfCode;
    unsigned long SizeOfInitializedData;
    unsigned long SizeOfUnitializedData;
    unsigned long AddressOfEntryPoint;
    unsigned long BaseOfCode;
    unsigned long BaseOfData;
    unsigned long ImageBase;
    unsigned long SectionAlignment;
    unsigned long FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinprImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned long Win32VersionValue;
    unsigned long SizeOfVersion;
    unsigned long SizeOfHeaders;
    unsigned long CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned short SizeOfStackReserve;
    unsigned short SizeOfStackCommit;
    unsigned short SizeOfHeapReserve;
    unsigned short SizeOfHeapCommit;
    unsigned short LoaderFlags;
    unsigned short NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    unsigned short Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    unsigned long SizeOfCode;
    unsigned long SizeOfInitializedData;
    unsigned long SizeOfUninitializedData;
    unsigned long AddressOfEntryPoint;
    unsigned long BaseOfCode;
    unsigned long long ImageBase;
    unsigned long SectionAlignment;
    unsigned long FileAlignment;
    unsigned short MajorOperationgSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned long Win32VersionValue;
    unsigned long SizeOfImage;
    unsigned long SizeOfImage;
    unsigned long SizeOfHeaders;
    unsigned long CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned long long SizeOfStackReserve;
    unsigned long long SizeOfStackCommit;
    unsigned long long SizeOfHeapReserve;
    unsigned long long SizeOfHeapCommit;
    unsigned long LoaderFlags;
    unsigned long NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIE];
} IMAGE_OPTIONAL_HEADER64; *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS {
    unsigned long Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_NT_HEADER64 {
    unsigned long Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER_64 OptionalHeader;
} IMAGE_NT_HEADER64, *PIMAGE_NT_HEADERS64;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
    unsigned char Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        unsigned long PhysicalAddress;
        unsigned long VirtualSize;
    } Misc;
    unsigned long VirtualAddress;
    unsigned long SizeOfRawData;
    unsigned long PointerToRawData;
    unsigned long PointerToRelocations;
    unsigned long PointerToLinenumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLinenumbers;
    unsigned long Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#endif /* PESTRUCT_H */
