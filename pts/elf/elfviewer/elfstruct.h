#ifndef ELFSTRUCT_H
#define ELFSTRUCT_H

#include <stdint.h>

#define EI_NIDENT 16

/* ELF header */

typedef struct _Elf32_Ehdr {
    unsigned char e_ident[EI_NIDENT];   /* File identification */
    uint16_t e_type;                    /* File type */
    uint16_t e_machine;                 /* Machine architecture */
    uint32_t e_version;                 /* ELF format version */
    uint32_t e_entry;                   /* Entry point */
    uint32_t e_phoff;                   /* Program header file offset */
    uint32_t e_shoff;                   /* Section header file offset */
    uint32_t e_flags;                   /* Architecture-specific flags */
    uint16_t e_ehsize;                  /* Size of ELF header in bytes */
    uint16_t e_phentsize;               /* Size of program header entry */
    uint16_t e_phnum;                   /* Number of program header entries */
    uint16_t e_shentsize;               /* Size of section header entry */
    uint16_t e_shnum;                   /* Number of section header entries */
    uint16_t e_shtrndx;                 /* Section name strings section */
} Elf32_Ehdr, *PElf32_Ehdr;

typedef struct _Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    uint32_t e_type;
    uint32_t e_machine;
    uint64_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint64_t e_flags;
    uint32_t e_ehsize;
    uint32_t e_phentsize;
    uint32_t e_phnum;
    uint32_t e_shentsize;
    uint32_t e_shnum;
    uint32_t e_shtrndx;
} Elf64_Ehdr, *PElf64_Ehdr;

/* Section header */

typedef struct _Elf32_Shdr {
    uint32_t sh_name;      /* Section name (index into the
                               section header string table). */
    uint32_t sh_type;      /* Section type. */
    uint32_t sh_flags;     /* Section flags. */
    uint32_t sh_addr;      /* Address in memory image. */
    uint32_t sh_offset;    /* Offset in file. */
    uint32_t sh_size;      /* Size in bytes. */
    uint32_t sh_link;      /* Index of a related section. */
    uint32_t sh_info;      /* Depends on section type. */
    uint32_t sh_addralign; /* Alignment in bytes. */
    uint32_t sh_entsize;   /* Size of each entry in section. */
} Elf32_Shdr, *PElf32_Shdr;

typedef struct _Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr, *PElf64_Shdr;

/* Program header */

typedef struct _Elf32_Phdr{
    uint32_t p_type;     /* Entry type. */
    uint32_t p_offset;   /* File offset of contents. */
    uint32_t p_vaddr;    /* Virtual address in memory image. */
    uint32_t p_paddr;    /* Physical address (not used). */
    uint32_t p_filesz;   /* Size of contents in file. */
    uint32_t p_memsz;    /* Size of contents in memory. */
    uint32_t p_flags;    /* Access permission flags. */
    uint32_t p_align;    /* Alignment in memory and file. */
} Elf32_Phdr, *PElf32_Phdr;

typedef struct _Elf64_Phdr{
    uint32_t p_type;     /* Entry type. */
    uint32_t p_flags;    /* Access permission flags. */
    uint64_t p_offset;   /* File offset of contents. */
    uint64_t p_vaddr;    /* Virtual address in memory image. */
    uint64_t p_paddr;    /* Physical address (not used). */
    uint64_t p_filesz;   /* Size of contents in file. */
    uint64_t p_memsz;    /* Size of contents in memory. */
    uint64_t p_align;    /* Alignment in memory and file. */
} Elf64_Phdr, *PElf64_Phdr;

/* Dynamic structure.  The ".dynamic" section contains an array of them */

typedef struct _Elf32_Dyn{
    int32_t d_tag;       /* Entry type. */
    union {
        uint32_t d_val;  /* Integer value. */
        uint32_t d_ptr;  /* Address value. */
    } d_un;
} Elf32_Dyn, *PElf32_Dyn;

typedef struct _Elf64_Dyn{
    uint64_t d_tag;      /* Entry type. */
    union {
        uint64_t d_val;  /* Integer value. */
        uint64_t d_ptr;  /* Address value. */
    } d_un;
} Elf64_Dyn, *PElf64_Dyn;

/* Relocation entries */

/* Relocations that don't need an addend field. */
typedef struct _Elf32_Rel{
    uint32_t r_offset;   /* Location to be relocated. */
    uint32_t r_info;     /* Relocation type and symbol index. */
} Elf32_Rel, *PElf32_Rel;

/* Relocations that need an addend field. */
typedef struct _Elf32_Rela{
    uint32_t r_offset;   /* Location to be relocated. */
    uint32_t r_info;     /* Relocation type and symbol index. */
    int32_t r_addend;    /* Addend. */
} Elf32_Rela, *PElf32_Rela;

/* Relocations that don't need an addend field. */
typedef struct _Elf64_Rel{
    uint64_t r_offset;   /* Location to be relocated. */
    uint64_t r_info;     /* Relocation type and symbol index. */
} Elf64_Rel, *PElf64_Rel;

/* Relocations that need an addend field. */
typedef struct _Elf64_Rela{
    uint64_t r_offset;   /* Location to be relocated. */
    uint64_t r_info;     /* Relocation type and symbol index. */
    uint64_t r_addend;   /* Addend. */
} Elf64_Rela, *PElf64_Rela;

/* Symbol table entries */

typedef struct _Elf32_Sym{
    uint32_t st_name;    /* String table index of name. */
    uint32_t st_value;   /* Symbol value. */
    uint32_t st_size;    /* Size of associated object. */
    unsigned char st_info;    /* Type and binding information. */
    unsigned char st_other;   /* Reserved (not used). */
    uint16_t st_shndx;   /* Section index of symbol. */
} Elf32_Sym, *PElf32_Sym;

typedef struct _Elf64_Sym{
    uint32_t st_name;    /* String table index of name. */
    unsigned char st_info;    /* Type and binding information. */
    unsigned char st_other;   /* Reserved (not used). */
    uint16_t st_shndx;   /* Section index of symbol. */
    uint64_t st_value;   /* Symbol value. */
    uint64_t st_size;    /* Size of associated object. */
} Elf64_Sym, *PElf64_Sym;

#endif /* ELFSTRUCT_H */
