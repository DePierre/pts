#include <stdlib.h>
#include <stdio.h>

#include <peviewer.h>
#include <peviewer32.h>
#include <peviewer64.h>
#include <payload.h>
#include <peloader.h>
#include <pepacker32.h>
#include <pepacker64.h>

int main(int argc, char *argv[]) {
    Loader loader = NULL;
    PE32 pe32 = NULL;
    PE64 pe64 = NULL;

    printf("Hello world!\n");

    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(1);
    }

    if (is_pe(argv[1])) {
        printf("Error: %s is not a valid PE\n", argv[1]);
        exit(1);
    }

    loader = (Loader)calloc(1, sizeof(Struct_Loader));
    if (loader == NULL) {
        perror("Error: cannot allocate memory for loader");
        exit(1);
    }
    init_loader(loader, x86_32_jump_far, 7, 1);

    switch (get_arch_pe(argv[1])) {
        case PECLASS32:
            printf("[+] PE 32bits detected\n");
            dump_pe32(argv[1], &pe32);
            pack32(&pe32, loader);
            delete_pe32(&pe32);
            break;
        case PECLASS64:
            printf("[+] PE 64bits detected\n");
            dump_pe64(argv[1], &pe64);
            pack64(&pe64, loader);
            delete_pe64(&pe64);
            break;
        default:
            printf("[!] Unknown file\n");
    }

    return 0;
}
