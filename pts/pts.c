#include <stdlib.h>
#include <stdio.h>

#include <peviewer.h>
#include <payload.h>
#include <peloader.h>
#include <pepacker.h>

int main(int argc, char *argv[]) {
    Loader loader = NULL;

    printf("Hello world!\n");

    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(1);
    }

    if (!is_pe(argv[1])) {
        printf("Error: %s is not a valid PE\n", argv[1]);
        exit(1);
    }

    loader = (Loader)calloc(1, sizeof(Struct_Loader));
    if (loader == NULL) {
        printf("Error: cannot allocate memory for the loader\n");
        exit(1);
    }
    init_loader(loader, x86_32_jump_far, 0x1);
    add_section(argv[1], loader);

    return 0;
}
