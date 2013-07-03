#include <stdlib.h>
#include <stdio.h>

#include <peviewer.h>

int main(int argc, char *argv[]) {

    printf("Hello world!\n");

    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(1);
    }

    if (!is_pe(argv[1])) {
        printf("Error: %s is not a valid PE\n", argv[1]);
        exit(1);
    }

    return 0;
}
