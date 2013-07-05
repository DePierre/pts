#include <stdlib.h>
#include <stdio.h>

#include <pestruct.h>
#include <peviewer.h>
#include <pepacker.h>
#include <pepacker32.h>
#include <peloader.h>

int add_section(const char *filename, Loader loader) {
    switch (get_arch_pe(filename)) {
        case PECLASS32:
            add_section32(filename, loader);
            break;
        default:
            fputs("Error: unknow architecture", stderr);
            return 0;
    }

    return 1;
}
