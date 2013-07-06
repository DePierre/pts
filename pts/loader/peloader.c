#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <peloader.h>

/*! \arg \c loader the loader structure to be filled
 * \arg \c payload the payload of the loader
 * \arg \c oep the original entry point for the payload
 * \return 0 if it failed
 * \return 1 if it succeed
 */
int init_loader(Loader loader, const uint8_t *payload, const unsigned int length, const int offset_oep) {
    if (loader == NULL) {
        fputs("Loader cannot be null", stderr);
        return 0;
    }

    loader->payload = (uint8_t *)calloc(1, length * sizeof(*payload));
    if (loader->payload == NULL) {
        perror("Error: cannot allocate memory for payload");
        return 0;
    }

    memcpy(loader->payload, payload, length * sizeof(*payload));

    loader->length = length;

    loader->offset_oep = offset_oep;

    return 1;
}
