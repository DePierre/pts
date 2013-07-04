#include <stdio.h>
#include <stdlib.h>

#include <peloader.h>

/*! \arg \c loader the loader structure to be filled
 * \arg \c payload the payload of the loader
 * \arg \c oep the original entry point for the payload
 * \return 0 if it failed
 * \return 1 if it succeed
 */
int init_loader(Loader loader, const char *payload, const unsigned int oep) {
    if (loader == NULL) {
        printf("Error: loader structure is NULL\n");
        return 0;
    }

    loader->payload = (char*)calloc(1, sizeof(payload));
    if (loader->payload == NULL) {
        printf("Error: cannot allocate memory for payload\n");
        return 0;
    }
    memcpy(loader->payload, payload, sizeof(payload));
    loader->size = (unsigned int)sizeof(loader->payload);

    if (!oep) {
        printf("Error: oep cannot be 0\n");
        return -1;
    }
    loader->oep = (unsigned int)oep;

    return 1;
}
