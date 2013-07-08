Welcome to the repo of PTS!
===================================

Fork from HackGyver
-------------------


PTS is a C tool providing the ability of packing PE and ELF files.
It will compress and encrypt the target file.


The first main part of the project is to code a PE viewer and ELF viewer (like
readelf).
Of course tools already exist to do this but it's more interesting to code it
by ourselves.


The second main part is the packer itself, where PTS has to manage the
informations to modify to headers and co.
