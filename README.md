Welcome to the repo of PackThatShit!


PTS is a C tool providing the ability of packing PE and ELF files, oh yeah!
It will compress and encrypt the target file.


It will contain a CLI to allow the user to chose between two methods of packing:
    -fill the end of the code section if there is enough space
    -or create a new section containing the loader code (aka Jump Far method)


The first main part of the project is to code a PE viewer and ELF viewer (like
readelf).
Of course tools already exist to do this but it's more interesting to code it
by ourselves.


The second main part is the packer itself, where PTS has to manage the
informations to modify to headers and co.


And finally, there is the loader.
We are dealing here with ASM code in order to write a loader which will decode
and decompress the sections
We will surely have to write several ones to run with Windows and GNU/Linux.


This project is created by the HackGyver which is a lovely place to be.
So sweet!


Enjoy!


TODO:
    -everything god damn it!
