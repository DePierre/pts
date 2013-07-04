export CC = gcc
export CCFLAGS = -W -Wall -ansi -pedantic -Werror -m32

TARGET = pts.out
SRC = pts.c ./loader/peloader.c
OBJ = $(SRC:.c=.o)

LOADER_DIR = ./loader
PEVIEWER_DIR = ./pe/peviewer/
PEVIEWER_LIB = PEViewer
PEPACKER_DIR = ./pe/pepacker/
PEPACKER_LIB = PEPacker

DIR = -I. -I$(LOADER_DIR) -I$(PEVIEWER_DIR) -I$(PEPACKER_DIR)

all: $(TARGET)

$(TARGET): $(OBJ)
	cd $(PEVIEWER_DIR) && $(MAKE)
	cd $(PEPACKER_DIR) && $(MAKE)
	$(CC) $(CCFLAGS) -L$(PEVIEWER_DIR) -L$(PEPACKER_DIR) -l$(PEVIEWER_LIB) -l$(PEPACKER_LIB) -o $@ $^

%.o: %.c
	$(CC) $(CCFLAGS) -I$(DIR) -o $@ -c $<

clean:
	cd $(PEVIEWER_DIR) && $(MAKE) $@
	cd $(PEPACKER_DIR) && $(MAKE) $@
	rm -f *.o ./loader/*.o *.out
