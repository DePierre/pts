export CC = gcc
export CCFLAGS = -W -Wall -ansi -pedantic -Werror -m32

TARGET = pts.out
SRC = pts.c
OBJ = $(SRC:.c=.o)

PEVIEWER_DIR = ./pe/peviewer/
PEVIEWER_LIB = Peviewer

all: $(TARGET)

$(TARGET): $(OBJ)
	cd $(PEVIEWER_DIR) && $(MAKE)
	$(CC) $(CCFLAGS) -L$(PEVIEWER_DIR) -l$(PEVIEWER_LIB) -o $@ $^

%.o: %.c
	$(CC) $(CCFLAGS) -I$(PEVIEWER_DIR) -o $@ -c $<

clean:
	cd $(PEVIEWER_DIR) && $(MAKE) $@
	rm -f *.o *.out
