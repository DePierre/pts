export CC = gcc
export CCFLAGS = -W -Wall -ansi -pedantic -Werror -m32 -g

TARGET = pts.out

LOADER_DIR = ./loader/
PEVIEWER_DIR = ./pe/peviewer/
PEPACKER_DIR = ./pe/pepacker/
PEPACKER_LIB = PEPacker

DIR = -I. -I$(LOADER_DIR) -I$(PEVIEWER_DIR) -I$(PEPACKER_DIR)

SRC = $(wildcard *.c) $(wildcard $(LOADER_DIR)*.c) $(wildcard $(PEVIEWER_DIR)*.c) $(wildcard $(PEPACKER_DIR)*.c)
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CCFLAGS) $(DIR) -o $@ $^

%.o: %.c
	$(CC) $(CCFLAGS) $(DIR) -o $@ -c $<

clean:
	rm -f *.o $(LOADER_DIR)*.o $(PEVIEWER_DIR)*.o $(PEPACKER_DIR)*.o *.out
