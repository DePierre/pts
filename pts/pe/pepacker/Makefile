SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

INCLUDES = -I. -I../peviewer/ -I../../loader/

all: libPEPacker.so

libPEPacker.so: $(OBJ)
	$(CC) -o $@ $^ -shared -fPIC $(CCFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CCFLAGS) $(INCLUDES)

clean:
	rm -f *.o *.so
