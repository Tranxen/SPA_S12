CC=gcc
CFLAGS=
LDFLAGS=-lpcap -lcrypto -lssl -lpthread
EXEC=server
SRC= capture.c decrypt.c spa_parser.c antireplay.c txlist.c ../util.c ../md5.c main.c
OBJ= $(SRC:.c=.o)

all: $(EXEC)

server: $(OBJ)
		$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)
