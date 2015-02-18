CC=gcc
CFLAGS=-Wall
LDFLAGS=-lnet -lcrypto -lssl
EXEC=client
SRC= udp_packet.c encrypt.c ../util.c ../md5.c main.c
OBJ= $(SRC:.c=.o)

all: $(EXEC)

client: $(OBJ)
		$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)