CC=gcc
CFLAGS=-Wall
CFLAGS+=-DDEBUG
LDFLAGS=-lnet -lcrypto -lssl
EXEC=client
SRC= network_util.c encrypt.c ../util.c ../md5.c ../server/secret.c counter.c main.c
OBJ= $(SRC:.c=.o)

all: $(EXEC)

client: $(OBJ)
		$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o ../*.o

mrproper: clean
	rm -rf $(EXEC)