CC=clang
CFLAGS=-Wall -Wextra -pedantic
all: tcp-listen
clean:
	@rm -f tcp-listen
