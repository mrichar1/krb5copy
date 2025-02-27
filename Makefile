# Variables
CC = gcc
CFLAGS = -o krb5copy -l krb5
SRC = krb5copy.c
DEST = /usr/local/bin/krb5copy

# Default target: build the program
all:
	$(CC) $(SRC) $(CFLAGS)

# Install target: copy the binary to /usr/local/bin
install: all
	sudo cp krb5copy $(DEST)
	sudo chmod +x $(DEST)

# Clean target: remove the binary
clean:
	rm -f krb5copy

# Phony targets to prevent conflicts with file names
.PHONY: all install clean

