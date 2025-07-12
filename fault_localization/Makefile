SHELL:=/bin/bash

.PHONY: all

INCLUDE_DIR = ./include

# DEBUG_FLAG = -g
CFLAGS = -I$(INCLUDE_DIR) -Wall $(DEBUG_FLAG) -c -fPIC -pthread -lgcc_s -D_IV_DEBUG -DSECCOMP_DENY_epoll_wait
CSHARED_FLAG = -I$(INCLUDE_DIR) -fPIC -shared -ldl
OBJ_DIR = ./objs/

CC = gcc
LD = ld
LDFLAGS = -r
MAKE = make

all: 
	mkdir -p $(OBJ_DIR)
	$(MAKE) FL

FL: $(OBJ_DIR)main.o $(OBJ_DIR)control.o $(OBJ_DIR)instrumented.o util.o
	$(LD) -o $@.o $(LDFLAGS) $^

$(OBJ_DIR)%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf FL.o $(OBJ_DIR)

.PHONY: clean
