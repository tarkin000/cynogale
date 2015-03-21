CC=gcc
CFLAGS=-O3 -UDEBUG -DNO_CGI -DNO_SSL -DPH7_ENABLE_MATH_FUNC -DPH7_ENABLE_THREADS
LDFLAGS=-lm -ldl -lrt -lpthread
LIBDIR=/usr/local/lib

.PHONY: all libph7

all: cynogale

civetweb.o: civetweb.c
	$(CC) $(CFLAGS) -c $^

vedis.o: vedis.c
	$(CC) $(CFLAGS) -c $^

ph7.o: ph7.c
	$(CC) $(CFLAGS) -c $^

cynogale: main.c civetweb.o ph7.o
	$(CC) -g -DNO_SSL -DUSE_SQLITE -DSCRIPT_CACHE -o $@ $^ -lph7 $(LDFLAGS) -lsqlite3
#	$(CC) $(CFLAGS) -DUSE_SQLITE -DSCRIPT_CACHE -o $@ $^ -lph7 $(LDFLAGS) -lsqlite3
#	$(CC) $(CFLAGS) -o $@ $^ -lph7 $(LDFLAGS)
#	$(CC) -g -DNO_SSL -o $@ $^ -lph7 $(LDFLAGS)

