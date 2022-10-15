all: http-server
# GET / HTTP/1.1
http-server: *.c
	gcc -w -g main.c utils.c utils.h -o http-server -lssl -lcrypto -lpthread

clean:
	@rm http-server
