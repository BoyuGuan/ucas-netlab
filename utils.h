
// 防止重复编译
#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <signal.h>
// #include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>

// #include <stdarg.h>
// #include <unistd.h>
// #include <ctype.h>
// #include <setjmp.h>
// #include <dirent.h>
// #include <sys/time.h>
// #include <sys/types.h>
// #include <sys/wait.h>
// #include <math.h>
// #include <semaphore.h>
// #include <sys/socket.h>
// #include <netinet/in.h>

#define HOSTNAME_LEN 512
#define PORT_LEN 8
#define ONE_K_SIZE  1024
#define FOUR_K_SIZE  4096
#define BUFFER_SIZE 8192
#define SHORT_STRING_BUF 32
#define MIDDLE_STRING_BUF 128
#define SIZE_T_MAX 0xffffffffffffffff   // 默认设为最大值，方便探查是否指定范围
#define LONG_STRING_BUF ONE_K_SIZE
#define CHUNK_SIZE 1048576   // 传输块大小设置为1M，即一次传输512KB的数据
// #define CHUNK_SIZE 3145728  // 传输块大小设置为1M，即一次传输1M的数据

#define LISTEN_QUERY_MAX_LEN 512
#define RIO_BUFSIZE 8192
#define MINI_CHUNK_SIZE 1280
#define WRITE_OK 1
#define WRITE_ERROR_NOT_SHUT_DOWN_SSL  7
#define WRITE_ERROR_SHUT_DOWN_SSL 8
#define READ_ERROR -1


typedef struct {
    int rio_fd;                /* Descriptor for this internal buf */
    int rio_cnt;               /* Unread bytes in internal buf */
    char *rio_bufptr;          /* Next unread byte in internal buf */
    char rio_buf[RIO_BUFSIZE]; /* Internal buffer */
} rio_t;

typedef struct {
    SSL* ssl;                   /* ssl pointer for this internal buf */
    int rio_cnt;               /* Unread bytes in internal buf */
    char *rio_bufptr;          /* Next unread byte in internal buf */
    char rio_buf[RIO_BUFSIZE]; /* Internal buffer */
} rio_ssl_t;


struct thread_80_request{   // 80线程处理函数的参数结构
    int connectFD;  // 线程对应连接的文件描述符
    char clientHostName[HOSTNAME_LEN];  // 线程对应连接的客户端地址
};

struct thread_443_request { // 443线程处理函数的参数结构
	int connectFD;
	SSL_CTX *ctx;
};

void sigpipe_handler(int unused);

// robust IO 健壮性的读写
void rio_readinitb(rio_t *rp, int fd) ;
int rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen);
int rio_writen(int fd, void *usrbuf, size_t n) ;

// ssl版本的robust IO
void rio_ssl_readinitb(rio_ssl_t *rp, SSL* ssl);
int rio_ssl_readlineb(rio_ssl_t *rp, void *usrbuf, size_t maxlen);
int rio_ssl_writen(SSL* ssl, void *usrbuf, size_t n);



void server_error(char *errorMsessage);
int open_listen_fd(char *port);
void closeConnection(SSL* ssl, int connectFD, int shutDownSSL);
void get_filetype(char *filename, char *filetype);






#endif
