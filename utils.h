
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
#define BUFFER_SZIE 8192
#define SHORT_STRING_BUF 32
#define MIDDLE_STRING_BUF 128
#define LONG_STRING_BUF ONE_K_SIZE
// #define CONTENT_BUFFER 4096 << 4



#define LISTEN_QUERY_MAX_LEN 512

#define RIO_BUFSIZE ONE_K_SIZE << 3
typedef struct {
    int rio_fd;                /* Descriptor for this internal buf */
    int rio_cnt;               /* Unread bytes in internal buf */
    char *rio_bufptr;          /* Next unread byte in internal buf */
    char rio_buf[RIO_BUFSIZE]; /* Internal buffer */
} rio_t;




void rio_readinitb(rio_t *rp, int fd) ;
int rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen);
void rio_writen(int fd, void *usrbuf, size_t n) ;


void server_error(char *errorMsessage);
int open_listen_fd(char *port);












#endif
