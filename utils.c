#include "utils.h"

void server_error(char *errorMsessage){
    printf("%s", errorMsessage);
    fprintf(stderr, "%s: %s", strerror(errno) );
    exit(1);
}


void rio_readinitb(rio_t *rp, int fd) 
{
    rp->rio_fd = fd;  
    rp->rio_cnt = 0;  
    rp->rio_bufptr = rp->rio_buf;
}


/* 
 * rio_read - This is a wrapper for the Unix read() function that
 *    transfers min(n, rio_cnt) bytes from an internal buffer to a user
 *    buffer, where n is the number of bytes requested by the user and
 *    rio_cnt is the number of unread bytes in the internal buffer. On
 *    entry, rio_read() refills the internal buffer via a call to
 *    read() if the internal buffer is empty.
 */
/* $begin rio_read */
static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n)
{
    int cnt;

    while (rp->rio_cnt <= 0) {  /* Refill if buf is empty */
        rp->rio_cnt = read(rp->rio_fd, rp->rio_buf, sizeof(rp->rio_buf));
        if (rp->rio_cnt < 0) {
            if (errno != EINTR) /* Interrupted by system call*/
                return -1;
        }
        else if (rp->rio_cnt == 0)  /* EOF */
            return 0;
        else 
            rp->rio_bufptr = rp->rio_buf;   /* Read success, reset buffer ptr */
    }

    /* Copy min(n, rp->rio_cnt) bytes from internal buf to user buf */
    cnt = n;
    if(rp->rio_cnt < n)
        cnt = rp->rio_cnt;
    memcpy(usrbuf, rp->rio_bufptr, cnt);
    rp->rio_bufptr += cnt;
    rp->rio_cnt -= cnt;
    return cnt;
}
/* $end rio_read */

// Robustly read a text line (buffered)
int rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen) 
{
    int n, rc;
    char c, *bufp = usrbuf;

    for (n = 1; n < maxlen; n++) { 
        if ((rc = rio_read(rp, &c, 1)) == 1) {
            // read success
            *bufp++ = c;
            if (c == '\n') {
                n++;
                break;
            }
        } else if (rc == 0) {
            if (n == 1)
                return 0; /* EOF, no data read */
            else
                break;    /* EOF, some data was read */
        } else
            server_error("rio_readlineb Error!");	  /* Error */
    }

    *bufp = 0;
    if ( n - 1 < 0)
        server_error("Rio_readline Error!");
    return n-1;
}


void rio_writen(int fd, void *usrbuf, size_t n) 
{
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0) {
        if ((nwritten = write(fd, bufp, nleft)) <= 0) {
            if (errno == EINTR)  /* Interrupted by system call */
                nwritten = 0;    /* and call write() again */
            else
                server_error("rio_writen Error!");       /* errno set by write() */
        }
        nleft -= nwritten;
        bufp += nwritten;
    }
}


int open_listen_fd(char *port){
    struct addrinfo hints, *addrInfoList, *addressPointer;
    int listenFD, rc, optval = 1;

    memset(&hints, 0, sizeof(struct addrinfo));  // 初始制空
    hints.ai_socktype = SOCK_STREAM;             // TCP传输
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;   
    hints.ai_flags |= AI_NUMERICSERV;            // 连接默认设置
    
    if ((rc = getaddrinfo(NULL, port, &hints, &addrInfoList)) != 0) {
        // 获取addrInfoList失败
        fprintf(stderr, "getaddrinfo failed (port %s): %s\n", port, gai_strerror(rc));
        server_error("openListenFD error");
    }

    for ( addressPointer = addrInfoList; addressPointer ; addressPointer->ai_next){
        if( (listenFD = socket(addressPointer->ai_family, addressPointer->ai_socktype, addressPointer->ai_protocol)) < 0 )
            // 创建对应描述符失败，尝试下一个节点能不能创建
            continue;
        // 打开或关闭地址复用功能。防止出现地址已经被使用错误.    指针，指向存放选项值的缓冲区
        setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
        if(bind(listenFD, addressPointer->ai_addr, addressPointer->ai_addrlen) == 0)
            break;
        if(close(listenFD) < 0) { // 关闭失败
            fprintf(stderr, "open listen fd close faild: %s\n", strerror(errno) );
            server_error("open_listen_fd error");
        }
        
    }

    freeaddrinfo(addrInfoList);
    if(!addressPointer)
        server_error("openListenFD error");
    if(listen(listenFD, LISTEN_QUERY_MAX_LEN) < 0 ){
        close(listenFD);
        fprintf(stderr, "listen function faild: %s\n", strerror(errno) );
        server_error("open_listen_fd error");
    }
    return listenFD;
 }
    

