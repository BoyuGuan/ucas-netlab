#include "utils.h"

void clienterror(int fd, char *cause, char *errnum, char *shortErroMessage, char *longErrorMessage);
void read_requesthdrs(rio_t *rp, char* partialRange);
void *handle_80_thread(void* arg);
int parseURL(char* url, char* fileName);
void serve_static(int fd, char *fileName, int serverCode, char* shortErrorMessage, char* range); //多传一个是否需要加密
void serve_video(int fd, char *fileName, int serviceCode, char *serviceShortMesssage, char* range);
void get_filetype(char *filename, char *filetype);


int main(int argc, char** argv)
{
    char clientHostName[HOSTNAME_LEN], clientPort[PORT_LEN];
    pid_t process443Pid, process80Pid;

    // 创建两个子进程，一个是进程处理443的https，一个进程处理80的http
    if ( (process443Pid = fork()) == 0  )
    {   // 443端口的子进程
        int listen443FD = open_listen_fd("443");
        // printf("443 port listen fd is %d \n", listen443FD);
        prctl(PR_SET_PDEATHSIG, SIGTERM);  // 父进程死后杀死自己
        int  conn443FD;
        struct sockaddr_storage clientAddress;
        __socklen_t clientLen = sizeof(clientAddress);
        while (1)
        {
            if((conn443FD = accept(listen443FD,  &clientAddress, &clientLen ) ) < 0 ) 
                server_error("443 port accept error!");
            if( getnameinfo(&clientAddress, clientLen, clientHostName, \
                    HOSTNAME_LEN, clientPort, PORT_LEN, 0) != 0 )
                server_error("443 port getnameinfo error");
        }
        
    }
    else{
        if ( (process80Pid = fork()) == 0  )
        {   // 80端口的子进程
            int listen80FD = open_listen_fd("80");
            // printf("80 port listen fd is %d \n", listen80FD);
            prctl(PR_SET_PDEATHSIG, SIGTERM);  // 父进程死后杀死自己
            struct sockaddr_storage clientAddress;
            __socklen_t clientLen = sizeof(clientAddress);
            pthread_t newThreadID;
            while (1){
                // 注意此处一定要用conn80FD_P指向一个malloc出来的值，否则用实例传地址的话会导致主线程下一步for循环覆盖掉这个实例
                int *conn80FD_P = malloc(sizeof(int)); 
                if((*conn80FD_P = accept(listen80FD,  &clientAddress, &clientLen ) ) < 0 ) 
                    server_error("80 port accept error!");

                // if((*conn80FD_P = accept(listen80FD,  &clientAddress, &clientLen ) ) < 0 ) 
                //     server_error("80 port accept error!");
                if( getnameinfo(&clientAddress, clientLen, clientHostName, \
                        HOSTNAME_LEN, clientPort, PORT_LEN, 0) != 0 )
                    server_error("80 port getnameinfo error");
                // printf("Accept connection from (%s,%s)\n", clientHostName, clientPort);
                if (pthread_create(&newThreadID, NULL, handle_80_thread, conn80FD_P) != 0)
                    server_error("Thread create error!");
                // printf("\ntest2\n");
            }
        }
        else{
            while (1)
            {
                // 服务器主进程
                ;
            }
            
        }
    }
    return 0;
}

void *handle_80_thread(void* vargp){
    // 80 端口的线程处理函数
    // printf("3123978491\n" );

    pthread_detach(pthread_self()); 
    int connectFD = *(int*) vargp;
    char requestRange[ONE_K_SIZE];
    free(vargp);
    char buf[BUFFER_SZIE], method[SHORT_STRING_BUF], url[ONE_K_SIZE], \
        httpVersion[SHORT_STRING_BUF], fileName[ONE_K_SIZE]; 
    strcpy(fileName, "");

    // 读取请求
    struct stat sbuf;
    rio_t clientRio;
    rio_readinitb(&clientRio, connectFD);
    if (!rio_readlineb(&clientRio, buf, BUFFER_SZIE))  
        // 空请求
        return;
    sscanf(buf, "%s %s %s", method, url, httpVersion );
    // printf("request is %s", buf);
    if (strcasecmp(method, "GET")) {    // 只支持GET 方法
        // char file_501[20] = 
        serve_static(connectFD, "./dir/501.html", 501, "Not Implemented", requestRange);
        return;
    }

    strcpy(requestRange, ""); 
    read_requesthdrs(&clientRio, requestRange);  //读取所有请求内容，只是读完而已，目前没啥用，因为我们只对第一条的get方法感兴趣。

    // parser url
    int ifRequestVideo = parseURL(url, fileName) ; // 请求的是否是视频

    // printf("request file is %s \n", fileName);

    if(stat(fileName, &sbuf) < 0){  // 没这文件
        serve_static(connectFD, "./dir/404.html",  404, "Not Found", requestRange);
        return;
    }
    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) { // 没有权限读的文件
        stat("./dir/403.html", &sbuf);
        serve_static(connectFD, "./dir/403.html",  403, "Forbidden", requestRange);
        return;
    }

    int successServerCode = 200; // 请求成功的类型种类（是普通请求的话是200，分段的话是206）
    char successServerShortMessage = "OK";
    if(!strcmp(requestRange,"")) { // 请求是range分段请求
        successServerCode = 206;
        strcpy(successServerShortMessage, "Partial Content");
    }
    if (!ifRequestVideo)
        serve_static(connectFD, fileName,  successServerCode, successServerShortMessage, requestRange);
    else
        serve_video(connectFD, fileName, successServerCode, successServerShortMessage, requestRange);
    
    if(close(connectFD) < 0)
        server_error("close conncet fd error!");

}


void serve_static(int fd, char *fileName, int serviceCode, char* shortErrorMessage, char* range) //多传一个是否需要加密
{   
    // printf("\n\nfilename %s   serverCode %d  meg %s\n\n", fileName, serverCode, shortErrorMessage);

    struct stat sbuf;
    stat(fileName, &sbuf);
    int srcfd, fileSize = sbuf.st_size;
    char *srcp, fileType[MIDDLE_STRING_BUF], buf[FOUR_K_SIZE];
    // printf("serverCode: %d   shortMessage: %s  file name: %s  file size : %d \n", serverCode, shortErrorMessage, fileName ,fileSize);
    /* Send response headers to client */
    get_filetype(fileName, fileType);       
    sprintf(buf, "HTTP/1.1 %d %s\r\n", serviceCode, shortErrorMessage);    
    sprintf(buf, "%sServer: Guan&Wu Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);
    sprintf(buf, "%sAccept-Ranges: bytes\r\n", buf);  // 支持分段请求
    sprintf(buf, "%sContent-length: %d\r\n", buf, fileSize);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, fileType);

    // 加密然后再存

    rio_writen(fd, buf, strlen(buf));       

    /* Send response body to client */
    if ((srcfd = open(fileName, O_RDONLY, 0)) < 0 )
        server_error("open object file error!");
    if ( (srcp = mmap(0, fileSize, PROT_READ, MAP_PRIVATE, srcfd, 0)) == ((void *) -1) )
        server_error("mmap object file function error!");
    if(close(srcfd) < 0 )
        server_error("close object file error!");
    rio_writen(fd, srcp, fileSize);
    if( munmap(srcp, fileSize) < 0 )
        server_error("unmmap object file error!");
}


void serve_video(int fd, char *fileName, int serviceCode, char *serviceShortMesssage, char *range)
{   // 待写

    struct stat sbuf;
    stat(fileName, &sbuf);
    int srcfd, fileSize = sbuf.st_size;
    int contentLength = fileSize;
    char *srcp, fileType[MIDDLE_STRING_BUF], buf[FOUR_K_SIZE];

    get_filetype(fileName, fileType);       
    sprintf(buf, "HTTP/1.1 %d %s\r\n", serviceCode, serviceShortMesssage);    
    sprintf(buf, "%sServer: Guan&Wu Web Server\r\n", buf);
    sprintf(buf, "%sConnection: keep-alive\r\n", buf);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, fileType);
    int begin, end;
    // Content-Range: bytes 0-1023/146515
    // Content-Length: 1024
    if (serviceCode == 206){
        int begin, end = -1;
        sscanf(range, "Range: bytes=%d-%d", begin, end);
        if (end == -1)
            end = fileSize - 1;
        contentLength = end - begin + 1;
        sprintf(buf, "%sContent-Range: bytes %d-%d/%d", buf, end, fileSize);
    }
    

    sprintf(buf, "%sContent-length: %d\r\n", buf, contentLength);

    // 加密然后再存


    rio_writen(fd, buf, strlen(buf));       

    /* Send response body to client */
    if ((srcfd = open(fileName, O_RDONLY, 0)) < 0 )
        server_error("open object file error!");
    if ( (srcp = mmap(0, fileSize, PROT_READ, MAP_PRIVATE, srcfd, 0)) == ((void *) -1) )
        server_error("mmap object file function error!");
    if(close(srcfd) < 0 )
        server_error("close object file error!");
    rio_writen(fd, srcp, fileSize);
    if( munmap(srcp, fileSize) < 0 )
        server_error("unmmap object file error!");

}


void get_filetype(char *filename, char *filetype) 
{
    if (strstr(filename, ".html"))
        strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
        strcpy(filetype, "image/gif");
    else if (strstr(filename, ".png"))
        strcpy(filetype, "image/png");
    else if (strstr(filename, ".jpg"))
        strcpy(filetype, "image/jpeg");
    else if (strstr(filename, ".mp4"))
        strcpy(filetype, "video/mp4");
    else
        strcpy(filetype, "text/plain");
}  


int parseURL(char* url, char* fileName){
    strcpy(fileName, "./dir");
    strcat(fileName, url);
    if (url[strlen(url)-1] == '/')     
        strcat(fileName, "index.html");
    int isVideo = 1;
    if( !( strstr(url, ".mp4") ||  strstr(url, ".avi") || strstr(url, ".mkv") || strstr(url, ".mp4") ) )
        isVideo = 0;   // 请求的不是视频内容
    return isVideo;
}


void read_requesthdrs(rio_t *rp, char* partialRange) 
{   // 阅读请求头部，并判断是否请求中包含range
    char buf[ONE_K_SIZE];

    rio_readlineb(rp, buf, ONE_K_SIZE);
    if ( strstr(buf, "Range"))
        strcpy(partialRange, buf);

    while(strcmp(buf, "\r\n")) {          // http请求以一行 \r\n结束
        rio_readlineb(rp, buf, ONE_K_SIZE);
        if ( strstr(buf, "Range"))
            strcpy(partialRange, buf);
    }
    return;
}

