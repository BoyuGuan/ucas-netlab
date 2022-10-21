#include "utils.h"

void read_request_headers(rio_ssl_t *rp, char* partialRange);
void *handle_80_thread(void* vargp);
void *handle_443_thread(void* vargp);
void redirectTo443Use301(int fd, char* newRequestTarget);
void parseURL(char* url, char* fileName);
void server_response(SSL* ssl , char *fileName, int serviceCode, char* shortMessage, char* range);
void serve_no_range(SSL* ssl, char *fileName, int serviceCode, char* shortErrorMessage);
void serve_range(SSL* ssl, char*fileName,  char* range);
void serve_video(int fd, char *fileName, int serviceCode, char *serviceShortMesssage, char* range);
void get_filetype(char *filename, char *filetype);


int main(int argc, char** argv)
{
    signal(SIGPIPE, sigpipe_handler); // 忽略pipe错误，此错误会在对方关闭了TCP连接后己方仍要写时处罚
    char clientHostName[HOSTNAME_LEN], clientPort[PORT_LEN];
    pid_t process443Pid, process80Pid;

    // 创建两个子进程，一个是进程处理443的https，一个进程处理80的http
    if ( (process443Pid = fork()) == 0  )   
    {   // 443端口的子进程

        // 初始化SSL环境
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        const SSL_METHOD *method = TLS_server_method();  // 支持TLS server版方法，包含TLSV1.2和TLSV1.3等
        SSL_CTX *ctx = SSL_CTX_new(method);
        if( !ctx )
            server_error( "Init ssl ctx error" );
        if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0)   // 加载数字证书
            server_error("Load cert file error");
        if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0)     // 加载私钥
            server_error( "Load prikey file error");
        if( !SSL_CTX_check_private_key( ctx ) )             // 查看私钥和证书是否匹配
            server_error( "Private key does not match the certificate public key\n" );
        
        int listen443FD = open_listen_fd("443");
        // printf("443 port listen fd is %d \n", listen443FD);
        struct sockaddr_storage clientAddress;
        __socklen_t clientLen = sizeof(clientAddress);
        pthread_t newThreadID;
        while (1)
        {
            // 注意此处一定要用指针指向一个malloc出来的值，否则用实例传地址的话会导致主线程下一步for循环覆盖掉这个实例产生race
            struct thread_443_request* request443P = malloc(sizeof(struct thread_443_request)) ;
            request443P->ctx = ctx;
            if((request443P->connectFD = accept(listen443FD, &clientAddress, &clientLen ) ) < 0 ) // 新请求的fd
                server_error("443 port accept error!");
            if( getnameinfo(&clientAddress, clientLen, clientHostName, HOSTNAME_LEN, clientPort, PORT_LEN, 0) != 0 )   // 得到对方的主机名（ip）与对方的端口
                server_error("443 port getnameinfo error");
            printf("**NEW REQUEST**: 443 Accept connection from (%s,%s)\n", clientHostName, clientPort);
            if (pthread_create(&newThreadID, NULL, handle_443_thread, (void*)request443P) != 0)     // 创建新线程来处理该请求，这样就可以实现并发服务器
                server_error("Thread create error!");
        }
        
    }
    else{
        if ( (process80Pid = fork()) == 0 )
        {   // 80端口的子进程
            int listen80FD = open_listen_fd("80");
            // printf("80 port listen fd is %d \n", listen80FD);
            prctl(PR_SET_PDEATHSIG, SIGTERM);  // 父进程死后杀死自己
            struct sockaddr_storage clientAddress;
            __socklen_t clientLen = sizeof(clientAddress);
            pthread_t newThreadID;
            while (1){
                // 注意此处一定要用指针指向一个malloc出来的值，否则用实例传地址的话会导致主线程下一步for循环覆盖掉这个实例产生race
                struct thread_80_request * request80P = malloc(sizeof(struct thread_80_request));
                if((request80P->connectFD = accept(listen80FD,  &clientAddress, &clientLen ) ) < 0 )    // 同80
                    server_error("80 port accept error!");
                if( getnameinfo(&clientAddress, clientLen, clientHostName, HOSTNAME_LEN, clientPort, PORT_LEN, 0) != 0 )    // 同80
                    server_error("80 port getnameinfo error");
                printf("**NEW REQUEST**: 80 Accept connection from (%s,%s)\n", clientHostName, clientPort); // 同80
                strcpy(request80P->clientHostName, clientHostName);
                if (pthread_create(&newThreadID, NULL, handle_80_thread, (void *)request80P) != 0)  // 同80
                    server_error("Thread create error!");
                // printf("\ntest2\n");
            }
        }
        else{
            while (1)
            {
                // 服务器主进程，等俩子进程跑
                ;
            }
            
        }
    }
    return 0;
}

// 80 端口的线程处理函数，在支持https的服务器上唯一的作用就是用301把请求转发到443端口
void *handle_80_thread(void* vargp){    
    pthread_detach(pthread_self());     //  分离线程，方便其自动回收
    
    struct thread_80_request* request80P = (struct thread_80_request* ) vargp ;
    int connectFD = request80P->connectFD;
    char clientHostName[HOSTNAME_LEN];
    strcpy(clientHostName, request80P->clientHostName);
    free(vargp);
    char buf[BUFFER_SIZE], method[SHORT_STRING_BUF], httpVersion[SHORT_STRING_BUF], \
        url[ONE_K_SIZE], newRequestTarget[ONE_K_SIZE]="https://" ; 
    
    // 因为我们没有备案，所以走不了公网的80端口，只能通过zerotier或者wireguard组内网
    // zerotier我用的是 192.168.196.0/24子网，wireguard我用的是10.0.0.0/24子网
    // 两者通过ip第二位可以区分开，zerotier内网过来的包，走服务器在zerotier上的ip 192.168.196.7，
    // 否则就是wireguard内网过来的包，走服务器在wireguard上的ip 10.0.0.7，

    // 读取请求
    rio_t clientRio;
    rio_readinitb(&clientRio, connectFD);
    if (!rio_readlineb(&clientRio, buf, BUFFER_SIZE))          // 空请求
        return;
    // 做新请求链接
    sscanf(buf, "%s %s %s", method, url, httpVersion );
    if(clientHostName[1] == '0')
        strcat(newRequestTarget, "10.0.0.7");
    else
        strcat(newRequestTarget, "192.168.196.7");
    strcat( newRequestTarget, url);
    redirectTo443Use301(connectFD, newRequestTarget);

    if(close(connectFD) < 0)
        server_error("close conncet fd error!");
}

// 443 端口的线程处理函数
void *handle_443_thread(void* vargp){
    pthread_detach(pthread_self());    //  分离线程，方便其自动回收

    struct thread_443_request *request443P = (struct thread_443_request*)vargp;
	int connectFD = request443P -> connectFD;
	SSL_CTX *ctx = request443P -> ctx;
    free(request443P);

    SSL	*ssl = SSL_new(ctx);    // 根据之前设定的ctx来创建新的ssl会话
    if( !ssl )
        server_error("Create ssl error!");
    if( !SSL_set_fd(ssl, connectFD))    // ssl会话绑定文件描述符
        server_error("ssl set fd error!");
    int SSLAcceptCode = SSL_accept(ssl) ;   // ssl会话accept进行TLS握手连接
    if( SSLAcceptCode <= 0 ){
        // printf("The TLS/SSL handshake was not successful, but not a .\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(connectFD);
        // server_error("ssl accept error!");
        return;
    }

    char requestRange[ONE_K_SIZE] = "No Range";
    char buf[BUFFER_SIZE], method[SHORT_STRING_BUF], url[ONE_K_SIZE], \
        httpVersion[SHORT_STRING_BUF], fileName[ONE_K_SIZE]=""; 

    rio_ssl_t clientRio;

    // 读取请求
    rio_ssl_readinitb(&clientRio, ssl);
    if( !rio_ssl_readlineb(&clientRio, buf, BUFFER_SIZE)){   // 空请求
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(connectFD);
    }

    printf("request content is \n%s", buf);
    sscanf(buf, "%s %s %s", method, url, httpVersion );
    if (strcasecmp(method, "GET")) {    // 只支持GET 方法
        server_response(ssl, "./dir/501.html", 501, "Not Implemented", NULL);
        return;
    }
    read_request_headers(&clientRio, requestRange);  //读取所有请求内容，并查看是否有Range段，有的话为分段请求
    parseURL(url, fileName) ; //  解析出文件地址

    struct stat sbuf;   // 该文件状态
    if(stat(fileName, &sbuf) < 0){  // 没这文件
        server_response(ssl, "./dir/404.html",  404, "Not Found", NULL);
        return;
    }
    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) { // 没有权限读的文件
        stat("./dir/403.html", &sbuf);
        server_response(ssl, "./dir/403.html",  403, "Forbidden", NULL);
        return;
    }

    int successServerCode = 200; // 请求成功的类型种类（是普通请求的话是200，分段的话是206）
    char successServerShortMessage[SHORT_STRING_BUF] = "OK";

    if(strcmp(requestRange, "No Range")) { // 请求是range分段请求
        successServerCode = 206;
        strcpy(successServerShortMessage, "Partial Content");
    }
    server_response(ssl, fileName,  successServerCode, successServerShortMessage, requestRange);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if(close(connectFD) < 0)
        server_error("close conncet fd error!");  
}

void server_response(SSL* ssl , char *fileName, int serviceCode, char* shortMessage, char* range){
    if(serviceCode != 206)
        serve_no_range(ssl, fileName, serviceCode, shortMessage);
    else
        serve_range(ssl, fileName, range);
}

void serve_no_range(SSL* ssl,  char *fileName, int serviceCode, char* shortMessage){

    struct stat sbuf;
    stat(fileName, &sbuf);
    int srcfd, fileSize = sbuf.st_size;
    char *srcp, fileType[MIDDLE_STRING_BUF], buf[FOUR_K_SIZE];
    // printf("serverCode: %d   shortMessage: %s  file name: %s  file size : %d \n", serviceCode, shortMessage, fileName ,fileSize);
    // 发headers给client
    get_filetype(fileName, fileType); 
    
    sprintf(buf, "HTTP/1.1 %d %s\r\n", serviceCode, shortMessage);    
    sprintf(buf, "%sServer: Guan&Wu Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);   // 注意，如果不是close而是keep-alive，在请求后会一直转圈
    sprintf(buf, "%sAccept-Ranges: bytes\r\n", buf);  // 支持分段请求
    sprintf(buf, "%sContent-length: %d\r\n", buf, fileSize);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, fileType);
    printf("response header is:\n%s", buf);

    if( rio_ssl_writen(ssl, buf, strlen(buf)) != 1 )
        return ;

    //  发所请求的文件内容给client
    if ((srcfd = open(fileName, O_RDONLY, 0)) < 0 )
        server_error("open object file error!");

    if ( (srcp = mmap(0, fileSize, PROT_READ, MAP_PRIVATE, srcfd, 0)) == ((void *) -1) ) // 内存映射，加快速度
        server_error("mmap object file function error!");
    if(close(srcfd) < 0 )
        server_error("close object file error!");
    rio_ssl_writen(ssl, srcp, fileSize);
    if( munmap(srcp, fileSize) < 0 )
        server_error("unmmap object file error!");
}


void serve_range(SSL* ssl, char*fileName,  char* range){
    // printf("\n\n%  %s  %s \n" , fileName, range);
    struct stat sbuf;
    stat(fileName, &sbuf);
    int srcfd;
    size_t contentLength, fileSize = sbuf.st_size;
    char *srcp, fileType[MIDDLE_STRING_BUF], buf[FOUR_K_SIZE];

    size_t begin = SIZE_T_MAX, end = SIZE_T_MAX;
    sscanf(range, "Range: bytes=%lu-%lu", &begin, &end);

    if (begin == SIZE_T_MAX)  // 没给begin，默认是0
        begin = 0;
    if (begin >= fileSize)// 给大了，超过视频大小了
        return; // 啥也不干
    
    if(end == SIZE_T_MAX)  // 没给end，也就是读到头
        end = fileSize-1;

    contentLength = end - begin + 1;
    
    get_filetype(fileName, fileType);       
    sprintf(buf, "HTTP/1.1 206 Partial Content\r\n");    
    sprintf(buf, "%sServer: Guan&Wu Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);
    // sprintf(buf, "%sKeep-Alive: timeout=5, max=100\r\n", buf);
    sprintf(buf, "%sContent-type: %s\r\n", buf, fileType);
    sprintf(buf, "%sContent-Range: bytes %lu-%lu/%lu\r\n", buf, begin, end, fileSize); // 注意是lu！！！
    sprintf(buf, "%sContent-length: %d\r\n\r\n", buf, contentLength);
    printf("%s", buf);
    
    if( rio_ssl_writen(ssl, buf, strlen(buf)) != 1 )
        return;
    // 发headers
    if ((srcfd = open(fileName, O_RDONLY, 0)) < 0 )
        server_error("open object file error!");
    if ( (srcp = mmap(0, fileSize, PROT_READ, MAP_PRIVATE, srcfd, 0)) == ((void *) -1) )
        server_error("mmap object file function error!");
    if(close(srcfd) < 0 )
        server_error("close object file error!");
    size_t loops =  contentLength / MINI_CHUNK_SIZE;
    size_t remain  = contentLength % MINI_CHUNK_SIZE;
    short dataStatusCode = 0;
    // printf("loops is:%lu   remain:%d\n", loops, remain);

    for (size_t i = 0; i < loops ; i++){
        if( rio_ssl_writen(ssl, srcp + i * MINI_CHUNK_SIZE + begin, MINI_CHUNK_SIZE) !=  1 ){
            dataStatusCode = 1;
            break;
        }
    }
    if(dataStatusCode == 0)
        rio_ssl_writen(ssl, srcp + MINI_CHUNK_SIZE * loops + begin, remain);
    if( munmap(srcp, fileSize) < 0 )
        server_error("unmmap object file error!");
}


// 解析请求的文件类型
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

// 解析URL，搞出文件的相对路径
void parseURL(char* url, char* fileName){
    strcpy(fileName, "./dir");
    strcat(fileName, url);
    if (url[strlen(url)-1] == '/')     
        strcat(fileName, "index.html");

}

 // 阅读请求头部，并判断是否请求中包含range
void read_request_headers(rio_ssl_t *rp, char* partialRange) 
{ 
    char buf[ONE_K_SIZE];

    rio_ssl_readlineb(rp, buf, ONE_K_SIZE);
    printf("%s", buf);
    if ( strstr(buf, "Range"))
        strcpy(partialRange, buf);

    while(strcmp(buf, "\r\n")) {          // http请求以一行 \r\n结束
        // rio_readlineb(rp, buf, ONE_K_SIZE);
        rio_ssl_readlineb(rp, buf, ONE_K_SIZE);
        printf("%s", buf);
        if ( strstr(buf, "Range"))
            strcpy(partialRange, buf);        
    }
    return;
}

 // 301重定向到443
void redirectTo443Use301(int fd, char* newRequestTarget){
    char buf[FOUR_K_SIZE]; 
    sprintf(buf, "HTTP/1.1 301 Moved Permanently\r\n");    
    sprintf(buf, "%sLocation: %s\r\n\r\n", buf, newRequestTarget);
    printf("rediect header is:\n%s", buf);
    rio_writen(fd, buf, strlen(buf));
}
