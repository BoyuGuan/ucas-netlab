#include "utils.h"





int main(int argc, char** argv){
    int listen_80_fd, conn_80_fd, listen_443_fd, conn_443_fd;
    char clinetHostName[STRINGSIZE_MAX], clientPort[8];
    __socklen_t clinetLen;
    struct sockaddr_storage clientAddr;
    listen_80_fd = Open_listenfd("80");
    listen_443_fd = Open_listenfd("443");
    

    



}