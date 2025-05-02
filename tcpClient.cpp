#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string>




//this can be set to a fix size later representing the size of the ciphertext 
#define BUFSIZE 60

//Server info
#define SERVERPORT 12001
char* IP = "127.0.0.1";

int main(int argc, char *argv[]){

    //Declare socket file descriptor
    int sockfd;

    //Declare server address to accept
    //Declare host
    //get hostname
    //Set the server address to send using socket addressing structure
    struct sockaddr_in sockAddr;
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(SERVERPORT);
    sockAddr.sin_addr.s_addr = inet_addr(IP);

    //Open a socket, if successful, returns a fd
    sockfd = socket(AF_INET,SOCK_STREAM,0);
   if(sockfd<0){
      printf("Failed to create sockfd");
      return 1;
   }

    //Connect to the server
    connect(sockfd,(const struct sockaddr*)&sockAddr, sizeof(sockAddr));

    unsigned char ciphertext[] = {
        0x08,0x7A,0xB1,0x56,0x93,0x09,0xD1,0x2D,
        0xE8,0x56,0x04,0xDC,0xD9,0x8E,0xF3,0x82,
        0x97,0x8D,0xFA,0x06,0xDC,0x0A,0x6B,0x8A,
        0x5A,0xA6,0x8A,0x09,0xEE,0x52,0x92,0x16,
        0xF1,0x7A,0x3E,0x14,0x16,0x88,0x52,0xE8,
        0xCB,0x08,0x7A,0xC2,0xD6,0x59,0x3B,0x18
    };
    size_t len = sizeof(ciphertext);

    //sample code of sending stuff in a loop
    /*char buf[2];
    for(int i = 0; i<10;i++){
        //the only line of code that we need the c++ for
        //or actually it would be beneficial that client code are in c++ since this will be offered to students later.
        //and having access to c++ library would be a lot convenient
        std::string str = std::__cxx11::to_string(i) + '\n';
        write(sockfd,(void*)str.c_str(),2);
        int k;
        k = read(sockfd,buf,2);
        if(k<0){
            printf("Error reading from server\n");
            break;  
        }else if (k == 0) {
            printf("Server disconnected.\n");
            break;  
        }

        printf("From server: %s\n",buf);
        
    }*/

    // send ciphertext to server
    if (write(sockfd, ciphertext, len) != (ssize_t)len) {
        perror("write");
        close(sockfd);
        return 1;
    }

    //read padding oracle response ("1\n" or "0\n")
    char buf[3] = {0};
    ssize_t n = read(sockfd, buf, 2);
    if (n < 0) {
        perror("read");
    } else if (n == 0) {
        printf("Server closed connection\n");
    } else {
        buf[n] = '\0';
        // Print result: should be "1\n" (valid padding) or "0\n" (invalid)
        printf("Oracle response: %s", buf);
    }

    //Close connection

    while(1);
    close(sockfd);
    return 0;
}