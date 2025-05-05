#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cstring>


static const size_t CIPHER_LEN = 48;


//function for debug purpose:
void print_hex(const char* buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02X", buf[i]);
    printf("\n");
}



struct thread_args {
	int index; 
	int confd;
};

 

//Define the number of clients/threads that can be served
#define N 100
#define SERVERPORT 12001
int threadCount = 0;
pthread_t clients[N]; //thread pool for clients 
int availableSlots[N];

//Declare socket file descriptor.
int sockfd;

//Declare server address to which to bind for receiving messages and client address to fill in sending address
struct sockaddr_in clienAddr;



//function that do the padding check from a ciphertext
//return 1 if the padding is valid and 0 otherwise
int paddingCheck(char* ciphertext){
    using namespace CryptoPP;
    std::cout<<std::endl;
    print_hex(ciphertext,CIPHER_LEN);
    std::string decrypted;

    byte key[AES::DEFAULT_KEYLENGTH] = {
        0xc5, 0x29, 0xe8, 0x26, 0xe7, 0xd2, 0x25, 0x74,
        0x22, 0x65, 0xbd, 0x69, 0xc5, 0x8c, 0xa3, 0x5d
    };
    byte iv[AES::BLOCKSIZE] = {
        0xc9, 0xdd, 0x57, 0x5d, 0xa3, 0xdf, 0x32, 0x6b,
        0x19, 0xfc, 0x60, 0x04, 0xea, 0xaf, 0x8e, 0x9c
    };


    CBC_Mode< AES >::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv);
    // Decrypt the ciphertext (padding is removed by the filter)
    StringSource(ciphertext, true, 
        new StreamTransformationFilter(decryptor,
            new StringSink(decrypted),
            StreamTransformationFilter::NO_PADDING
        ) 
    ); 

    std::cout<< "Expected plaintext here:" <<std::endl;
    std::cout<< '\n' <<decrypted <<'\n';
    std::cout<< "End of plaintext:" <<std::endl;

    std::string decryptedHex;
    StringSource(decrypted, true, 
        new HexEncoder(
            new StringSink(decryptedHex)   
        ) // HexEncoder
    ); // StringSource

    //pkcs7 padding check:
    //extract padding len from last block

    unsigned char* plaintext = ((unsigned char*)decryptedHex.c_str() );
    
    unsigned char padLen = plaintext[96-1];
    int padLenNum = (int)padLen - '0';
    std::cout<<"pad len in int: "<<padLenNum<<std::endl;

    for (size_t i = 0; i < padLenNum; ++i) {
        if (plaintext[96 - 1 - 2*i] -'0' != padLenNum)
            return 0;
    }
    return 1;
    
}

//Connection handler (thread function) for servicing client requests for padding check
void* connectionHandler(void* args){
    struct thread_args* sock = (thread_args*)args;
    //buffer for modified ciphertext 
    char ciphertext[CIPHER_LEN];
    
   //get the connection descriptor
   int sockAdd = sock->confd;
   
   //Connection established
   printf("Connection Established with client IP: %s and Port: %d\n", inet_ntoa(clienAddr.sin_addr), ntohs(clienAddr.sin_port));
    int check = 0;


   while (check != 1){
        //read the modified ciphertext into the buffer
        int k = read(sockAdd,ciphertext,CIPHER_LEN);
        if(k<0){
            printf("Error reading from client\n");
            break;  // exit the loop and close the connectio
        }else if (k == 0) {
            // Client has disconnected
            printf("Client at thread %d disconnected.\n", sock->index);
            break;  // exit the loop and close the connection
        }

        std::cout<<"Ciphertext from client:";
        print_hex (ciphertext, CIPHER_LEN);
        std::cout<<'\n';
        
        //perform padding check.
        
        check = paddingCheck(ciphertext);

        if(check == 1)
        {
            write(sockAdd,"1\n",2);
        }else{
            write(sockAdd,"0\n",2);
        }
    }
   
   //Close connection descriptor and decrement the threadCount.
    close(sockAdd);
    //mark slot as available  
    availableSlots[sock->index] = 1;
    free(sock);
    pthread_exit(NULL);
}




int main(int argc, char *argv[]){
    // initialize the availableSlots array
    for(int i = 0; i<N; i++){
        availableSlots[i] = 1;
    }

 //Open a TCP socket, if successful, returns a descriptor
   sockfd = socket(AF_INET,SOCK_STREAM,0);
   if(sockfd<0){
      printf("Failed to create sockfd");
      return 1;
   }
  //Setup the server address to bind using socket addressing structure
   struct sockaddr_in sckaddr;
   sckaddr.sin_family = AF_INET;
   sckaddr.sin_port = htons(SERVERPORT);
   // INADDR_ANY accepts connections from all ip addresses of the current machine
   sckaddr.sin_addr.s_addr =  htonl (INADDR_ANY);

 //bind IP address and port for server endpoint socket 
   int binded = bind(sockfd,(const struct sockaddr*) &sckaddr, sizeof(sckaddr));
   if(binded<0){
      return 1;
   }
  // Server listening to the socket endpoint, and can queue N client requests
 printf("Server listening/waiting for client at port %d\n", SERVERPORT );
   int listened = listen(sockfd,N);
   if(listened<0){
      return 1;
   }
   socklen_t len = sizeof(clienAddr);


    //Main loop:
    while (1){
    int connfd;
    //Server accepts the connection and allocate a thread for it to call the connection handler
    if((connfd = accept(sockfd,(struct sockaddr*) &clienAddr,(socklen_t*)& len))<0){
        printf("Failed to accept\n");
        continue;
    }
        
    printf("CONNFD IS %d\n", connfd);

    //find out the next available slot in the thread pool
    int availableIndex = -1;
    for(int i = 0; i<N;i++){
        if(availableSlots[i]==1){
        availableIndex=i;
        availableSlots[availableIndex] = 0;
        break;
        }
    }

    if(availableIndex == -1){
        //if no more available thread to hanlde the connection.
        //(which is very unlikely to happen)
        printf("No available slots for new client connection\n");
        close(connfd);    
    }else{
        //allocate a thread for the connection
        struct thread_args *threadI = (struct thread_args*) malloc(sizeof(struct thread_args));
        threadI->confd = connfd;
        threadI->index = availableIndex;

        if(pthread_create(&clients[availableIndex], NULL, connectionHandler, (void*) threadI) < 0){
            //if unexpected error happen -> mark the slot available again
            perror("Unable to create a thread");
            availableSlots[availableIndex] = 1;
            close(connfd);
        }
        else {
            //else we let the thread run and clean up after its done 
            pthread_detach(clients[availableIndex]);
            printf("Thread %d has been created to service client request\n",availableIndex);
            
        }
    }
 }



 return 0;
}