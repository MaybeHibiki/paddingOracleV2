#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>
using namespace CryptoPP;



bool checkPadding(unsigned char* plaintext){
    unsigned char padLen = plaintext[96-1];
    int padLenNum = (int)padLen - '0';
    std::cout<<plaintext<<" in int: "<<padLenNum<<std::endl;

    std::cout<<padLen<<std::endl;

    for (size_t i = 0; i < padLenNum; ++i) {
        if (plaintext[96 - 1 - 2*i] -'0' != padLenNum)
            return 0;
    }
    return 1;
}

/*
General structure of encryption/decryption process in cryptopp (They called it a pipeline):
Reference: https://www.cryptopp.com/wiki/Advanced_Encryption_Standard 
Source -> Filter -> Sink
Source can be one of the three types: FileSource,StringSource, SocketSource
Sink can be one of the three types: FileSink,StringSink, SocketSink
Filter transfer data into different encoding (maybe it can do more)
*/

int main() {
    byte key[AES::DEFAULT_KEYLENGTH] = {
        0xc5, 0x29, 0xe8, 0x26, 0xe7, 0xd2, 0x25, 0x74,
        0x22, 0x65, 0xbd, 0x69, 0xc5, 0x8c, 0xa3, 0x5d
    };
    byte iv[AES::BLOCKSIZE] = {
        0xc9, 0xdd, 0x57, 0x5d, 0xa3, 0xdf, 0x32, 0x6b,
        0x19, 0xfc, 0x60, 0x04, 0xea, 0xaf, 0x8e, 0x9c
    };

    // Plaintext to encrypt
    std::string plaintext = "the padding oracle attack can be applied to";
    std::string ciphertext;
    std::string decrypted;

    //encryption:
    CBC_Mode< AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);
    //encrypt the plaintext and automatically handle padding
    StringSource(plaintext, true, 
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        ) // StreamTransformationFilter
    ); // StringSource

    //decryption:
    CBC_Mode< AES >::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv);
    //decrypt the ciphertext while preserve padding
    StringSource(ciphertext, true, 
        new StreamTransformationFilter(decryptor,
            new StringSink(decrypted),
            StreamTransformationFilter::NO_PADDING
        ) // StreamTransformationFilter
    ); // StringSource

    //print the results in hex and plain format
    std::string ciphertextHex;
    StringSource(ciphertext, true, 
        new HexEncoder(
            new StringSink(ciphertextHex)   
        ) // HexEncoder
    ); // StringSource

    std::string decryptedHex;
    StringSource(decrypted, true, 
        new HexEncoder(
            new StringSink(decryptedHex)   
        ) // HexEncoder
    ); // StringSource


    std::cout << "Ciphertext (hex): " << ciphertextHex << std::endl;
    std::cout << "Decrypted text: " << decrypted << std::endl;
    std::cout << "Decrypted (hex): " << decryptedHex << std::endl;


    std::cout<<"Padding check: "<< checkPadding( ((unsigned char*)decryptedHex.c_str() ))<<std::endl;
    return 0;
}
