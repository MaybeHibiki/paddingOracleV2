#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>
using namespace CryptoPP;

/*
General structure of encryption/decryption process in cryptopp (They called it a pipeline):
Reference: https://www.cryptopp.com/wiki/Advanced_Encryption_Standard 
Source -> Filter -> Sink
Source can be one of the three types: FileSource,StringSource, SocketSource
Sink can be one of the three types: FileSink,StringSink, SocketSink
Filter transfer data into different encoding (maybe it can do more)
*/

int main() {
    // 128-bit AES key (16 bytes) and 128-bit IV for CBC mode (16 bytes)
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

    // **Encryption**: AES-128 in CBC mode with PKCS#7 padding (handled by Crypto++ filter)
    CBC_Mode< AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);
    // Encrypt the plaintext and automatically handle padding
    StringSource(plaintext, true, 
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        ) // StreamTransformationFilter
    ); // StringSource

    // **Decryption**: AES-128 in CBC mode
    CBC_Mode< AES >::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv);
    // Decrypt the ciphertext (padding is removed by the filter)
    StringSource(ciphertext, true, 
        new StreamTransformationFilter(decryptor,
            new StringSink(decrypted)
        ) // StreamTransformationFilter
    ); // StringSource

    // Print the results in hex and plain format for verification
    std::string ciphertextHex;
    StringSource(ciphertext, true, 
        new HexEncoder(
            new StringSink(ciphertextHex)
        ) // HexEncoder
    ); // StringSource
    std::cout << "Ciphertext (hex): " << ciphertextHex << std::endl;
    std::cout << "Decrypted text: " << decrypted << std::endl;

    return 0;
}
