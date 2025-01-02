#pragma once
#include "includes.h"
#define AES_BLOCK_SIZE 16
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

// generating AES key
unsigned char* generate_aes_key(const int key_length = 32) {
    unsigned char* key = new unsigned char[key_length];

    if (!RAND_bytes(key, key_length))
    {
        fprintf(stderr, "error generating aes key\n");
        delete[] key;
        return nullptr;
    }

    printf("aes key generated successfully\n");
    for (int i = 0; i < key_length; i++) {
        printf("%02x", key[i]);
    }

    //// saving key to file w constant path
    //ofstream keyFile("C:\\ProgramData\\aes_key.bin", ios::binary);
    //keyFile.write(reinterpret_cast<const char*>(key), key_length);
    //keyFile.close();

    printf("\n");
    return key;
}

// genereating IV
unsigned char* generate_iv(const int iv_length = AES_BLOCK_SIZE)
{
    unique_ptr<unsigned char[]> iv(new unsigned char[iv_length]);

    if (!RAND_bytes(iv.get(), iv_length)) {
        fprintf(stderr, "Error generating IV\n");
        return nullptr;
    }

    printf("IV generated successfully.\n");
    return iv.release();
}