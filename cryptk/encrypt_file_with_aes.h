#pragma once
#pragma once
#include "includes.h"
#define AES_BLOCK_SIZE 16
#define _CRTDBG_MAP_ALLOC
#define _CRT_SECURE_NO_WARNINGS
using namespace std;




bool encrypt_file_with_aes(const string& input_file, const string& output_file, unsigned char* iv, unsigned char* aes)
{
    ifstream temp_input_file(input_file, ios::binary);
    ofstream temp_output_file(output_file, ios::binary);

    if (!temp_input_file.is_open() || !temp_output_file.is_open())
    {
        fprintf(stderr, "error on opening your file\n");
        return false;
    }


    temp_output_file.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
        printf("%02x ", iv[i]);
    printf("\n");


    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "cant create context");
        return false;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes, iv))
    {
        fprintf(stderr, "cant initialize aes enc\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char buffer[4096];
    unsigned char encrypted_buffer[4096 + AES_BLOCK_SIZE];
    streamsize bytes;
    int encrypted_bytes;

    while ((bytes = temp_input_file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)).gcount()) > 0)
    {
        if (!EVP_EncryptUpdate(ctx, encrypted_buffer, &encrypted_bytes, buffer, bytes))
        {
            fprintf(stderr, "encrypting block error");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        temp_output_file.write(reinterpret_cast<char*>(encrypted_buffer), encrypted_bytes);
    }

    int final_bytes;
    if (!EVP_EncryptFinal_ex(ctx, encrypted_buffer, &final_bytes))
    {
        fprintf(stderr, "final encrypting block error\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    temp_output_file.write(reinterpret_cast<char*>(encrypted_buffer), final_bytes);

    //for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    //    printf("IV[%d]: %02x\n", i, iv[i]);
    //for (int i = 0; i < 32; ++i)
    //    printf("AES Key[%d]: %02x\n", i, aes[i]);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}