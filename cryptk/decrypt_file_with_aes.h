#pragma once
#include "includes.h"
#include "load_aes_key.h"
#define AES_BLOCK_SIZE 16
#define _CRT_SECURE_NO_WARNINGS

using namespace std;


bool decrypt_file_with_aes(const string& input_file_path, const string& output_file_path, const string AES_KEY_FILE)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);
    /*const string AES_KEY_FILE = "C:\\ProgramData\\aes_key.bin";*/
    unsigned char aes[32];

    cout << "Input file path: " << input_file_path << endl;
    cout << "Output file path: " << output_file_path << endl;
   /* cout << "decrypt_file_with_aes.h AES_KEY_FILE path: " << AES_KEY_FILE << endl;*/

    if (!load_aes_key(AES_KEY_FILE.c_str(), aes, 32))
    {
        return 1;
    }

    ifstream input_file(input_file_path, ios::binary);
    ofstream output_file(output_file_path, ios::binary);

    if (!input_file || !output_file)
    {
        fprintf(stderr, "Error on opening files");
        return false;
    }

    unsigned char iv[AES_BLOCK_SIZE];

    input_file.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);


    if (input_file.gcount() != AES_BLOCK_SIZE)
    {
        fprintf(stderr, "error reading IV from file\n");
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "error creating context\n");
        return false;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes, iv))
    {
        fprintf(stderr, "error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char buffer[4096];
    unsigned char decrypted_buffer[4096 + AES_BLOCK_SIZE];
    int decrypted_bytes;

    while (input_file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || input_file.gcount() > 0)
    {
        int bytes_read = static_cast<int>(input_file.gcount());

        if (!EVP_DecryptUpdate(ctx, decrypted_buffer, &decrypted_bytes, buffer, bytes_read))
        {
            fprintf(stderr, "error decrypting block\n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        output_file.write(reinterpret_cast<char*>(decrypted_buffer), decrypted_bytes);
    }


    int final_bytes;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_buffer, &final_bytes))
    {

        /*for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            printf("IV[%d]: %02x\n", i, iv[i]);
        for (int i = 0; i < 32; ++i)
            printf("AES Key[%d]: %02x\n", i, aes[i]);*/
        fprintf(stderr, "årror finalizing decryption\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
            return false;

    }
    output_file.write(reinterpret_cast<char*>(decrypted_buffer), final_bytes);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
