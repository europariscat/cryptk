#pragma once
#include "includes.h"
using namespace std;

bool encrypt_aes_key_with_public_key(const string& aes_key, const string& public_key_path, string& encrypted_key)
{
    FILE* public_key_file = fopen(public_key_path.c_str(), "r");
    if (!public_key_file)
    {
        fprintf(stderr, "failed to open public key file.\n");
        return false;
    }

    EVP_PKEY* public_key = PEM_read_PUBKEY(public_key_file, nullptr, nullptr, nullptr);
    fclose(public_key_file);

    if (!public_key)
    {
        fprintf(stderr, "error reading public key: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    if (!ctx)
    {
        fprintf(stderr, "failed to create EVP_PKEY_CTX.\n");
        EVP_PKEY_free(public_key);
        return false;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {

        fprintf(stderr, "Failed to initialize encryption.\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    size_t encrypted_len = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encrypted_len, reinterpret_cast<const unsigned char*>(aes_key.data()), aes_key.size()) <= 0)
    {
        fprintf(stderr, "failed to determine encrypted length.\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    encrypted_key.resize(encrypted_len);
    if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char*>(&encrypted_key[0]), &encrypted_len,
        reinterpret_cast<const unsigned char*>(aes_key.data()), aes_key.size()) <= 0)
    {
        fprintf(stderr, "encryption failed.\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    encrypted_key.resize(encrypted_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    return true;
}