#pragma once
#include "includes.h"
using namespace std;

bool decrypt_aes_key_with_private_key(const string& encrypted_key, const string& private_key_path, string& decrypted_key)
{
    FILE* private_key_file = fopen(private_key_path.c_str(), "r");
    if (!private_key_file)
    {
        fprintf(stderr, "failed to open private key file.\n");
        return false;
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(private_key_file, nullptr, nullptr, nullptr);
    fclose(private_key_file);

    if (!private_key)
    {
        fprintf(stderr, "error reading private key: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx)
    {
        fprintf(stderr, "failed to create EVP_PKEY_CTX.\n");
        EVP_PKEY_free(private_key);
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        fprintf(stderr, "failed to initialize decryption.\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return false;
    }

    size_t decrypted_len = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &decrypted_len,
        reinterpret_cast<const unsigned char*>(encrypted_key.data()), encrypted_key.size()) <= 0)
    {
        fprintf(stderr, "failed to determine decrypted length.\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return false;
    }

    decrypted_key.resize(decrypted_len);
    if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(&decrypted_key[0]), &decrypted_len,
        reinterpret_cast<const unsigned char*>(encrypted_key.data()), encrypted_key.size()) <= 0)
    {
        fprintf(stderr, "decryption failed.\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return false;
    }

    decrypted_key.resize(decrypted_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    return true;
}

