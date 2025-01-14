#pragma once
#include "includes.h"
using namespace std;




bool generate_and_save_rsa_keys(const string& private_key_path, const string& public_key_path)
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey)
    {
        fprintf(stderr, "error allocating EVP_PKEY\n");
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    {
        fprintf(stderr, "error initializing keygen context\n");
        EVP_PKEY_free(pkey);
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        fprintf(stderr, "error generating RSA key\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    FILE* private_key_file = fopen(private_key_path.c_str(), "wb");
    if (!private_key_file || PEM_write_PrivateKey(private_key_file, pkey, NULL, NULL, 0, NULL, NULL) <= 0)
    {
        fprintf(stderr, "error writing private key\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        if (private_key_file) fclose(private_key_file);
        return false;
    }
    fclose(private_key_file);

    FILE* public_key_file = fopen(public_key_path.c_str(), "wb");
    if (!public_key_file || PEM_write_PUBKEY(public_key_file, pkey) <= 0)
    {
        fprintf(stderr, "error writing public key\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        if (public_key_file) fclose(public_key_file);
        return false;
    }
    fclose(public_key_file);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return true;
}



