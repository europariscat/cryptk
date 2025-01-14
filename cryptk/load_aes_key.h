#pragma once
#include "includes.h"
#define _CRT_SECURE_NO_WARNINGS
using namespace std;


bool load_aes_key(const char* file_path, unsigned char* key, size_t key_size)
{
    ifstream file(file_path, ios::binary);
    if (!file.is_open())
    {
        cout << "error opening file for reading\n";
        return false;
    }

    file.read(reinterpret_cast<char*>(key), key_size);
    if (!file)
    {
        cout << "error reading key from file\n";
        file.close();
        return false;
    }
    cout << "AES key loaded successfully\n";
    file.close();
    return true;
}

