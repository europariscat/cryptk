#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <dbt.h>
#include <setupapi.h> 
#include <winioctl.h> 
#include <comdef.h>
#include <WbemIdl.h>

#include "includes.h"
#include "flash_utils.h"
#include "load_aes_key.h"
#include "generate_aes_key_and_iv.h"
#include "encrypt_file_with_aes.h"
#include "decrypt_file_with_aes.h"
#include "rsa_keys_generation.h"
#include "encrypt_aes_key_with_public_rsa_key.h"
#include "decrypt_aes_key_with_private_rsa_key.h"
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "setupapi.lib")

using namespace std;




// root path folder

const string root_path = "C:\\ProgramData\\cryptk\\";

// path to AES key if alr generated
static string AES_KEY_FILE = "C:\\ProgramData\\cryptk\\";


// path to cfg file
const string CFG_FILE = "C:\\ProgramData\\quanticrypt_cfg.txt";

// path to public RSA key

static string RSA_PUBLIC_KEY_PATH = "C:\\ProgramData\\cryptk\\";

// func that allows us to check if aes key is encrypted

bool is_file_encrypted(const string& aes_key_file)
{
    ifstream file(aes_key_file, ios::binary | ios::ate);
    if (!file.is_open())
    {
        cerr << "unable to open AES key file.\n";
        return false;
    }


    streamsize file_size = file.tellg();
    file.close();


    return file_size > 32;
}


// function to check if file exists already
bool is_file_exists(const char* file_path)
{
    FILE* file = fopen(file_path, "rb");

    if (file)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

// function that allows to check cfg file

// creating root folder

void create_root_folder()
{
    filesystem::path root_path = "C:\\ProgramData\\cryptk";
    if (!filesystem::exists(root_path))
    {
        try
        {
            filesystem::create_directory(root_path);
        }
        catch(const filesystem::filesystem_error& e)
        {
            cerr << e.what(); // ??? :D
        }
    }
}

// creating folder for flash


// =============================
// functions for working with usb devices
// =============================

// structure to store device information

struct usb_device_info
{
    string drive_letter;
    string serial_number;
    string pnp_device_id;
};

// get device serial number

//string get_serial_number(const string& drive_letter)
//{
//    HRESULT hres;
//    string serial_number = "unknown";
//
//    // Initialize COM library
//    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
//    if (FAILED(hres))
//    {
//        return serial_number;
//    }
//
//    // Initialize security
//    hres = CoInitializeSecurity(
//        NULL,
//        -1,
//        NULL,
//        NULL,
//        RPC_C_AUTHN_LEVEL_DEFAULT,
//        RPC_C_IMP_LEVEL_IMPERSONATE,
//        NULL,
//        EOAC_NONE,
//        NULL);
//
//    if (FAILED(hres))
//    {
//        CoUninitialize();
//        return serial_number;
//    }
//
//    // Obtain the initial locator to WMI
//    IWbemLocator* pLoc = NULL;
//    hres = CoCreateInstance(
//        CLSID_WbemLocator,
//        0,
//        CLSCTX_INPROC_SERVER,
//        IID_IWbemLocator,
//        (LPVOID*)&pLoc);
//
//    if (FAILED(hres))
//    {
//        CoUninitialize();
//        return serial_number;
//    }
//
//    IWbemServices* pSvc = NULL;
//    hres = pLoc->ConnectServer(
//        _bstr_t(L"ROOT\\CIMV2"),
//        NULL,
//        NULL,
//        0,
//        NULL,
//        0,
//        0,
//        &pSvc);
//
//    if (FAILED(hres))
//    {
//        pLoc->Release();
//        CoUninitialize();
//        return serial_number;
//    }
//
//    // Set the proxy for impersonation
//    hres = CoSetProxyBlanket(
//        pSvc,
//        RPC_C_AUTHN_WINNT,
//        RPC_C_AUTHZ_NONE,
//        NULL,
//        RPC_C_AUTHN_LEVEL_CALL,
//        RPC_C_IMP_LEVEL_IMPERSONATE,
//        NULL,
//        EOAC_NONE);
//
//    if (FAILED(hres))
//    {
//        pSvc->Release();
//        pLoc->Release();
//        CoUninitialize();
//        return serial_number;
//    }
//
//    // Query for the disk drive associated with the logical disk
//    wstring logical_disk_query = L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='";
//    logical_disk_query += wstring(drive_letter.begin(), drive_letter.end());
//    logical_disk_query.pop_back(); // Remove trailing backslash
//    logical_disk_query += L"'} WHERE AssocClass=Win32_LogicalDiskToPartition";
//
//    IEnumWbemClassObject* pEnumerator = NULL;
//    hres = pSvc->ExecQuery(
//        bstr_t("WQL"),
//        bstr_t("SELECT SerialNumber FROM Win32_PhysicalMedia"),
//        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
//        NULL,
//        &pEnumerator);
//
//    if (FAILED(hres))
//    {
//        pSvc->Release();
//        pLoc->Release();
//        CoUninitialize();
//        return serial_number;
//    }
//
//    IWbemClassObject* pclsObj = NULL;
//    ULONG uReturn = 0;
//
//    // Iterate through the results
//    while (pEnumerator)
//    {
//        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
//        if (0 == uReturn)
//        {
//            break;
//        }
//
//        VARIANT vtProp;
//
//        // Get the serial number property
//        hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
//        if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR)
//        {
//            serial_number = _bstr_t(vtProp.bstrVal);
//        }
//        VariantClear(&vtProp);
//        pclsObj->Release();
//    }
//
//    pEnumerator->Release();
//    pSvc->Release();
//    pLoc->Release();
//    CoUninitialize();
//
//    return serial_number;
//}
//
// 
//// get pnp device id of a usb drive by its drive letter
//string get_pnp_device_id(const string& drive_letter)
//{
//    HRESULT hres;
//    string pnp_device_id = "unknown";
//
//
//    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
//    if (FAILED(hres))
//    {
//        cerr << "Failed to initialize COM library" << endl;
//        return pnp_device_id;
//    }
//
//
//    hres = CoInitializeSecurity(
//        NULL,
//        -1,
//        NULL,
//        NULL,
//        RPC_C_AUTHN_LEVEL_DEFAULT,
//        RPC_C_IMP_LEVEL_IMPERSONATE,
//        NULL,
//        EOAC_NONE,
//        NULL);
//
//    if (FAILED(hres))
//    {
//        cerr << "Failed to initialize security" << endl;
//        CoUninitialize();
//        return pnp_device_id;
//    }
//
//
//    IWbemLocator* p_loc = NULL;
//    hres = CoCreateInstance(
//        CLSID_WbemLocator,
//        0,
//        CLSCTX_INPROC_SERVER,
//        IID_IWbemLocator,
//        (LPVOID*)&p_loc);
//
//    if (FAILED(hres))
//    {
//        cerr << "Failed to create IWbemLocator object" << endl;
//        CoUninitialize();
//        return pnp_device_id;
//    }
//
//    IWbemServices* p_svc = NULL;
//    hres = p_loc->ConnectServer(
//        _bstr_t(L"ROOT\\CIMV2"),
//        NULL,
//        NULL,
//        0,
//        NULL,
//        0,
//        0,
//        &p_svc);
//
//    if (FAILED(hres))
//    {
//        cerr << "Could not connect to WMI namespace ROOT\\CIMV2" << endl;
//        p_loc->Release();
//        CoUninitialize();
//        return pnp_device_id;
//    }
//
//
//    hres = CoSetProxyBlanket(
//        p_svc,
//        RPC_C_AUTHN_WINNT,
//        RPC_C_AUTHZ_NONE,
//        NULL,
//        RPC_C_AUTHN_LEVEL_CALL,
//        RPC_C_IMP_LEVEL_IMPERSONATE,
//        NULL,
//        EOAC_NONE);
//
//    if (FAILED(hres))
//    {
//        cerr << "Could not set proxy blanket" << endl;
//        p_svc->Release();
//        p_loc->Release();
//        CoUninitialize();
//        return pnp_device_id;
//    }
//
//
//    wstring query_partition = L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='";
//    query_partition += wstring(drive_letter.begin(), drive_letter.end());
//    query_partition.pop_back();
//    query_partition += L"'} WHERE AssocClass=Win32_LogicalDiskToPartition";
//
//    IEnumWbemClassObject* p_enumerator = NULL;
//    hres = p_svc->ExecQuery(
//        bstr_t("WQL"),
//        bstr_t(query_partition.c_str()),
//        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
//        NULL,
//        &p_enumerator);
//
//    if (FAILED(hres) || !p_enumerator)
//    {
//        cerr << "Query for partitions failed" << endl;
//        p_svc->Release();
//        p_loc->Release();
//        CoUninitialize();
//        return pnp_device_id;
//    }
//
//    IWbemClassObject* p_partition = NULL;
//    ULONG u_return = 0;
//
//    while (p_enumerator->Next(WBEM_INFINITE, 1, &p_partition, &u_return) == S_OK)
//    {
//        VARIANT vt_device_id;
//        hres = p_partition->Get(L"DeviceID", 0, &vt_device_id, 0, 0);
//
//        if (SUCCEEDED(hres) && vt_device_id.vt == VT_BSTR)
//        {
//            // 2. Ќайти диск, соответствующий разделу
//            wstring query_disk = L"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='";
//            query_disk += vt_device_id.bstrVal;
//            query_disk += L"'} WHERE AssocClass=Win32_DiskDriveToDiskPartition";
//
//            IEnumWbemClassObject* p_disk_enumerator = NULL;
//            hres = p_svc->ExecQuery(
//                bstr_t("WQL"),
//                bstr_t(query_disk.c_str()),
//                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
//                NULL,
//                &p_disk_enumerator);
//
//            if (SUCCEEDED(hres) && p_disk_enumerator)
//            {
//                IWbemClassObject* p_disk = NULL;
//
//                while (p_disk_enumerator->Next(WBEM_INFINITE, 1, &p_disk, &u_return) == S_OK)
//                {
//                    VARIANT vt_pnp_id;
//                    hres = p_disk->Get(L"PNPDeviceID", 0, &vt_pnp_id, 0, 0);
//
//                    if (SUCCEEDED(hres) && vt_pnp_id.vt == VT_BSTR)
//                    {
//                        pnp_device_id = _bstr_t(vt_pnp_id.bstrVal);
//                        VariantClear(&vt_pnp_id);
//                    }
//
//                    p_disk->Release();
//                }
//
//                p_disk_enumerator->Release();
//            }
//
//            VariantClear(&vt_device_id);
//        }
//
//        p_partition->Release();
//    }
//
//    p_enumerator->Release();
//    p_svc->Release();
//    p_loc->Release();
//    CoUninitialize();
//
//    return pnp_device_id;
//}


// get a list of connected removable devices
vector<usb_device_info> get_removable_drives()
{
    vector<usb_device_info> devices;
    char drive_letters[256];
    DWORD size = GetLogicalDriveStringsA(sizeof(drive_letters), drive_letters);

    if (size == 0)
    {
        cerr << "error getting logical drives" << endl;
        return devices;
    }

    for (char* drive = drive_letters; *drive; drive += strlen(drive) + 1)
    {
        if (GetDriveTypeA(drive) == DRIVE_REMOVABLE)
        {
            usb_device_info device;
            device.drive_letter = drive;
            device.serial_number = get_serial_number(drive); 
            device.pnp_device_id = get_pnp_device_id(drive);
            devices.push_back(device);
        }
    }
    return devices;
}

// =============================
// functions for displaying and selecting devices
// =============================

// display connected usb devices
void display_removable_drives(const vector<usb_device_info>& devices)
{
    if (devices.empty())
    {
        cout << "no usb flash drives detected." << endl;
    }
    else
    {
        cout << "available usb flash drives:" << endl;
        for (size_t i = 0; i < devices.size(); ++i)
        {

            string rsa_key_p = devices[i].drive_letter + "\\rsa_private_key.pem";

            bool rsa_key_exists = filesystem::exists(rsa_key_p);

            cout << i + 1 << ". " << devices[i].drive_letter
                << " (pnp device id: " << devices[i].pnp_device_id << ")" << "\t RSA pk:" << (rsa_key_exists ? " Found" : " Not found") << endl;
        }
    }
}

// let the user select a device
usb_device_info select_device(const vector<usb_device_info>& devices)
{
    if (devices.empty())
    {
        cout << "no usb devices available to select." << endl;
        return {};
    }

    int choice = -1;
    while (choice < 1 || choice > static_cast<int>(devices.size()))
    {
        cout << "select a device by entering its number (1-" << devices.size() << "): ";
        cin >> choice;
        if (choice < 1 || choice > static_cast<int>(devices.size()))
        {
            cout << "invalid selection. please try again." << endl;
        }
    }
    return devices[choice - 1];
}

// =============================
// function to update the device list
// =============================

// update the list of devices
vector<usb_device_info> update_drive_list()
{
    auto devices = get_removable_drives();
    system("cls");
    display_removable_drives(devices);
    return devices;
}




// =============================
// other ui 
// =============================




// overwriting aes key to encrypted aes key with PUBLIC key
bool encrypt_and_overwrite_aes_key_with_public_key(const string& aes_key_file, const string& public_key_path)
{

    ifstream input_file(aes_key_file, ios::binary);
    if (!input_file)
    {
        cerr << "Failed to open AES key file: " << aes_key_file << endl;
        return false;
    }

    string aes_key((istreambuf_iterator<char>(input_file)), istreambuf_iterator<char>());
    input_file.close();

    if (aes_key.empty())
    {
        cerr << "AES key file is empty: " << aes_key_file << endl;
        return false;
    }


    string encrypted_key;
    if (!encrypt_aes_key_with_public_key(aes_key, public_key_path, encrypted_key))
    {
        cerr << "Failed to encrypt AES key with public key." << endl;
        return false;
    }


    ofstream output_file(aes_key_file, ios::binary | ios::trunc);
    if (!output_file)
    {
        cerr << "Failed to overwrite AES key file: " << aes_key_file << endl;
        return false;
    }

    output_file.write(encrypted_key.data(), encrypted_key.size());
    

    if (!output_file.good())
    {
        cerr << "Error occurred while writing to file: " << aes_key_file << endl;
        return false;
    }
    output_file.close();
    cout << "AES key successfully encrypted and overwritten in: " << aes_key_file << endl;
    return true;
}

// overwriting aes key to encrypted aes key with PRIVATE key

bool decrypt_and_overwrite_aes_key_with_private_key(const string& encrypted_aes_key_file, const string& private_key_path)
{

    ifstream input_file(encrypted_aes_key_file, ios::binary);
    if (!input_file)
    {
        cerr << "failed to open encrypted AES key file: " << encrypted_aes_key_file << endl;
        return false;
    }

    string encrypted_aes_key((istreambuf_iterator<char>(input_file)), istreambuf_iterator<char>());
    input_file.close();

    if (encrypted_aes_key.empty())
    {
        cerr << "encrypted AES key file is empty: " << encrypted_aes_key_file << endl;
        return false;
    }


    string decrypted_aes_key;
    if (!decrypt_aes_key_with_private_key(encrypted_aes_key, private_key_path, decrypted_aes_key))
    {
        cerr << "failed to decrypt AES key with private key." << endl;
        return false;
    }
    else
    {
        cout << "decrypted AES key size: " << decrypted_aes_key.size() << endl;
    }

    ofstream output_file(encrypted_aes_key_file, ios::binary | ios::trunc);
    if (!output_file)
    {
        cerr << "failed to overwrite AES key file: " << encrypted_aes_key_file << endl;
        return false;
    }

    output_file.write(decrypted_aes_key.data(), decrypted_aes_key.size());
    output_file.close();

    if (!output_file.good())
    {
        cerr << "error occurred while writing to file: " << encrypted_aes_key_file << endl;
        return false;
    }

    cout << "AES key successfully decrypted and overwritten in: " << encrypted_aes_key_file << endl;
    return true;
}

// aes key file utils

bool ensure_aes_key_decrypted(const string& aes_key_file, const string& rsa_private_key_path)
{
    if (is_file_encrypted(aes_key_file))
    {
        if (!decrypt_and_overwrite_aes_key_with_private_key(aes_key_file, rsa_private_key_path))
        {
            cerr << "failed to decrypt AES key.\n";
            return false;
        }
        cout << "AES key successfully decrypted.\n";
    }
    return true;
}


bool ensure_aes_key_encrypted(const string& aes_key_file, const string& rsa_public_key_path)
{
    if (!is_file_encrypted(aes_key_file))
    {
        if (!encrypt_and_overwrite_aes_key_with_public_key(aes_key_file, rsa_public_key_path))
        {
            cerr << "failed to encrypt AES key.\n";
            return false;
        }
        cout << "AES key successfully encrypted.\n";
    }
    return true;
}

// encrypting with aes ui
bool encryption_with_aes_ui(unsigned char* iv, const string& AES_KEY_FILE)
{
    unsigned char aes_key[32];

    if (!load_aes_key(AES_KEY_FILE.c_str(), aes_key, sizeof(aes_key)))
    {
        cerr << "error loading AES key from file";
        return false;
    }


    string input_file_path, output_file_path, output_file_name;
    cout << "1. tell path to which file you want to encrypt (drag & drop it to cmd!)\n";
    cin >> input_file_path;
    system("cls");

    cout << "2. where do you want to save your file?\n";
    cin >> output_file_path;
    system("cls");

    cout << "3. tell me the output file name\n";
    cin >> output_file_name;
    if (output_file_path.back() != '\\' && output_file_path.back() != '/')
    {
        output_file_path += "\\";
    }
    system("cls");

    output_file_name = output_file_name + ".bin";


    output_file_path = output_file_path + output_file_name;




    if (!encrypt_file_with_aes(input_file_path, output_file_path, iv, aes_key))
    {
        fprintf(stderr, "error on encrypting file");
        return false;
    }
    else
    {
        system("cls");
        cout << "encrypting " << input_file_path << " success! \n" << "Path to encrypted file: " << output_file_path << "\n";
        return true;
    }
}

// decrypting with aes ui
bool decryption_with_aes_ui(unsigned char* aes_key, const string AES_KEY_FILE)
{
    string input_file_path, output_file_path, output_base_name;


    cout << "Tell path to the file you want to decrypt (drag & drop it to cmd!):\n";
    cin >> input_file_path;
    system("cls");


    cout << "Where do you want to save your decrypted file? (drag & drop folder or type path):\n";
    cin >> output_file_path;
    if (output_file_path.back() != '\\' && output_file_path.back() != '/')
    {
        output_file_path += "\\";
    }
    system("cls");


    cout << "Enter base name for the decrypted file (without extension):\n";
    cin >> output_base_name;
    system("cls");

    cout << "decryption_with_aes_ui AES_KEY_FILE path: " << AES_KEY_FILE << endl;


    string full_output_path = output_file_path + output_base_name;
    if (!decrypt_file_with_aes(input_file_path, full_output_path, AES_KEY_FILE))
    {
        system("cls");
        cout << "Error decrypting your file\n";
        return false;
    }
    else
    {
        system("cls");
        cout << "decryption of " << input_file_path << " succeeded!\nPath to output file: " << full_output_path << endl;
        return true;
    }
}



// =============================
// initializing aes and iv
// =============================
unsigned char* initialize_aes()
{

    unsigned char* aes = generate_aes_key();
    if (!aes)
    {
        free(aes);
        return nullptr;
    }
    return aes;

    /*unsigned char* aes = new unsigned char[32];
    if (is_file_exists(AES_KEY_FILE.c_str()))
    {
        if (!load_aes_key(AES_KEY_FILE.c_str(), aes, 32))
        {
            delete[] aes;
            return nullptr;
        }
    }
    else
    {
        cout << "cant find aes key file, generating new one...\n";

        unsigned char* gen_aes = generate_aes_key();
        if (!gen_aes)
        {
            delete[] aes;
            cout << "error on generating new aes key.";
            return nullptr;
        }
        memcpy(aes, gen_aes, 32);
        delete[] gen_aes;
    }

    return aes;*/
}
unsigned char* initialize_iv()
{
    unsigned char* iv = generate_iv();
    if (!iv)
    {
        free(iv);
        return nullptr;
    }
    return iv;
}
// =============================
// main ui
// =============================
bool user_interface()
{
    static unsigned char* aes = initialize_aes();
    static unsigned char* iv = initialize_iv();


    static usb_device_info selected_device;
    bool running = true;
    vector<usb_device_info> devices = get_removable_drives();

    display_removable_drives(devices);
    while (running)
    {
        cout << "\ncryptk tool menu:\n";
        cout << "1. display available usb devices\n";
        cout << "2. select a usb device\n";
        cout << "3. refresh device list\n";
        cout << "4. encrypt file\n";
        cout << "5. decrypt file\n";
        cout << "6. exit\n";
        cout << "enter your choice: ";

        int choice;
        cin >> choice;


        if (isdigit(choice))
        {
            switch (choice)
            {
            case 1:
                system("cls");
                display_removable_drives(devices);
                break;

            case 2:
            {
                system("cls");
                display_removable_drives(devices);
                selected_device = select_device(devices);

                if (!selected_device.drive_letter.empty())
                {

                    cout << "you selected: " << selected_device.drive_letter
                        << " (pnp device id: " << selected_device.pnp_device_id << ")" << endl;

                    filesystem::path selected_flash_path = root_path + (string)selected_device.serial_number;

                    if (!filesystem::exists(selected_flash_path))
                    {
                        filesystem::create_directory(selected_flash_path);
                    }

                    AES_KEY_FILE = AES_KEY_FILE + selected_device.serial_number + "\\aes_key.bin";

                    if (!is_file_exists(AES_KEY_FILE.c_str()))
                    {
                        ofstream key_file(AES_KEY_FILE.c_str(), ios::binary);
                        key_file.write(reinterpret_cast<const char*>(aes), 32);
                        key_file.close();
                    }
                    else
                    {
                        load_aes_key(AES_KEY_FILE.c_str(), aes, 32);
                    }

                    RSA_PUBLIC_KEY_PATH = RSA_PUBLIC_KEY_PATH + "\\" + (string)selected_device.serial_number + "\\rsa_public_key.pem";


                    string rsa_private_key_path = selected_device.drive_letter + "rsa_private_key.pem";
                    if (!is_file_exists(RSA_PUBLIC_KEY_PATH.c_str()))
                    {
                        if (!generate_and_save_rsa_keys(rsa_private_key_path, RSA_PUBLIC_KEY_PATH))
                        {
                            cerr << "error on writing rsa keys\n";
                            return false;
                        }
                    }
                    if (!is_file_encrypted(AES_KEY_FILE.c_str()))
                    {
                        ensure_aes_key_encrypted(AES_KEY_FILE, RSA_PUBLIC_KEY_PATH.c_str());
                    }
                }
                break;
            }

            case 3:
                system("cls");
                devices = update_drive_list();
                break;
            case 4:
                system("cls");
                if (!selected_device.drive_letter.empty())
                {

                    string rsa_private_key_path = selected_device.drive_letter + "rsa_private_key.pem";

                    if (is_file_encrypted(AES_KEY_FILE.c_str()))
                    {
                        ensure_aes_key_decrypted(AES_KEY_FILE.c_str(), rsa_private_key_path.c_str());
                    }
                    if (!encryption_with_aes_ui(iv, AES_KEY_FILE.c_str()))
                    {
                        cout << "error on encrypting files...\n";
                        ensure_aes_key_encrypted(AES_KEY_FILE.c_str(), RSA_PUBLIC_KEY_PATH.c_str());
                        return false;
                    }
                    ensure_aes_key_encrypted(AES_KEY_FILE.c_str(), RSA_PUBLIC_KEY_PATH.c_str());
                }
                else
                {
                    cout << "please, pick a device (option 2)\n";
                }
                break;
            case 5:
                system("cls");
                if (!selected_device.drive_letter.empty())
                {
                    string rsa_private_key_path = selected_device.drive_letter + "rsa_private_key.pem";

                    if (is_file_encrypted(AES_KEY_FILE.c_str()))
                    {
                        ensure_aes_key_decrypted(AES_KEY_FILE.c_str(), rsa_private_key_path.c_str());
                    }

                    if (!decryption_with_aes_ui(aes, AES_KEY_FILE.c_str()))
                    {
                        cout << "error on decrypting files...\n";
                        ensure_aes_key_encrypted(AES_KEY_FILE.c_str(), RSA_PUBLIC_KEY_PATH.c_str());
                        return false;
                    }
                    ensure_aes_key_encrypted(AES_KEY_FILE.c_str(), RSA_PUBLIC_KEY_PATH.c_str());
                }
                else
                {
                    cout << "please, pick a device (option 2)\n";
                }
                break;
            case 6:
                running = false;
                break;

            default:
                cout << "invalid choice. please try again.\n";
            }
        }
        else
        {
            cout << "Invalid choice\n";
            return 0;
        }
    }
      
    delete[] aes;
    delete[] iv;
}




int main()
{
    create_root_folder();
    user_interface();

    return 0;
}
