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

// path to AES key if alr generated
string AES_KEY_FILE = "C:\\ProgramData\\aes_key.bin";

// path to temp AES encrypted key

string AES_KEY_FILE_ENCRYPTED = "C:\\ProgramData\\aes_key_enc.bin";

// path to cfg file
const string CFG_FILE = "C:\\ProgramData\\quanticrypt_cfg.txt";

// path to public RSA key

const string RSA_PUBLIC_KEY_PATH = "C:\\ProgramData\\rsa_public_key.pem";

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

//void create_root_folder()
//{
//    string root_folder_path = "C:\\ProgramData\\cryptk";
//    if(CreateDirectory(root_folder_path.c_str(), NULL))
//}



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

// get pnp device id of a usb drive by its drive letter
string get_pnp_device_id(const string& drive_letter)
{
    HRESULT hres;
    string pnp_device_id = "unknown";

    // initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        return pnp_device_id;
    }

    // initialize security
    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL);

    if (FAILED(hres))
    {
        CoUninitialize();
        return pnp_device_id;
    }

    // obtain the initial locator to WMI
    IWbemLocator* p_loc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&p_loc);

    if (FAILED(hres))
    {
        CoUninitialize();
        return pnp_device_id;
    }

    IWbemServices* p_svc = NULL;
    hres = p_loc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // wmi namespace
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &p_svc);

    if (FAILED(hres))
    {
        p_loc->Release();
        CoUninitialize();
        return pnp_device_id;
    }

    // set the proxy for impersonation
    hres = CoSetProxyBlanket(
        p_svc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        p_svc->Release();
        p_loc->Release();
        CoUninitialize();
        return pnp_device_id;
    }

    // query for the disk drive associated with the logical disk
    wstring logical_disk_query = L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='";
    logical_disk_query += wstring(drive_letter.begin(), drive_letter.end());
    logical_disk_query.pop_back(); // remove trailing backslash
    logical_disk_query += L"'} WHERE AssocClass=Win32_LogicalDiskToPartition";

    IEnumWbemClassObject* p_enumerator = NULL;
    hres = p_svc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT PNPDeviceID FROM Win32_DiskDrive WHERE MediaType = 'Removable Media'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &p_enumerator);

    if (FAILED(hres))
    {
        p_svc->Release();
        p_loc->Release();
        CoUninitialize();
        return pnp_device_id;
    }

    IWbemClassObject* p_cls_obj = NULL;
    ULONG u_return = 0;

    // iterate through partitions to find the corresponding disk
    while (p_enumerator)
    {
        hres = p_enumerator->Next(WBEM_INFINITE, 1, &p_cls_obj, &u_return);
        if (0 == u_return)
        {
            break;
        }

        VARIANT vt_prop;

        // get the pnp device id from the associated disk
        hres = p_cls_obj->Get(L"PNPDeviceID", 0, &vt_prop, 0, 0);
        if (SUCCEEDED(hres) && vt_prop.vt == VT_BSTR)
        {
            pnp_device_id = _bstr_t(vt_prop.bstrVal);
        }
        VariantClear(&vt_prop);
        p_cls_obj->Release();
    }

    p_enumerator->Release();
    p_svc->Release();
    p_loc->Release();
    CoUninitialize();

    return pnp_device_id;
}

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
            device.serial_number = "not implemented"; // implement later if needed
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
            cout << i + 1 << ". " << devices[i].drive_letter
                << " (pnp device id: " << devices[i].pnp_device_id << ")" << endl;
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
// windows event handling
// =============================

// main window procedure for handling device events
LRESULT CALLBACK window_proc(HWND hwnd, UINT u_msg, WPARAM w_param, LPARAM l_param)
{
    static vector<usb_device_info> devices = get_removable_drives();

    switch (u_msg)
    {
    case WM_DEVICECHANGE:
        if (w_param == DBT_DEVICEARRIVAL || w_param == DBT_DEVICEREMOVECOMPLETE)
        {
            devices = update_drive_list();
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, u_msg, w_param, l_param);
    }
    return 0;
}

// =============================
// other ui 
// =============================

// overwriting aes key to encrypted aes key with PUBLIC key
bool encrypt_and_overwrite_aes_key_with_public_key(const string& aes_key_file, const string& public_key_path) {

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
    output_file.close();

    if (!output_file.good())
    {
        cerr << "Error occurred while writing to file: " << aes_key_file << endl;
        return false;
    }

    cout << "AES key successfully encrypted and overwritten in: " << aes_key_file << endl;
    return true;
}

// overwriting aes key to encrypted aes key with PRIVATE key

bool decrypt_and_overwrite_aes_key_with_private_key(const string& encrypted_aes_key_file, const string& private_key_path) {

    ifstream input_file(encrypted_aes_key_file, ios::binary);
    if (!input_file) {
        cerr << "Failed to open encrypted AES key file: " << encrypted_aes_key_file << endl;
        return false;
    }

    string encrypted_aes_key((istreambuf_iterator<char>(input_file)), istreambuf_iterator<char>());
    input_file.close();

    if (encrypted_aes_key.empty()) {
        cerr << "Encrypted AES key file is empty: " << encrypted_aes_key_file << endl;
        return false;
    }


    string decrypted_aes_key;
    if (!decrypt_aes_key_with_private_key(encrypted_aes_key, private_key_path, decrypted_aes_key))
    {
        cerr << "Failed to decrypt AES key with private key." << endl;
        return false;
    }


    ofstream output_file(encrypted_aes_key_file, ios::binary | ios::trunc);
    if (!output_file) {
        cerr << "Failed to overwrite AES key file: " << encrypted_aes_key_file << endl;
        return false;
    }

    output_file.write(decrypted_aes_key.data(), decrypted_aes_key.size());
    output_file.close();

    if (!output_file.good()) {
        cerr << "Error occurred while writing to file: " << encrypted_aes_key_file << endl;
        return false;
    }

    cout << "AES key successfully decrypted and overwritten in: " << encrypted_aes_key_file << endl;
    return true;
}


// encrypting with aes ui
bool encryption_with_aes_ui(unsigned char* iv, unsigned char* aes_key)
{
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
        output_file_path += "\\"; // adding slash if user didnt put it himself
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
bool decryption_with_aes_ui(unsigned char* aes_key)
{
    string input_file_path, output_file_path, output_base_name;


    cout << "Tell path to the file you want to decrypt (drag & drop it to cmd!):\n";
    cin >> input_file_path;
    system("cls");


    cout << "Where do you want to save your decrypted file? (drag & drop folder or type path):\n";
    cin >> output_file_path;
    if (output_file_path.back() != '\\' && output_file_path.back() != '/')
    {
        output_file_path += "\\"; // adding slash if user didnt put it himself
    }
    system("cls");


    cout << "Enter base name for the decrypted file:\n";
    cin >> output_base_name;
    system("cls");


    string full_output_path = output_file_path + output_base_name;
    if (!decrypt_file_with_aes(input_file_path, full_output_path))
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
    unsigned char* aes = new unsigned char[32];
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

    return aes;
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
    unsigned char* aes = initialize_aes();
    unsigned char* iv = initialize_iv();



    static usb_device_info selected_device;
    bool running = true;
    vector<usb_device_info> devices = get_removable_drives();

    display_removable_drives(devices);
    while (running)
    {
        cout << "\ncryptk tool menu:\n";
        cout << "1. select a usb device\n";
        cout << "2. encrypt/decrypt file\n";
        cout << "3. settings\n";
        cout << "4. exit\n";
        cout << "enter your choice: ";

        int choice;
        cin >> choice;

        

        switch (choice)
        {
        case 1:
            system("cls");
            display_removable_drives(devices);
            selected_device = select_device(devices);

            if (!selected_device.drive_letter.empty())
            {

                cout << "you selected: " << selected_device.drive_letter
                    << " (pnp device id: " << selected_device.pnp_device_id << ")" << endl;


                string rsa_private_key_path = selected_device.drive_letter + "rsa_private_key.pem";
                if (!is_file_exists(rsa_private_key_path.c_str()))
                {
                    if (!generate_and_save_rsa_keys(rsa_private_key_path, RSA_PUBLIC_KEY_PATH))
                    {
                        cerr << "error on writing rsa keys\n";
                        return false;
                    }
                }
            }
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


                string rsa_private_key_path = selected_device.drive_letter + "rsa_private_key.pem";
                if (!is_file_exists(RSA_PUBLIC_KEY_PATH.c_str()))
                {
                    if (!generate_and_save_rsa_keys(rsa_private_key_path, RSA_PUBLIC_KEY_PATH))
                    {
                        cerr << "error on writing rsa keys\n";
                        return false;
                    }
                }
            }
            break;
        }

        case 3:
            system("cls");
            devices = update_drive_list();
            break;
        //case 4:
        //    system("cls");
        //    if (!selected_device.drive_letter.empty())
        //    {
        //        if (!encryption_with_aes_ui(iv, aes))
        //        {
        //            cout << "error on encrypting files...\n";
        //            return false;
        //        }
        //    }
        //    else
        //    {
        //        cout << "please, pick a device (option 2)\n";
        //    }
        //    break;
        //case 5:
        //    system("cls");
        //    if (!decryption_with_aes_ui(aes))
        //    {
        //        return false;
        //    }
        //    break;
        case 4:
            running = false;
            break;
        case 7:
            if (!encrypt_and_overwrite_aes_key_with_public_key(AES_KEY_FILE, RSA_PUBLIC_KEY_PATH))
            {
                return false;
            }
            else
            {
                cout << "succesfully encrypted AES key with RSA key\n";
            }
            break;
        case 8:
            if (!selected_device.drive_letter.empty()) {
                string rsa_key_path = selected_device.drive_letter + "rsa_private_key.pem";
                if (!decrypt_and_overwrite_aes_key_with_private_key(AES_KEY_FILE, rsa_key_path))
                {
                    return false;
                }
            }
            else
            {
                cout << "please, select a device that has RSA private key\n";
            }
            break;
        default:
            cout << "invalid choice. please try again.\n";
        }
    }
    delete[] aes;
    delete[] iv;
}




int main()
{
    if()
    user_interface();

    return 0;
}