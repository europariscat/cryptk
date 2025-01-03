#pragma once
#include "includes.h"
using namespace std;

string get_serial_number(const string& drive_letter)
{
    HRESULT hres;
    string serial_number = "unknown";

    // Initialize COM library
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        return serial_number;
    }

    // Initialize security
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
        return serial_number;
    }

    // Obtain the initial locator to WMI
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        CoUninitialize();
        return serial_number;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres))
    {
        pLoc->Release();
        CoUninitialize();
        return serial_number;
    }

    // Set the proxy for impersonation
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return serial_number;
    }

    // Query for the disk drive associated with the logical disk
    wstring logical_disk_query = L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='";
    logical_disk_query += wstring(drive_letter.begin(), drive_letter.end());
    logical_disk_query.pop_back(); // Remove trailing backslash
    logical_disk_query += L"'} WHERE AssocClass=Win32_LogicalDiskToPartition";

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT SerialNumber FROM Win32_PhysicalMedia"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return serial_number;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    // Iterate through the results
    while (pEnumerator)
    {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        // Get the serial number property
        hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR)
        {
            serial_number = _bstr_t(vtProp.bstrVal);
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return serial_number;
}


// get pnp device id of a usb drive by its drive letter
string get_pnp_device_id(const string& drive_letter)
{
    HRESULT hres;
    string pnp_device_id = "unknown";


    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cerr << "Failed to initialize COM library" << endl;
        return pnp_device_id;
    }


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
        cerr << "Failed to initialize security" << endl;
        CoUninitialize();
        return pnp_device_id;
    }


    IWbemLocator* p_loc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&p_loc);

    if (FAILED(hres))
    {
        cerr << "Failed to create IWbemLocator object" << endl;
        CoUninitialize();
        return pnp_device_id;
    }

    IWbemServices* p_svc = NULL;
    hres = p_loc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &p_svc);

    if (FAILED(hres))
    {
        cerr << "Could not connect to WMI namespace ROOT\\CIMV2" << endl;
        p_loc->Release();
        CoUninitialize();
        return pnp_device_id;
    }


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
        cerr << "Could not set proxy blanket" << endl;
        p_svc->Release();
        p_loc->Release();
        CoUninitialize();
        return pnp_device_id;
    }


    wstring query_partition = L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='";
    query_partition += wstring(drive_letter.begin(), drive_letter.end());
    query_partition.pop_back();
    query_partition += L"'} WHERE AssocClass=Win32_LogicalDiskToPartition";

    IEnumWbemClassObject* p_enumerator = NULL;
    hres = p_svc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query_partition.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &p_enumerator);

    if (FAILED(hres) || !p_enumerator)
    {
        cerr << "Query for partitions failed" << endl;
        p_svc->Release();
        p_loc->Release();
        CoUninitialize();
        return pnp_device_id;
    }

    IWbemClassObject* p_partition = NULL;
    ULONG u_return = 0;

    while (p_enumerator->Next(WBEM_INFINITE, 1, &p_partition, &u_return) == S_OK)
    {
        VARIANT vt_device_id;
        hres = p_partition->Get(L"DeviceID", 0, &vt_device_id, 0, 0);

        if (SUCCEEDED(hres) && vt_device_id.vt == VT_BSTR)
        {
            // 2. Ќайти диск, соответствующий разделу
            wstring query_disk = L"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='";
            query_disk += vt_device_id.bstrVal;
            query_disk += L"'} WHERE AssocClass=Win32_DiskDriveToDiskPartition";

            IEnumWbemClassObject* p_disk_enumerator = NULL;
            hres = p_svc->ExecQuery(
                bstr_t("WQL"),
                bstr_t(query_disk.c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL,
                &p_disk_enumerator);

            if (SUCCEEDED(hres) && p_disk_enumerator)
            {
                IWbemClassObject* p_disk = NULL;

                while (p_disk_enumerator->Next(WBEM_INFINITE, 1, &p_disk, &u_return) == S_OK)
                {
                    VARIANT vt_pnp_id;
                    hres = p_disk->Get(L"PNPDeviceID", 0, &vt_pnp_id, 0, 0);

                    if (SUCCEEDED(hres) && vt_pnp_id.vt == VT_BSTR)
                    {
                        pnp_device_id = _bstr_t(vt_pnp_id.bstrVal);
                        VariantClear(&vt_pnp_id);
                    }

                    p_disk->Release();
                }

                p_disk_enumerator->Release();
            }

            VariantClear(&vt_device_id);
        }

        p_partition->Release();
    }

    p_enumerator->Release();
    p_svc->Release();
    p_loc->Release();
    CoUninitialize();

    return pnp_device_id;
}
