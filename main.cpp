#include <iostream>
#include <string>
#include <ctype.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

int getProcId(const string& p_name);
bool injectDDL(const int &pid, const string &DLL_Path);
void usage();

int main(int argc, char ** argv)
{
    if (argc != 3)
    {
        usage();
        return EXIT_FAILURE;
    }

    if (PathFileExists(argv[2]) == FALSE)
    {
        cerr << "DLL File not existing." << endl;
        return EXIT_FAILURE;
    }

    if (isdigit(argv[1][0]))
    {
        cout << "PID: " << atoi(argv[1]) << endl;
        injectDDL(atoi(argv[1]), argv[2]);
    }
    else {
        injectDDL(getProcId(argv[1]), argv[2]);
    }

    return EXIT_SUCCESS;
}

int getProcID(const string& p_name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32  processentry32 = { 0 };

    processentry32.dwSize = sizeof(PROCESSENTRY32);

    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32First(snapshot, &processentry32) == FALSE) return 0;

    while (Process32Next(snapshot, &processentry32))
    {
        if (!strcmp(processentry32.szExeFile, p_name.c_str()))
        {
            CloseHandle(snapshot);
            cout << "Process name: " << p_name << "\nProcess ID: " << processentry32.th32ProcessID << endl;
            return processentry32.th32ProcessID;
        }
    }

    CloseHandle(snapshot);
    cerr << "Can't find a PID" << endl;
}

bool injectDDL(const int &pid, const string &DLL_Path)
{
    long dll_size = DLL_Path.length() + 1;
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProc == NULL)
    {
        cerr << "Can't open process." << endl;
        return false;
    }

    cout << "Trying to open process..." << endl;

    LPVOID MyAlloc = VirtualAllocEx(hProc, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (MyAlloc == NULL)
    {
        cerr << "Failed to allocate memory in process." << endl;
        return false;
    }

    cout << "Allocating memory in process..." << endl;
    int IsWriteable = WriteProcessMemory(hProc, MyAlloc, DLL_Path.c_str(), dll_size, 0);
    if (IsWriteable == 0)
    {
        cerr << "Failed to write in process memory." << endl;
    }
    cout << "Creating remote Thread in process..." << endl;

    DWORD dWord;
    LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
    HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
    if (ThreadReturn == NULL)
    {
        cerr << "Failed to create remote thread." << endl;
        return false;
    }

    if ((hProc != NULL) && (MyAlloc != NULL) && (IsWriteable != ERROR_INVALID_HANDLE) && (ThreadReturn != NULL))
    {
        cout << "Injected!" << endl;
        return true;
    }

    return false;
}

void usage()
{
    cout << "How to use: Injector.exe <process_name/pid> <dll path>" << endl;
}