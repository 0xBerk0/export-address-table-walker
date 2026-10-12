#include <Windows.h>
#include <stdio.h>
#include <inttypes.h>


int main () {

    HANDLE  hKernel32 = CreateFileA(
        "C:\\Windows\\System32\\kernel32.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hKernel32 == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFileA failed: %d/n", GetLastError());
        return 1;

    }

    DWORD dwFileSize = GetFileSize(hKernel32, NULL);

    void *lpBuffer = VirtualAlloc(
        NULL, 
        dwFileSize, 
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_READWRITE
    );

    if (!lpBuffer)
    {
        printf("[-] VirtualAlloc failed: %d/n", GetLastError());
        return 1;
    }


    if (!ReadFile(
        hKernel32,
        lpBuffer,
        dwFileSize,
        NULL,
        NULL
    ))
    {
        printf("[-] ReadFile failed: %d\n", GetLastError());
        return 1;
    }

    CloseHandle(hKernel32);

    PIMAGE_DOS_HEADER pImageDOSHeader;
    PIMAGE_NT_HEADERS pImageNTHeaders;

    pImageDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;
    if (pImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) 
    {
        printf("INVALID PE");
        return 1;
    }

    printf("[+] Valid PE loaded into memory\n");

    pImageNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)pImageDOSHeader + pImageDOSHeader->e_lfanew);

    if (pImageNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        printf("[-] Invalid PE architecture. Use a 64-bit PE\n");
        return 1;
    }

    IMAGE_DATA_DIRECTORY exportDataDir = pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDataDir.VirtualAddress == 0)
    {
        printf("[-] Without exports\n");
        return 1;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)pImageDOSHeader + exportDataDir.VirtualAddress);

    DWORD *pFunctions = (DWORD *)((BYTE *)pImageDOSHeader + pExportDir->AddressOfFunctions);
    DWORD *pNames = (DWORD *)((BYTE *)pImageDOSHeader + pExportDir->AddressOfNames);
    WORD *pOrdinals = (WORD *)((BYTE *)pImageDOSHeader + pExportDir->AddressOfNameOrdinals);


    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
    {
        const char *name = (const char *)((BYTE *)lpBuffer + pNames[i]);
        WORD idx = pOrdinals[i];
        DWORD funcRVA = pFunctions[idx];

        printf("%4u  0x%08lX  %s\n",
           (unsigned)(idx + pExportDir->Base),
           funcRVA,
           name);
    }

    return 0;

}
    








