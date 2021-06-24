#include <Windows.h>
#include <detours.h>
#pragma comment(lib, "detours.lib")

typedef BOOL(APIENTRY* ProtoType_WriteProcessMemory)
(   
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
 );

ProtoType_WriteProcessMemory WriteProcessMemoryHook = 
(ProtoType_WriteProcessMemory)((uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory"));

BOOL APIENTRY WriteProcessMemoryHooked
(
    _In_   HANDLE hProcess,               // Handle To Specified Process
    _In_   LPVOID lpBaseAddress,          // Dll's memory allocated in a buffer or programs memory.
    _In_   LPCVOID lpBuffer ,             // Dll Path (Buffer, text)
    _In_   SIZE_T nSize,                  // Dll Path (Length)
    _Out_  SIZE_T* lpNumberOfBytesWritten  
)
{
    MessageBoxA(0, "Hooked on WriteProcessMemory!", "Success", 0);
    const char* dllPath = reinterpret_cast<const char*>(*lpBuffer);
    MessageBoXA(0, dllPath, "Grabbed Dll Path!",0);
}


BOOL APIENTRY DllMain( HMODULE hModule, DWORD Reason,LPVOID lpReserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(LPVOID&)WriteProcessMemoryHook, (PBYTE)WriteProcessMemoryHooked);
        DetourTransactionCommit();
    }
    return TRUE;
}

