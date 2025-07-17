# winmm.dll hijack & DLL Injection & Hook

Hijack `winmm.dll` and inject a specified DLL.

The target exe to be hijacked must have `winmm.dll` in its Import Address Table (IAT) for the hijack to succeed.

> To check the target exe's architecture and IAT, use: [Detect it easy](https://github.com/horsicq/Detect-It-Easy)

## Build

Build the project in Release mode to generate two files:
- winmm.x86.dll
- winmm.x64.dll

## Usage

1. If the target exe is x86, rename `winmm.x86.dll` to `winmm.dll` and place it in the program's directory.
2. The DLLs to be injected should be named as `winmm.xxx.dll` and placed in the same directory.

    Multiple DLLs are supported, for example:

    ```
    winmm.core.dll
    winmm.module.dll
    ```

3. The loading order is simple lexicographical order, e.g., `winmm.a.dll` loads before `winmm.b.dll`.

4. To check if the DLLs loaded successfully, use [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview).

    The following output indicates that `winmm.core.dll` was injected successfully:
    ```
    Injected dll: winmm.core.dll
    ```

## Development

1. You can use [Baymax Patch Tools](https://www.chinapyg.com/thread-83083-1-1.html) or [AHeadLibEx](https://github.com/i1tao/AheadLibEx) to generate hijack source code.

    For example, for system DLLs like `winhttp.dll` or `version.dll`.

2. You need to generate x86 and x64 source code separately:
    - System x64 DLLs are in: `C:\Windows\System32`
    - System x86 DLLs are in: `C:\Windows\SysWOW64`

    - x86 will generate only a .cpp file
    - x64 will generate .cpp and .asm files; the exported functions' code is actually in the .asm file

## Exported Methods

winmm.dll exports 3 simple hook methods:

```cpp
long hook(PVOID* originalFunc, PVOID hookFunc);
long unhook(PVOID* originalFunc, PVOID hookFunc);
long hookTransaction(HANDLE threadHandle, void (*callback)(void));
```

In addition, all Detours methods are exported:

```cpp
LONG WINAPI DetourTransactionBegin(VOID);
LONG WINAPI DetourTransactionCommit(VOID);
LONG WINAPI DetourTransactionAbort(VOID);
LONG WINAPI DetourUpdateThread(HANDLE hThread);
LONG WINAPI DetourAttach(PVOID *ppPointer, PVOID pDetour);
LONG WINAPI DetourAttachEx(PVOID *ppPointer, PVOID pDetour, PDETOUR_TRAMPOLINE *ppRealTrampoline, PVOID *ppRealTarget, PVOID *ppRealDetour);
LONG WINAPI DetourDetach(PVOID *ppPointer, PVOID pDetour);

BOOL WINAPI DetourCreateProcessWithDllExA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, LPCSTR lpDllName, PDETOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA);
BOOL WINAPI DetourCreateProcessWithDllExW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, LPCSTR lpDllName, PDETOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);

BOOL WINAPI DetourCreateProcessWithDllsA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD nDlls, LPCSTR *rlpDlls, PDETOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA);
BOOL WINAPI DetourCreateProcessWithDllsW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD nDlls, LPCSTR *rlpDlls, PDETOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);

BOOL WINAPI DetourRestoreAfterWith(VOID);
BOOL WINAPI DetourFinishHelperProcess(HANDLE hProcess, DWORD dwProcessId, BOOL fFinishedProcess);

PVOID WINAPI DetourBinaryOpen(HANDLE hFile);
VOID WINAPI DetourBinaryClose(PVOID pBinary);
BOOL WINAPI DetourBinaryWrite(HANDLE hFile, PVOID pBinary);
BOOL WINAPI DetourBinaryResetImports(PVOID pBinary);
BOOL WINAPI DetourBinaryEditImports(PVOID pBinary, PVOID pContext, PF_DETOUR_BINARY_BYWAY_CALLBACK pfByway, PF_DETOUR_BINARY_FILE_CALLBACK pfFile, PF_DETOUR_BINARY_SYMBOL_CALLBACK pfSymbol, PF_DETOUR_BINARY_COMMIT_CALLBACK pfCommit);

PVOID WINAPI DetourAllocateRegionWithinJumpBounds(PVOID pbTarget, LONG cbAllocate);
PVOID WINAPI DetourCopyInstruction(PVOID pDst, PVOID *ppDstPool, PVOID pSrc, PVOID *ppTarget, LONG *plExtra);

BOOL WINAPI DetourSetCodeModule(HMODULE hModule, BOOL fLimitReferencesToModule);
BOOL WINAPI DetourSetIgnoreTooSmall(BOOL fIgnore);
BOOL WINAPI DetourSetRetainRegions(BOOL fRetain);
BOOL WINAPI DetourSetSystemRegionLowerBound(PVOID pSystemRegionLowerBound);
BOOL WINAPI DetourSetSystemRegionUpperBound(PVOID pSystemRegionUpperBound);

PVOID WINAPI DetourGetEntryPoint(HMODULE hModule);
ULONG WINAPI DetourGetModuleSize(HMODULE hModule);
HMODULE WINAPI DetourEnumerateModules(HMODULE hModuleLast);
ULONG WINAPI DetourGetSizeOfPayloads(HMODULE hModule);

PVOID WINAPI DetourFindPayload(HMODULE hModule, REFGUID rguid, DWORD *pcbData);
PVOID WINAPI DetourGetContainingModule(PVOID pvAddr);

BOOL WINAPI DetourEnumerateImports(HMODULE hModule, PVOID pContext, PF_DETOUR_IMPORT_FILE_CALLBACK pfImportFile, PF_DETOUR_IMPORT_FUNC_CALLBACK pfImportFunc);
BOOL WINAPI DetourEnumerateExports(HMODULE hModule, PVOID pContext, PF_DETOUR_ENUMERATE_EXPORT_CALLBACK pfExport);
```

## Example: Hooking a System Function

For example, to hook `CreateFileW`, refer to the following in `dllmain.cpp` of your `winmm.xxx.dll`:

```cpp
#include <Windows.h>

// Declare parent winmm.dll functions
#define BindDllMethod(funcPtr, dllHandle, funcName) (funcPtr = (decltype(funcPtr))GetProcAddress(dllHandle, funcName))
long (*hookTransaction)(HANDLE threadHandle, void (*callback)(void)) = nullptr;
long (*hook)(PVOID* originalFunc, PVOID hookFunc) = nullptr;
long (*unhook)(PVOID* originalFunc, PVOID hookFunc) = nullptr;

// Pointer to the original CreateFileW function
auto RealCreateFileW = CreateFileW;

// Hook function
static HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    // Do what you want here

    // Call the original CreateFileW function
    HANDLE hFile = RealCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );

    // Do what you want here

    return hFile;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH: {
            HMODULE hModule = GetModuleHandle("winmm.dll");
            if (nullptr == hModule) { // This DLL was not loaded by winmm.dll, cannot hook
                return;
            }
            // Bind methods
            BindDllMethod(hookTransaction, hModule, "hookTransaction");
            BindDllMethod(hook, hModule, "hook");
            BindDllMethod(unhook, hModule, "unhook");

            if (hookTransaction != nullptr) {
                hookTransaction(NULL, [](){
                    hook(&(PVOID&)RealCreateFileW, (PVOID)HookCreateFileW);
                    // ...
                });
            }
        } break;
        case DLL_PROCESS_DETACH: {
            if (hookTransaction != nullptr) {
                hookTransaction(NULL, [](){
                    unhook(&(PVOID&)RealCreateFileW, (PVOID)HookCreateFileW);
                    // ...
                });
            }
        }
        break;
    }
}

#undef BindDllMethod // Avoid affecting other modules

```
