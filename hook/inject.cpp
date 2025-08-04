#include "inject.h"
#include <algorithm>
#include <regex>
#include "utils.h"
#include <tchar.h>
#include <shellapi.h>
#include <vector>
#include <fstream>
#include <filesystem>
#include <windows.h> 
#include <iostream>

std::vector<HMEMORYMODULE> g_InjectDlls;
static bool g_consoleInitialized = false;

// Safe console initialization that won't conflict with injected DLL
void InitWinMMConsole() {
    if (g_consoleInitialized) return;
    
    // Only allocate console if one doesn't exist
    if (!GetConsoleWindow()) {
        AllocConsole();
    }
    
    // Redirect stdout to console without interfering with injected DLL streams
    FILE* pCout;
    freopen_s(&pCout, "CONOUT$", "w", stdout);
    
    g_consoleInitialized = true;
}

void WinMMLog(const std::wstring& message) {
    InitWinMMConsole();
    std::wcout << L"[WINMM] " << message << L"\n";
    std::wcout.flush();
}

// temp for testing
std::vector<BYTE> LoadLocalDll(const std::filesystem::path &dllPath) {
    std::vector<BYTE> modBytes;
    
    if (!std::filesystem::exists(dllPath)) {
        WinMMLog(L"Local DLL not found: " + dllPath.wstring());
        return modBytes;
    }

    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        WinMMLog(L"Failed to open local DLL");
        return modBytes;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    modBytes.resize(static_cast<size_t>(size));

    if (!file.read(reinterpret_cast<char*>(modBytes.data()), size)) {
        WinMMLog(L"Failed to read local DLL");
        return {};
    } 
    else {
        WinMMLog(L"Successfully loaded local DLL");
    }
    return modBytes;
}

std::vector<HMEMORYMODULE> LoadInjectDlls(const std::wstring &tokenParam) {
    int argc;
    LPWSTR cmdLine = GetCommandLineW();
    LPWSTR *argv = CommandLineToArgvW(cmdLine, &argc);

    bool mpEnabled = false;
    std::wstring token;

    // Parse CL arguments
    for (int i = 0; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-mp") {
            mpEnabled = true;
            WinMMLog(L"-mp argument detected"); 
        } 
        else if (arg.starts_with(L"-token=")) {
            token = arg.substr(7);
            WinMMLog(L"Token found: " + token);
        }    
    }
    LocalFree(argv);

    if(!mpEnabled || token.empty()) {
        WinMMLog(L"No MP arg or token provided");
        return {};
    }

    std::vector<BYTE> modBytes;

    // Local injection for testing
    {
        WinMMLog(L"Loading local DLL for testing");
        std::filesystem::path CurrentDllPath = GetCurrentDllPath(NULL);
        std::filesystem::path dllPath = CurrentDllPath.parent_path();

        // Load DLL with name matching the token
        std::filesystem::path localDllPath = dllPath / (token + L".dll");
        modBytes = LoadLocalDll(localDllPath);

        if (modBytes.empty()) {
            WinMMLog(L"Failed to load local DLL");
            return {};
        }
    }

    // VPS injection
    // {
    //     WinMMLog(L"Attempting to download from VPS");
    //     if (!VerifyToken(token)) {
    //         WinMMLog(L"Invalid token");
    //         return {};
    //     }

    //     auto modBytes = DownloadMod(token);
    //     if (modBytes.empty()) {
    //         WinMMLog(L"Failed to download mod");
    //         return {};
    //     }
    // }
    
    // Load DLL bytes into memory using MemoryModule
    WinMMLog(L"Loading DLL into memory...");
    HMEMORYMODULE hMod = MemoryLoadLibrary(modBytes.data(), modBytes.size());
    if (!hMod) {
        DWORD lastError = GetLastError();
        WinMMLog(L"Failed to load module. Error code: " + std::to_wstring(lastError));
        
        if (lastError == ERROR_MOD_NOT_FOUND) {
            WinMMLog(L"ERROR_MOD_NOT_FOUND: Required dependency DLL not found");
        }
        else if (lastError == ERROR_PROC_NOT_FOUND) {
            WinMMLog(L"ERROR_PROC_NOT_FOUND: Required function not found in dependency");
        }
        else if (lastError == ERROR_DLL_INIT_FAILED) {
            WinMMLog(L"ERROR_DLL_INIT_FAILED: DLL or dependency DllMain returned FALSE");
        }
        
        return {};
    }
    WinMMLog(L"Successfully loaded DLL into memory using MemoryModule");
    g_InjectDlls.push_back(hMod);
    return g_InjectDlls;
}

void UnloadInjectDlls(const std::vector<HMEMORYMODULE>& injectDlls) {
    for (const auto& hModule : injectDlls) {
        MemoryFreeLibrary(hModule);
        WinMMLog(L"Unloaded DLL from memory");
    }
}