#include "inject.h"
#include <algorithm>
#include <regex>
#include "utils.h"
#include <tchar.h>
#include <shellapi.h>
#include <vector>
#include <fstream>

std::vector<HMEMORYMODULE> g_InjectDlls;

// temp  for testing
std::vector<BYTE> LoadLocalDll(const std::filesystem::path &dllPath) {
    std::vector<BYTE> modBytes;
    
    if (!std::filesystem::exists(dllPath)) {
        std::wstring errorStr = L"Local DLL not found: " + dllPath.wstring();
        OutputDebugString(errorStr.c_str());
        return modBytes;
    }

    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::wstring errorStr = L"Failed to open local DLL: " + dllPath.wstring();
        OutputDebugString(errorStr.c_str());
        return modBytes;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    modBytes.resize(static_cast<size_t>(size));

    if (!file.read(reinterpret_cast<char*>(modBytes.data()), size)) {
        std::wstring errorStr = L"Failed to read local DLL: " + dllPath.wstring();
        OutputDebugString(errorStr.c_str());
        return {};
    } 
    else {
        std::wstring successStr = L"Successfully loaded local DLL: " + dllPath.wstring();
        OutputDebugString(successStr.c_str());
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
            OutputDebugString(L"-mp argument detected"); 
        } 
        else if (arg.rfind(L"-token=", 0) == 0) {
            token = arg.substr(7);
            OutputDebugString((L"Token found: " + token).c_str());
        }    
    }
    LocalFree(argv);

    if(!mpEnabled || token.empty()) {
        OutputDebugString(L"No MP arg or token provided");
        return {};
    }

    std::vector<BYTE> modBytes;

    // Local injection for testing
    {
        OutputDebugString(L"Loading local DLL for testing");
        std::filesystem::path CurrentDllPath = GetCurrentDllPath(NULL);
        std::filesystem::path dllPath = CurrentDllPath.parent_path();

        // Load DLL with name matching the token
        std::filesystem::path localDllPath = dllPath / (token + L".dll");
        modBytes = LoadLocalDll(localDllPath);


        if (modBytes.empty()) {
            OutputDebugString(L"Failed to load local DLL");
            return {};
        }
    }

    // VPS injection
    // {
    //     OutputDebugString(L"Attempting to downlaod from VPS");
    //     if (!VerifyToken(token)) {
    //         OutputDebugString(L"Invalid token");
    //         return {};
    //     }

    //     auto modBytes = DownloadMod(token);
    //     if (modBytes.empty()) {
    //         OutputDebugString(L"Failed to download mod");
    //         return {};
    //     }
    // }
    
    // Load DLL bytes into memory using MemoryModule
    HMEMORYMODULE hMod = MemoryLoadLibrary(modBytes.data(), modBytes.size());
    if (!hMod) {
        DWORD lastError = GetLastError();
        std::wstring errorStr = L"Failed to load module. Error code: " + std::to_wstring(lastError);
        OutputDebugString(errorStr.c_str());
        return {};
    }
    OutputDebugString(L"Sucessfully loaded  DLL into memory using MemoryModule lib");
    g_InjectDlls.push_back(hMod);
    return g_InjectDlls;
 }


void UnloadInjectDlls(const std::vector<HMEMORYMODULE>& injectDlls) {
    for (const auto& hModule : injectDlls) {
        MemoryFreeLibrary(hModule);
        OutputDebugString(L"Unloaded DLL from memory");
    }
}