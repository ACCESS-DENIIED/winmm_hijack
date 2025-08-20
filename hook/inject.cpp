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
#include <cwctype>

/*
 Module: winmm_hijack/hook/inject.cpp
 Purpose:
   - Entry point for downloading and loading in-memory DLL(s) using MemoryModule.
   - Parses command-line for token and optional pacing, verifies with VPS, downloads mod bytes,
     validates PE headers, and loads modules into the current process address space.
 Logging:
   - All diagnostics are written to <exe_dir>/SMT/Logs/winmm.log via WinMMLog.
   - Never logs token contents (only length/status for privacy).
 Related:
   - Network and utility helpers live in utils.cpp.
   - In-memory PE loader implementation in MemoryModule.c, which uses MM_LogW/MM_LogA to log here.
 Environment:
   - See utils.cpp for `SMT_VPS_BASE_URL` (Debug) and `CACHE_TTL_SECONDS`.
*/

std::vector<HMEMORYMODULE> g_InjectDlls;
static std::wofstream g_logStream;
static std::wstring GetLogFilePath()
{
    auto exePath = GetCurrentDllPath(NULL);
    auto dir = exePath.parent_path() / L"SMT" / L"Logs";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return (dir / L"winmm.log").wstring();
}

void WinMMLog(const std::wstring& message) {
    if (!g_logStream.is_open())
    {
        // Append to preserve prior sessions for debug
        g_logStream.open(GetLogFilePath(), std::ios::out | std::ios::app);
    }
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[64];
    swprintf_s(ts, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    // Timestamped prefix
    g_logStream << L"[" << ts << L"] [WINMM] " << message << L"\n";
    g_logStream.flush();
}

// Expose a simple wide-string logger for C code (MemoryModule.c)
extern "C" void MM_LogW(const wchar_t* msg) {
    if (msg) {
        WinMMLog(std::wstring(msg));
    } else {
        WinMMLog(L"(null)");
    }
}

// Expose a simple ANSI-string logger for C code (MemoryModule.c)
extern "C" void MM_LogA(const char* msg) {
    if (!msg) { WinMMLog(L"(null)"); return; }
    // Convert from ANSI (ACP) to wide
    int wlen = MultiByteToWideChar(CP_ACP, 0, msg, -1, nullptr, 0);
    if (wlen <= 0) { WinMMLog(L"(conv error)"); return; }
    std::wstring wstr(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_ACP, 0, msg, -1, wstr.data(), wlen);
    // Remove trailing null placed by MultiByteToWideChar in std::wstring
    if (!wstr.empty() && wstr.back() == L'\0') wstr.pop_back();
    WinMMLog(wstr);
}

// Entry point for downloading and loading in-memory DLL(s) using MemoryModule.
std::vector<HMEMORYMODULE> LoadInjectDlls(const std::wstring &tokenParam) {
    int argc;
    LPWSTR cmdLine = GetCommandLineW();
    LPWSTR *argv = CommandLineToArgvW(cmdLine, &argc);

    bool mpEnabled = false;
    std::wstring token;
    // Optional pacing controls
    std::vector<std::wstring> waitModules; // if empty, defaults to dxgi.dll or d3d12.dll
    DWORD waitTimeoutMs = 15000; // 15s. FAR too long but it works for now.
    // TODO: Use a better method. Maybe an event to signal when the modules are loaded in prod?

    // Parse CL arguments
    for (int i = 0; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-mp") {
            mpEnabled = true;
            WinMMLog(L"-mp argument detected");
        }
        else if (arg._Starts_with(L"-token=")) {
            token = arg.substr(7);
            // Only log token length. Not content.
            WinMMLog(L"Token received (length=" + std::to_wstring(token.size()) + L")");
        }
        else if (arg == L"-token" && (i + 1) < argc) {
            // Support split form: -token "<value>". (Just in case the token contains spaces. Probably not needed.)
            token = argv[++i];
            WinMMLog(L"Token received (length=" + std::to_wstring(token.size()) + L")");
        }
        // Optional pacing args
        else if (arg._Starts_with(L"-waitmodule=")) {
            std::wstring list = arg.substr(std::wcslen(L"-waitmodule="));
            // split by comma/semicolon
            size_t start = 0;
            while (start <= list.size()) {
                size_t pos = list.find_first_of(L",;", start);
                std::wstring item = list.substr(start, (pos == std::wstring::npos ? list.size() : pos) - start);
                // trim spaces
                item.erase(item.begin(), std::find_if(item.begin(), item.end(), [](wchar_t c){ return !iswspace(c); }));
                while (!item.empty() && iswspace(item.back())) item.pop_back();
                if (!item.empty()) {
                    // normalize to lower
                    std::transform(item.begin(), item.end(), item.begin(), ::towlower);
                    waitModules.push_back(item);
                }
                if (pos == std::wstring::npos) break;
                start = pos + 1;
            }
        }
        else if (arg == L"-waitmodule" && (i + 1) < argc) {
            std::wstring list = argv[++i];
            size_t start = 0;
            while (start <= list.size()) {
                size_t pos = list.find_first_of(L",;", start);
                std::wstring item = list.substr(start, (pos == std::wstring::npos ? list.size() : pos) - start);
                item.erase(item.begin(), std::find_if(item.begin(), item.end(), [](wchar_t c){ return !iswspace(c); }));
                while (!item.empty() && iswspace(item.back())) item.pop_back();
                if (!item.empty()) {
                    std::transform(item.begin(), item.end(), item.begin(), ::towlower);
                    waitModules.push_back(item);
                }
                if (pos == std::wstring::npos) break;
                start = pos + 1;
            }
        }
        else if (arg._Starts_with(L"-waittimeoutms=")) {
            std::wstring v = arg.substr(std::wcslen(L"-waittimeoutms="));
            waitTimeoutMs = std::max<DWORD>(1000, (DWORD)_wtoi(v.c_str()));
        }
        else if (arg == L"-waittimeoutms" && (i + 1) < argc) {
            waitTimeoutMs = std::max<DWORD>(1000, (DWORD)_wtoi(argv[++i]));
        }
    }
    LocalFree(argv);

    if(!mpEnabled || token.empty()) {
        WinMMLog(L"No MP arg or token provided");
        return {};
    }

    std::vector<BYTE> modBytes;

    // Verify token via VPS, then download mod bytes from VPS.
    // Loading via MemoryModule to prevent writing dll to disk.
    {
        WinMMLog(L"Verifying token with VPS");
        if (!VerifyToken(token)) {
            WinMMLog(L"Token verification failed");
            return {};
        }

        WinMMLog(L"Downloading mod from VPS");
        modBytes = DownloadMod(token);
        if (modBytes.empty()) {
            WinMMLog(L"Failed to download mod");
            return {};
        }
        else {
            WinMMLog(L"Downloaded mod bytes: " + std::to_wstring(modBytes.size()));
        }
    }
    
    // Inspect PE headers to validate and log architecture before attempting to load
    if (modBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        WinMMLog(L"Mod bytes too small to be a PE file");
        return {};
    }
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(modBytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { // 'MZ'
        WinMMLog(L"Mod is not a valid PE: missing MZ header");
        return {};
    }
    if (modBytes.size() < static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) {
        WinMMLog(L"Mod PE header truncated");
        return {};
    }
    const BYTE* ntBase = modBytes.data() + dos->e_lfanew;
    const DWORD* sig = reinterpret_cast<const DWORD*>(ntBase);
    if (*sig != IMAGE_NT_SIGNATURE) { // 'PE\0\0'
        WinMMLog(L"Mod is not a valid PE: missing NT signature");
        return {};
    }
    const IMAGE_FILE_HEADER* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
    WORD machine = fh->Machine;
    std::wstring machineStr = L"unknown";
    if (machine == IMAGE_FILE_MACHINE_AMD64) machineStr = L"AMD64 (x64)";
    else if (machine == IMAGE_FILE_MACHINE_I386) machineStr = L"I386 (x86)";
    else if (machine == IMAGE_FILE_MACHINE_ARM64) machineStr = L"ARM64";
    WinMMLog(L"Mod PE Machine: " + machineStr + L" (0x" + std::to_wstring(machine) + L")");
#ifdef _WIN64
    WinMMLog(L"Host process arch: x64");
#else
    WinMMLog(L"Host process arch: x86");
#endif

    // Wait until problematic modules are loaded
    {
        if (waitModules.empty()) {
            // Seems to just be these?
            waitModules.push_back(L"dxgi.dll");
            waitModules.push_back(L"d3d12.dll");
        }
        
        // build printable list
        std::wstring list;
        for (size_t i = 0; i < waitModules.size(); ++i) {
            if (i) list += L",";
            list += waitModules[i];
        }
        WinMMLog(L"Waiting for any of modules to load: " + list + L" (timeout=" + std::to_wstring(waitTimeoutMs) + L"ms)");
        ULONGLONG startTick = GetTickCount64();
        bool ready = false;
        while (GetTickCount64() - startTick < waitTimeoutMs) {
            for (const auto& m : waitModules) {
                if (GetModuleHandleW(m.c_str()) != nullptr) { ready = true; break; }
            }
            if (ready) break;
            Sleep(50);
        }
        if (ready) {
            WinMMLog(L"Module readiness detected; proceeding to MemoryLoadLibrary");
        } else {
            WinMMLog(L"Timeout waiting for modules; proceeding to MemoryLoadLibrary anyway");
        }
    }

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

// Unload smt module via MemoryFreeLibrary (MemoryModule) when the host process exits.
void UnloadInjectDlls(const std::vector<HMEMORYMODULE>& injectDlls) {
    for (const auto& hModule : injectDlls) {
        MemoryFreeLibrary(hModule);
        WinMMLog(L"Unloaded DLL from memory");
    }
}