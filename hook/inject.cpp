#include "inject.h"
#include <algorithm>
#include <regex>
#include "utils.h"
#include <tchar.h>
#include <shellapi.h>


std::vector<HMODULE> LoadInjectDlls(HMODULE hModule) {
    TCHAR output[2048];

    bool mpEnabled = false;
    {
        LPWSTR cmdLine = GetCommandLineW();
        int argc;
        LPWSTR* argv = CommandLineToArgvW(cmdLine, &argc);
        if (argv) {
            for (int i = 0; i < argc; ++i) {
                if (_wcsicmp(argv[i], L"-mp") == 0) {
                    mpEnabled = true;
                    break;
                }
            }
            LocalFree(argv);
        }
    }

    if (!mpEnabled) {
        OutputDebugString(L"-mp flag was not found.");
        return {};
    }

    std::filesystem::path dllPath = GetCurrentDllPath(hModule);
    std::filesystem::path smtDir = dllPath.parent_path() / _T("SMT") / _T("Scripts");
    std::vector<std::filesystem::path> dllList;

    std::basic_regex<TCHAR> pattern(_T(".*\\.dll$"));
    if (std::filesystem::exists(smtDir) && std::filesystem::is_directory(smtDir)) {
        for (const auto& entry : std::filesystem::directory_iterator(smtDir)) {
            if (entry.is_regular_file()){
                auto filename = entry.path().filename();
                if (std::regex_match(filename.c_str(), pattern)) {
                    dllList.push_back(entry.path());
                }
            }
        }
    } else {
        OutputDebugString(_T("SMT Folder does not exist."));
    }

    if (dllList.empty()) {
        // û���������ļ�
        OutputDebugString(_T("Found nothing for injection"));
        return {};
    }
    
    // ���ļ��б������ֵ�˳������
    std::sort(dllList.begin(), dllList.end());

    _stprintf_s(output, _countof(output), _T("Found %zu dlls for injection."), dllList.size());
    OutputDebugString(output);

    std::vector<HMODULE> dllModuleList;

    // LoadLibrary�������ļ��б�
    for (const auto& dllPath : dllList) {
        _stprintf_s(output, _countof(output), _T("Try to load dll: %s"), dllPath.c_str());
        OutputDebugString(output);

        HMODULE hModule = LoadLibrary(dllPath.c_str());
        if (hModule) {
            _stprintf_s(output, _countof(output), _T("Injected dll: %s"), dllPath.c_str());
            OutputDebugString(output);


            dllModuleList.push_back(hModule);
        }
    }
    return dllModuleList;
}

void UnloadInjectDlls(const std::vector<HMODULE>& dllModuleList)
{
    for (auto& hModule : dllModuleList) {
        FreeLibrary(hModule);
    }
}