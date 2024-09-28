#include <windows.h>
#include <fstream>
#include <filesystem>
#include <tchar.h>
#include "NsHiJack.h"


std::filesystem::path GetCurrentDllDir(HMODULE hModule = NULL)
{
    if (NULL == hModule) {
        hModule = GetModuleHandle(NULL); // ��ȡ�����ߵ�ģ����
    }
    TCHAR pathBuffer[MAX_PATH] = { 0 };
    // ��ȡ�����ļ���������·��
    if (GetModuleFileName(hModule, pathBuffer, MAX_PATH) == 0) {
        return {};
    }

    // ��ȡdir
    return std::filesystem::path(pathBuffer).parent_path();
}

void LoadInjectDlls(HMODULE hModule = NULL) {
    std::filesystem::path currentDir = GetCurrentDllDir();

    std::filesystem::path filename = currentDir / "inject.txt";
    // ����ļ��Ƿ����
    std::ifstream file(filename);
    if (!file.is_open()) {
        OutputDebugString(L"inject.txt does not exist, skip inject.");
        return;
    }

    OutputDebugString(TEXT("read inject.txt."));
    TCHAR output[1024];
    std::string line;
    // ���ж�ȡ�ļ�
    while (std::getline(file, line)) {
        // ȥ���հ��ַ�
        line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
        // ����ļ����Ƿ���.dll��β
        if (!line.empty() && line.size() > 4 && line.substr(line.size() - 4) == ".dll") {
            std::filesystem::path dllPath(line);
            // ������Ǿ���·�������ڵ�ǰ·���²���
            if (!dllPath.is_absolute()) {
                dllPath = currentDir / dllPath;
            }
            _stprintf_s(output, _countof(output), TEXT("try to load dll: %s"), dllPath.c_str());
            OutputDebugString(output);

            if (std::filesystem::exists(dllPath)) {
                HMODULE hModule = LoadLibrary(dllPath.c_str());
                if (hModule) {
                    _stprintf_s(output, _countof(output), TEXT("injected dll: %s"), dllPath.c_str());
                    OutputDebugString(output);
                }
            }
        }
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                      )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			if (!NsInitDll())
				return false;

			LoadInjectDlls(hModule);
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
