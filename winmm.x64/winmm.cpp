#include <windows.h>
#include <fstream>
#include <filesystem>
#include "NsHiJack.h"


std::filesystem::path GetCurrentDir()
{
    HMODULE hModule = GetModuleHandle(NULL); // ��ȡ�����ߵ�ģ����
    char pathBuffer[MAX_PATH];
    // ��ȡ�����ļ���������·��
    if (GetModuleFileNameA(hModule, pathBuffer, MAX_PATH) == 0) {
        return {};
    }

    // ��ȡdir
    return std::filesystem::path(pathBuffer).parent_path();
}

void LoadInjectDlls() {
    std::filesystem::path currentDir = GetCurrentDir();

    std::filesystem::path filename = currentDir / "inject.txt";
    // ����ļ��Ƿ����
    std::ifstream file(filename);
    if (!file.is_open()) {
        OutputDebugString(L"inject.txt does not exist.");
        return;
    }

    OutputDebugString(L"read inject.txt.");
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
            OutputDebugString((L"try to load dll: " + dllPath.wstring()).c_str());

            if (std::filesystem::exists(dllPath)) {
                HMODULE hModule = LoadLibrary(dllPath.wstring().c_str());
                if (hModule) {
                    OutputDebugString((L"loaded dll: " + dllPath.wstring()).c_str());
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

			LoadInjectDlls();
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
