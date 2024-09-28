#include <windows.h>
#include <vector>
#include <tchar.h>
#include <algorithm>
#include <string>

#include "NsHiJack.h"

using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;

static tstring GetCurrentDllDir(HMODULE hModule = NULL)
{
    if (NULL == hModule) {
        hModule = GetModuleHandle(NULL); // ��ȡ�����ߵ�ģ����
    }
    TCHAR pathBuffer[MAX_PATH] = { 0 };
    // ��ȡ�����ļ���������·��
    if (GetModuleFileName(hModule, pathBuffer, MAX_PATH) == 0) {
        return {};
    }

    // �������һ����б�ܵ�λ��
    TCHAR* lastSlash = _tcsrchr(pathBuffer, _T('\\'));
    if (lastSlash == NULL) {
        return _T("");
    }
    *lastSlash = '\0';

    return tstring(pathBuffer);
}

static void LoadInjectDlls(HMODULE hModule = NULL) {
    TCHAR output[1024];

    tstring currentDir = GetCurrentDllDir();

    // ����Ŀ¼����ģʽ
    tstring searchPattern = currentDir + _T("\\winmm.*.dll");
    // ��ʼ����
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile(searchPattern.c_str(), &findData);
    // û���������ļ�
    if (hFind == INVALID_HANDLE_VALUE) {
        OutputDebugString(_T("Found nothing for injection"));
        return;
    }

    // �����������
    std::vector<tstring> fileList;
    do {
        // ��ӵ��б���
        fileList.push_back(findData.cFileName);
    } while (FindNextFile(hFind, &findData));

    // �رվ��
    FindClose(hFind);

    // ���ļ��б�����ֵ�˳������
    std::sort(fileList.begin(), fileList.end());

    _stprintf_s(output, _countof(output), TEXT("Found %I64u dlls for injection."), fileList.size());
    OutputDebugString(output);

    // LoadLibrary�������ļ��б�
    for (const auto& dllPath : fileList) {
        _stprintf_s(output, _countof(output), TEXT("Try to load dll: %s"), dllPath.c_str());
        OutputDebugString(output);

        HMODULE hModule = LoadLibrary(dllPath.c_str());
        if (hModule) {
            _stprintf_s(output, _countof(output), TEXT("Injected dll: %s"), dllPath.c_str());
            OutputDebugString(output);
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
        break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
