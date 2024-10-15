#include "load.h"

#include "utils.h"
#include <vector>
#include <algorithm>


void LoadInjectDlls(HMODULE hModule) {
    TCHAR output[1024];

    tstring currentDir = GetCurrentDllDir(hModule);

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

    _stprintf_s(output, _countof(output), TEXT("Found %zu dlls for injection."), fileList.size());
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