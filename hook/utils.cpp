#include "utils.h"


tstring GetCurrentDllDir(HMODULE hModule/* = NULL */)
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