#include "utils.h"


//using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;
//tstring GetCurrentDllDir(HMODULE hModule/* = NULL */)
//{
//    if (NULL == hModule) {
//        hModule = GetModuleHandle(NULL); // ��ȡ�����ߵ�ģ����
//    }
//    TCHAR pathBuffer[MAX_PATH] = { 0 };
//    // ��ȡ�����ļ���������·��
//    if (GetModuleFileName(hModule, pathBuffer, MAX_PATH) == 0) {
//        return {};
//    }
//
//    // �������һ����б�ܵ�λ��
//    TCHAR* lastSlash = _tcsrchr(pathBuffer, _T('\\'));
//    if (lastSlash == NULL) {
//        return _T("");
//    }
//    *lastSlash = '\0';
//
//    return tstring(pathBuffer);
//}

std::filesystem::path GetCurrentDllPath(HMODULE hModule)
{
	if (NULL == hModule) {
        hModule = GetModuleHandle(NULL); // ��ȡ�����ߵ�ģ����
    }
    TCHAR pathBuffer[MAX_PATH] = { 0 };
    // ��ȡ�����ļ���������·��
    if (GetModuleFileName(hModule, pathBuffer, MAX_PATH) == 0) {
        return {};
    }

    return std::filesystem::path(pathBuffer);
}
