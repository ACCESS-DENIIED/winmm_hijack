#pragma once
#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����

#include <string>
#include <tchar.h>
#include <windows.h>

using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;

tstring GetCurrentDllDir(HMODULE hModule);
