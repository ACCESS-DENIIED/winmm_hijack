#pragma once
#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����

#include <string>
#include <filesystem>
// #include <tchar.h>
#include <windows.h>


std::filesystem::path GetCurrentDllPath(HMODULE hModule);
