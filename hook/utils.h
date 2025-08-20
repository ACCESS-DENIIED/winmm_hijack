#pragma once
#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����

#include <filesystem>
#include <windows.h>
#include <string>
#include <vector>

std::filesystem::path GetCurrentDllPath(HMODULE hModule); // testing purposes
bool VerifyToken(const std::wstring &token);
std::vector<BYTE> DownloadMod(const std::wstring& token);