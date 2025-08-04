#pragma once
#include <windows.h>
#include <vector>
#include <string>

extern "C" {
#include "./include/MemoryModule.h" // https://github.com/fancycode/MemoryModule
}

extern std::vector<HMEMORYMODULE> g_InjectDlls;
std::vector<HMEMORYMODULE> LoadInjectDlls(const std::wstring &tokenParam);
void UnloadInjectDlls(const std::vector<HMEMORYMODULE>& g_InjectDlls);