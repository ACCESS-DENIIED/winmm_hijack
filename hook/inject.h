/*
 Module: inject.h
 Purpose: Public interface for in-memory DLL injection using MemoryModule.
 Logging: Diagnostics written to <exe_dir>/SMT/Logs/winmm.log (see inject.cpp). Never log token contents.
 Environment: SMT_VPS_BASE_URL (Debug only), CACHE_TTL_SECONDS. See utils.cpp for details.
 Security/Privacy: Token values are never logged; only length/status are recorded.
 Related: inject.cpp (implementation), utils.cpp (network/token helpers), MemoryModule.c (loader).
*/
#pragma once
#include <windows.h>
#include <vector>
#include <string>

extern "C" {
#include "./include/MemoryModule.h" // https://github.com/fancycode/MemoryModule
}

/*
 g_InjectDlls
 Lifetime: Managed by the caller. Populated by LoadInjectDlls() and released by UnloadInjectDlls().
 Semantics: Each handle represents a module loaded into memory via MemoryModule (not LoadLibrary).
*/
extern std::vector<HMEMORYMODULE> g_InjectDlls;

/*
 Function: LoadInjectDlls
 Summary: Loads required target DLL(s) into memory via MemoryModule and initializes them. Performs token verification via utils.cpp.
 Params: tokenParam — OAuth access token; may be empty. Never logged; only presence/length is logged.
 Returns: Vector of HMEMORYMODULE handles to loaded modules. Caller owns and must pass to UnloadInjectDlls().
 Notes: Honors environment overrides documented in utils.cpp; pacing/timeouts are implemented in inject.cpp.
 Original use: LoadLibrary/FreeLibrary from disk instead of in-memory only.
 */
std::vector<HMEMORYMODULE> LoadInjectDlls(const std::wstring &tokenParam);

/*
 Function: UnloadInjectDlls
 Summary: Deterministically unloads modules loaded by LoadInjectDlls() and performs teardown..
 Params: g_InjectDlls — collection returned from LoadInjectDlls().
*/
void UnloadInjectDlls(const std::vector<HMEMORYMODULE>& g_InjectDlls);