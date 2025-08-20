#include <windows.h>
#include "NsHiJack.h"
#include "../hook/inject.h"

// Defer heavy work (network, MemoryModule loads) outside DllMain to avoid locking issues
static DWORD WINAPI InjectWorkerThread(LPVOID) {
	g_InjectDlls = LoadInjectDlls(L"");
	return 0;
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
			// Minimize callbacks we receive and return quickly from DllMain
			DisableThreadLibraryCalls(hModule);

			if (!NsInitDll())
				return FALSE;

			// Run injection asynchronously to avoid doing WinHTTP and module loads under loader lock
			HANDLE hThread = CreateThread(nullptr, 0, InjectWorkerThread, nullptr, 0, nullptr);
			if (hThread) CloseHandle(hThread);
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		{
			UnloadInjectDlls(g_InjectDlls);
		}
		break;
	}
	return TRUE;
}
