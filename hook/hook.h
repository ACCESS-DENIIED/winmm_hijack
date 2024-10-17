#pragma once
#include <wtypes.h>
#include "library.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  ���񣬿�����callback��ִ��hook��unhook
 * 
 * @param threadHandle �߳̾��������NULL��ʾ��ǰ�߳�
 * @param callback �����ڻص���ִ��hook��unhook
 * @return �Ƿ�ִ�гɹ�
 * 
 * @code
 * hookTransaction(NULL, [](){
 *		hook(&(PVOID&)RealCreateFileW, (PVOID)HookCreateFileW);
 * 
 * });
 * @endcode
 */
DLL_API bool hookTransaction(HANDLE threadHandle, void (*callback)(void));

// ��ס������������hookTransaction��ִ��
DLL_API long hook(PVOID* originalFunc, PVOID hookFunc);
// �����ס������������hookTransaction��ִ��
DLL_API long unhook(PVOID* originalFunc, PVOID hookFunc);

#ifdef __cplusplus
}
#endif