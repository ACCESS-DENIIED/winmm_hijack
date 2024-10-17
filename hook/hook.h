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
 * @return ִ�н��, 0: NO_ERROR
 * 
 * @code
 * hookTransaction(NULL, [](){
 *		hook(&(PVOID&)RealCreateFileW, (PVOID)HookCreateFileW);
 * 
 * });
 * @endcode
 */
long hookTransaction(HANDLE threadHandle, void (*callback)(void));

// ��ס������������hookTransaction��ִ��
long hook(PVOID* originalFunc, PVOID hookFunc);
// �����ס������������hookTransaction��ִ��
long unhook(PVOID* originalFunc, PVOID hookFunc);

#ifdef __cplusplus
}
#endif