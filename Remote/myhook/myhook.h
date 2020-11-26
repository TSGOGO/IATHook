#ifndef _HookImportFunction_H_
#define _HookImportFunction_H_
#define __DLL_EXPORTS__
#ifdef __DLL_EXPORTS__
#define DLLAPI  __declspec(dllexport)
#else
#define DLLAPI __declspec(dllimport)
#endif
#include <windows.h>
#include<atlstr.h>
#include<string>
#endif
FARPROC g_funcAddrOrigninal = NULL; // CreateProcessW�����ĵ�ַ
std::string DwordToString(DWORD_PTR dwValue);
CStringW A2Wstring(std::string strA);
typedef BOOL(WINAPI *CreateProcessWFunc)( //CreateProcessWģ��
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

BOOL WINAPI MyCreateProcessW(//�Զ���CreateProcessW����
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	CreateProcessWFunc func = (CreateProcessWFunc)g_funcAddrOrigninal;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_NORMAL;//���ص����ܳ��ֵ�cmd����� SW_HIDE
	ZeroMemory(&pi, sizeof(pi));
	if (!_wcsicmp(lpCommandLine, L"Remote.exe  1 123456789"))
		return func(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	return func(NULL, (LPWSTR)(LPCTSTR)A2Wstring("notepad.exe"), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}
BOOL walkImportLists(LPVOID lpBaseAddress, CHAR *apiName, int choice);


void InstallHooks(void);
void UninstallHooks(void);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH://����
		InstallHooks();
		break;
	case DLL_PROCESS_DETACH://ж��
		UninstallHooks();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

//��װ����
void InstallHooks()
{
	LPVOID lpBaseAddress = NULL;
	CHAR apiName[] = "CreateProcessW";
	if (GetModuleHandle(_T("kernelbase.dll"))) {
		lpBaseAddress = (LPVOID)GetModuleHandle(_T("kernelbase.dll"));//kernel32.dll�е���kernelbase.dll��CreateProcessW
		walkImportLists(lpBaseAddress, apiName, 0);
	}
	if (GetModuleHandle(_T("kernel32.dll"))) {
		lpBaseAddress = (LPVOID)GetModuleHandle(_T("kernel32.dll"));//kernel32�е�����CreateProcessW
		walkImportLists(lpBaseAddress, apiName, 0);
	}
	if (GetModuleHandle(_T("shell32.dll"))) {
		lpBaseAddress = (LPVOID)GetModuleHandle(_T("shell32.dll"));//shell32�е���kernel32.dll��CreateProcessW
		walkImportLists(lpBaseAddress, apiName, 0);
	}
	lpBaseAddress = (LPVOID)GetModuleHandle(0);//�������е���kernel32.dll��CreateProcessW
	walkImportLists(lpBaseAddress, apiName, 0);

}

//ж�ع���
void UninstallHooks()
{
	LPVOID lpBaseAddress = NULL;
	CHAR apiName[] = "CreateProcessW";
	if (g_funcAddrOrigninal) {
		if (GetModuleHandle(_T("kernelbase.dll"))) {
			lpBaseAddress = (LPVOID)GetModuleHandle(_T("kernelbase.dll"));//kernel32.dll�е���kernelbase.dll��CreateProcessW
			walkImportLists(lpBaseAddress, apiName, 1);
		}
		if (GetModuleHandle(_T("kernel32.dll"))) {
			lpBaseAddress = (LPVOID)GetModuleHandle(_T("kernel32.dll"));//kernel32�е�����CreateProcessW
			walkImportLists(lpBaseAddress, apiName, 1);
		}
		if (GetModuleHandle(_T("shell32.dll"))) {
			lpBaseAddress = (LPVOID)GetModuleHandle(_T("shell32.dll"));//shell�е���kernel32.dll��CreateProcessW
			walkImportLists(lpBaseAddress, apiName, 1);
		}
		lpBaseAddress = (LPVOID)GetModuleHandle(0);//�������е���kernel32.dll��CreateProcessW
		walkImportLists(lpBaseAddress, apiName, 1);
	}
}



