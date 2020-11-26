#include<iostream>
#include<windows.h>
#include<TlHelp32.h>
#include<malloc.h>  //for alloca
#include<conio.h>
#include<direct.h>
#include<vector>
#include<atlstr.h>
using namespace std;

#define InjectLib InjectLibW
#define EjectLib EjectLibW
CStringW A2Wstring(std::string strA)

{
	int UnicodeLen = ::MultiByteToWideChar(CP_ACP, 0, strA.c_str(), -1, NULL, 0);
	wchar_t *pUnicode = new wchar_t[UnicodeLen * 1]();
	::MultiByteToWideChar(CP_ACP, 0, strA.c_str(), strA.size(), pUnicode, UnicodeLen);
	CString str(pUnicode);
	delete[]pUnicode;
	return str;
}
std::string W2Astring(const CString& strUnicode)
{
	char *pElementText = NULL;
	int iTextLen;
	iTextLen = ::WideCharToMultiByte(CP_ACP, 0, strUnicode, -1, NULL, 0, NULL, NULL);
	pElementText = new char[iTextLen + 1];
	memset(pElementText, 0, (iTextLen + 1) * sizeof(char));
	::WideCharToMultiByte(CP_ACP, 0, strUnicode, strUnicode.GetLength(), pElementText, iTextLen, NULL, NULL);
	std::string str(pElementText);
	delete[]pElementText;
	return str;
}

BOOL WINAPI InjectLibW(DWORD dwProcessId, PCWSTR pszLibFile) {
	BOOL bOK = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	PWSTR pszLibFileRemote = NULL;
	__try {
		//访问目标进程
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessId);
		if (hProcess == NULL)__leave;
		int cch = 1 + lstrlenW(pszLibFile);
		int cb = cch * sizeof(wchar_t);
		//开辟空间
		pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL)__leave;
		//将模块地址写入目标进程空间
		if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, cb, NULL)) __leave;
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL)__leave;
		//开启远程线程
		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == NULL)__leave;
		//等待目标线程完成
		WaitForSingleObject(hThread, INFINITE);
		bOK = TRUE;
	}
	__finally {
		//失败则清理现场
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}
	return bOK;
}

BOOL WINAPI EjectLibW(DWORD dwProcessId, PCWSTR pszLibFile) {
	BOOL bOK = FALSE;
	HANDLE hthSnapshot = NULL;
	HANDLE hProcess = NULL, hThread = NULL;
	__try {
		hthSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hthSnapshot == INVALID_HANDLE_VALUE) __leave;
		MODULEENTRY32W me = { sizeof(me) };
		BOOL bFound = FALSE;
		BOOL bMoreMods = Module32FirstW(hthSnapshot, &me);
		for (; bMoreMods; bMoreMods = Module32NextW(hthSnapshot, &me)) {
			bFound = (_wcsicmp(me.szModule, pszLibFile) == 0) || (_wcsicmp(me.szExePath, pszLibFile) == 0);
			if (bFound) break;
		}
		if (!bFound)__leave;
		//访问目标进程
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, dwProcessId);
		if (hProcess == NULL) __leave;
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "FreeLibrary");
		if (pfnThreadRtn == NULL) __leave;
		//启动远程线程，卸载dll
		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, me.modBaseAddr, 0, NULL);
		if (hThread == NULL) __leave;
		//等待目标线程完成
		WaitForSingleObject(hThread, INFINITE);
		bOK = TRUE;
	}
	__finally {
		if (hthSnapshot != NULL)
			CloseHandle(hthSnapshot);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}
	return bOK;
}

int main(int argc, char *argv[]) {
	vector<DWORD> idlist;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	char procname[200] = { 0 };
	PROCESSENTRY32 pinfo;//用于保存进程信息的数据结构;
	pinfo.dwSize = sizeof(pinfo);
	Process32First(hSnapShot, &pinfo);//获取进程列表
	do {
		sprintf(procname, "%ws", pinfo.szExeFile);
		if (_stricmp(procname, "explorer.exe") == 0 || _stricmp(procname, "cmd.exe") == 0) {
			idlist.push_back(pinfo.th32ProcessID);
		}
		memset(procname, 0, sizeof(procname));
	} while (Process32Next(hSnapShot, &pinfo) != FALSE);
	char path[200];
	GetCurrentDirectoryA(200, path);
	strcat(path, "\\myhook.dll");
	switch (argc) {
		case 2: {
			for (auto id : idlist) {
				cout << id << " " << path << endl;
				if (InjectLib(id, A2Wstring(path))) {
					printf("%d,DLL Injection successful\n", id);
				}
				else {
					printf("%d,DLL Injection failed\n", id);
				}
			}
			break;
		}
		case 3: {
			for (auto id : idlist) {
				EjectLib(id, A2Wstring(path));
			}
			break;
		}
		default: {
			for (auto id : idlist) {
				cout << id << " " << path << endl;
				if (InjectLib(id, A2Wstring(path))) {
					printf("%d,DLL Injection successful\n", id);
				}
				else {
					printf("%d,DLL Injection failed\n", id);
				}
			}
			while (_getch() != 'q');
			for (auto id : idlist) {
				EjectLib(id, A2Wstring(path));
			}
			break;
		}
	}
}