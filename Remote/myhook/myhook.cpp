#include "myhook.h"
#include <tlhelp32.h>
#include<iostream>
#include<atlstr.h>

#include<string>
bool EnableDebugPrivilege();
std::string DwordToString(DWORD_PTR dwValue)
{

	char szHex[19] = { 0 };
	char chrTmp[] = "0123456789ABCDEF";
	szHex[0] = '0';
	szHex[1] = 'x';
	for (int i = 0; i < 16; i++)
		szHex[2 + i] = *(chrTmp + (((dwValue) >> (60 - i * 4)) & 0xF));

	return std::string(szHex);
}

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
BOOL walkImportLists(LPVOID lpBaseAddress, CHAR *apiName, int choice)
{
	EnableDebugPrivilege();//����ΪdebugȨ��
	PIMAGE_DOS_HEADER pDosHeader;//Dosͷ
	PIMAGE_NT_HEADERS pNtHeader;//NTͷ
	IMAGE_OPTIONAL_HEADER optionalHeader;//��ѡͷ
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD dwImpotStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;//�����ṹ

	pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBaseAddress + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	optionalHeader = pNtHeader->OptionalHeader;
	if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) //�ж�PE�ṹ
		return FALSE;

	importDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; 
	dwImpotStartRVA = importDirectory.VirtualAddress;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBaseAddress + importDirectory.VirtualAddress);//�õ�������VA
	if (pImportDescriptor == NULL)
		return FALSE;
	DWORD dwIndex = -1;
	while (pImportDescriptor[++dwIndex].Characteristics != 0) //����ÿ��������dllģ�飬���һ��������Ϊȫ0
	{
		PIMAGE_THUNK_DATA pINT;
		PIMAGE_THUNK_DATA pIAT;
		PIMAGE_IMPORT_BY_NAME pNameData;
		DWORD nFunctions = 0;
		DWORD nOrdinalFunctions = 0;

		char *dllName = (char *)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].Name);
		pINT = (PIMAGE_THUNK_DATA)(pImportDescriptor[dwIndex].OriginalFirstThunk);
		pIAT = (PIMAGE_THUNK_DATA)(pImportDescriptor[dwIndex].FirstThunk);
		if (pINT == NULL)
			return FALSE;
		if (pIAT == NULL)
			return FALSE;
		pINT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].OriginalFirstThunk);
		pIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].FirstThunk);
		if (pINT == NULL)
			return FALSE;
		if (pIAT == NULL)
			return FALSE;
		while (pINT->u1.AddressOfData != 0)//ÿ��������API�������һ��������ȫ0
		{
			if (!(pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				pNameData = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData);
				pNameData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + (DWORD)pNameData);
				if (strcmp(apiName, pNameData->Name) == 0)
				{
					DWORD dwOldProtect, temp;
					LPDWORD FunctionAddress = NULL;
					if (g_funcAddrOrigninal == NULL) {//����ԭ��ַ
						g_funcAddrOrigninal = (FARPROC)pIAT->u1.Function;
					}
					if (!VirtualProtect(&pIAT->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &dwOldProtect))
					{
						//MessageBox(NULL, L"�޸�ʧ��", L"VirtualProtect", 0);
						return FALSE;
					}
					if (choice == 0) {
						pIAT->u1.Function = (DWORD_PTR)MyCreateProcessW;//�޸�IAT���滻Ŀ���ַ
						//MessageBox(NULL, A2Wstring(DwordToString((DWORD_PTR)g_funcAddrOrigninal) + "���滻Ϊ" + DwordToString(pIAT->u1.Function)), L"IAT�滻�ɹ�", 0);
					}
					else {
						pIAT->u1.Function = (DWORD_PTR)g_funcAddrOrigninal;//ж�ع��ӣ���ԭĿ���ַ
						//MessageBox(NULL, A2Wstring(DwordToString((DWORD_PTR)MyCreateProcessW) + "���滻Ϊ" + DwordToString((DWORD_PTR)g_funcAddrOrigninal)), L"IAT�ָ��ɹ�", 0);
					}
					if (!VirtualProtect(&pIAT->u1.Function, sizeof(LPVOID), dwOldProtect, &temp))
					{
						//MessageBox(NULL, L"�޸�ʧ��", L"VirtualProtect", 0);
						return FALSE;
					}

				}
			}
			else
			{
				nOrdinalFunctions++;
			}
			pIAT++;
			pINT++;
			nFunctions++;
		}
	}
	return TRUE;
}


bool EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return false;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		__try {
			if (hToken) {
				CloseHandle(hToken);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {};
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		__try {
			if (hToken) {
				CloseHandle(hToken);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {};
		return false;
	}
	return true;
}