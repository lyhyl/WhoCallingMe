#include "stdafx.h"

#define ProcessBasicInformation 0

typedef struct
{
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
}   PROCESS_BASIC_INFORMATION;


typedef LONG(WINAPI *PROCNTQSIP)(HANDLE, UINT, PVOID, ULONG, PULONG);

PROCNTQSIP NtQueryInformationProcess;

DWORD GetParentProcessID(DWORD dwId);

void PrintProcessName(const DWORD &ppid);

int main(int argc, char* argv[])
{
	NtQueryInformationProcess = (PROCNTQSIP)GetProcAddress(
		GetModuleHandle(TEXT("ntdll")),
		"NtQueryInformationProcess"
	);

	if (!NtQueryInformationProcess)
		return -1;

	HANDLE hMe = GetCurrentProcess();
	DWORD dwId = GetProcessId(hMe);
	CloseHandle(hMe);

	DWORD ppid = GetParentProcessID(dwId);
	wprintf(TEXT("Parent PID for %lu is %lu\n"), dwId, ppid);
	PrintProcessName(ppid);

	system("pause");
	return 0;
}

void PrintProcessName(const DWORD &ppid)
{
	HANDLE hThs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hThs, &pe)) {
		do {
			if (pe.th32ProcessID == ppid) {
				wprintf(TEXT("name: %s\n"), pe.szExeFile);
			}
		} while (Process32Next(hThs, &pe));
	}

	CloseHandle(hThs);
}

DWORD GetParentProcessID(DWORD dwId)
{
	LONG                      status;
	DWORD                     dwParentPID = (DWORD)-1;
	HANDLE                    hProcess;
	PROCESS_BASIC_INFORMATION pbi;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwId);
	if (!hProcess)
		return (DWORD)-1;

	status = NtQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		(PVOID)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL
	);

	if (!status)
		dwParentPID = pbi.InheritedFromUniqueProcessId;

	CloseHandle(hProcess);

	return dwParentPID;
}