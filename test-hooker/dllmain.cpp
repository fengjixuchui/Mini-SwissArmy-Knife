#include <ostream>
#include <iostream>
#include <xiosbase>
#include "Header.h"
#include <string>
#include <iosfwd>
#include <ws2spi.h>
#include <thread>
#include <fstream>
#include <string>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

ProtoType_CreateRemoteThread oCreateRemoteThread;
ProtoType_VGetVolumeInformationA oGetVolumeInformationA;
ProtoType_FatalExit oFatalExit;
ProtoType_ExitProcess oExitProcess;
ProtoType_TerminateProcess oTerminateProcess;
ProtoType_WriteProcessMemory oWPM;
ProtoType_GetProcAddress oGetProcAddress;
ProtoType_CreateProcess oCreateProcess;
ProtoType_GetComputerName oGetComputerName;
ProtoType_SuspendThread oSuspendThread;
ProtoType_OpenProcess oOpenProcess;
ProtoType_CreateThread oCreateThread;
ProtoType_FindWindow oFindWindow;
ProtoType_GetNTHeaders oGetNtHeaders;
ProtoType_system oSystem;
ProtoType_VirtualAllocEx oVirtualAllocEx;
ProtoType_VirtualFreeEx oVirtualFreeEx;
ProtoType_DeviceIoControl oDeviceControl;
ProtoType_CreateFileA oCreateFileA;
ProtoType_recv oRecv;
ProtoType_send oSend;

bool m_bKDMapperFunctionHooksEnabled = false;
int m_nGlobalNameIdentifier = 1;

void WriteFileFromByteArray(const std::string& m_szFilePath, char* m_Data, size_t m_Size) {
	std::ofstream file(m_szFilePath.c_str(), std::ios_base::out | std::ios_base::binary);
	file.write(m_Data, m_Size);
	file.close();
}
void PatchMemory(PVOID address, int type, int bytes) {
	DWORD d, ds; //declared for future use.
	VirtualProtect(address, bytes, PAGE_EXECUTE_READWRITE, &d); //remove write protection!
	memset(address, type, bytes); //patch the data
	VirtualProtect(address, bytes, d, &ds); //set the write protection back to its normal state
}

long __stdcall RunExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	std::stringstream stream;

	// get all information about this crash..
	int m_ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	int m_exceptionInfo_0 = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
	int m_exceptionInfo_1 = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	int m_exceptionInfo_2 = ExceptionInfo->ExceptionRecord->ExceptionInformation[2];

	// to prevent spammage of our messagebox xd
	if (m_ExceptionCode == EXCEPTION_ACCESS_VIOLATION || m_ExceptionCode == EXCEPTION_ARRAY_BOUNDS_EXCEEDED || m_ExceptionCode == EXCEPTION_BREAKPOINT ||
		m_ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT || m_ExceptionCode == EXCEPTION_FLT_DENORMAL_OPERAND || m_ExceptionCode == EXCEPTION_FLT_DIVIDE_BY_ZERO ||
		m_ExceptionCode == EXCEPTION_FLT_INEXACT_RESULT || m_ExceptionCode == EXCEPTION_FLT_INVALID_OPERATION || m_ExceptionCode == EXCEPTION_FLT_OVERFLOW ||
		m_ExceptionCode == EXCEPTION_FLT_STACK_CHECK || m_ExceptionCode == EXCEPTION_FLT_UNDERFLOW || m_ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION ||
		m_ExceptionCode == EXCEPTION_IN_PAGE_ERROR || m_ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO || m_ExceptionCode == EXCEPTION_INT_OVERFLOW ||
		m_ExceptionCode == EXCEPTION_INVALID_DISPOSITION || m_ExceptionCode == EXCEPTION_NONCONTINUABLE_EXCEPTION || m_ExceptionCode == EXCEPTION_PRIV_INSTRUCTION ||
		m_ExceptionCode == EXCEPTION_SINGLE_STEP || m_ExceptionCode == EXCEPTION_STACK_OVERFLOW || m_ExceptionCode == DBG_CONTROL_C)
	{
		// basic information about our crash.
		stream << "Process has crashed!\n\nPress CNTRL + C to copy this message to your clipboard.\n";
		stream << "EX: " << std::hex << ExceptionInfo->ExceptionRecord->ExceptionAddress << std::endl;

		switch (m_ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			stream << ("CAUSE: EXCEPTION_ACCESS_VIOLATION\n");
			if (m_exceptionInfo_0 == 0) {
				// bad read
				stream << ("Attempted to read from: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}
			else if (m_exceptionInfo_0 == 1) {
				// bad write
				stream << ("Attempted to write to: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}
			else if (m_exceptionInfo_0 == 8) {
				// user-mode data execution prevention (DEP)
				stream << ("Data Execution Prevention (DEP) at: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}
			else {
				// unknown, shouldn't happen
				stream << ("Unknown access violation at: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}
			break;

		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			stream << ("CAUSE: EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
			break;

		case EXCEPTION_BREAKPOINT:
			stream << ("CAUSE: EXCEPTION_BREAKPOINT\n");
			break;

		case EXCEPTION_DATATYPE_MISALIGNMENT:
			stream << ("CAUSE: EXCEPTION_DATATYPE_MISALIGNMENT\n");
			break;

		case EXCEPTION_FLT_DENORMAL_OPERAND:
			stream << ("CAUSE: EXCEPTION_FLT_DENORMAL_OPERAND\n");
			break;

		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			stream << ("CAUSE: EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
			break;

		case EXCEPTION_FLT_INEXACT_RESULT:
			stream << ("CAUSE: EXCEPTION_FLT_INEXACT_RESULT\n");
			break;

		case EXCEPTION_FLT_INVALID_OPERATION:
			stream << ("CAUSE: EXCEPTION_FLT_INVALID_OPERATION\n");
			break;

		case EXCEPTION_FLT_OVERFLOW:
			stream << ("CAUSE: EXCEPTION_FLT_OVERFLOW\n");
			break;

		case EXCEPTION_FLT_STACK_CHECK:
			stream << ("CAUSE: EXCEPTION_FLT_STACK_CHECK\n");
			break;

		case EXCEPTION_FLT_UNDERFLOW:
			stream << ("CAUSE: EXCEPTION_FLT_UNDERFLOW\n");
			break;

		case EXCEPTION_ILLEGAL_INSTRUCTION:
			stream << ("CAUSE: EXCEPTION_ILLEGAL_INSTRUCTION\n");
			break;

		case EXCEPTION_IN_PAGE_ERROR:
			stream << ("CAUSE: EXCEPTION_IN_PAGE_ERROR\n");
			if (m_exceptionInfo_0 == 0) {
				// bad read
				stream << ("Attempted to read from: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}
			else if (m_exceptionInfo_0 == 1) {
				// bad write
				stream << ("Attempted to write to: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}
			else if (m_exceptionInfo_0 == 8) {
				// user-mode data execution prevention (DEP)
				stream << ("Data Execution Prevention (DEP) at: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}
			else {
				// unknown, shouldn't happen
				stream << ("Unknown access violation at: ") << std::hex << m_exceptionInfo_1 << std::endl;
			}

			stream << ("NTSTATUS: ") << std::hex << m_exceptionInfo_2 << std::endl;
			break;

		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			stream << ("CAUSE: EXCEPTION_INT_DIVIDE_BY_ZERO\n");
			break;

		case EXCEPTION_INT_OVERFLOW:
			stream << ("CAUSE: EXCEPTION_INT_OVERFLOW\n");
			break;

		case EXCEPTION_INVALID_DISPOSITION:
			stream << ("CAUSE: EXCEPTION_INVALID_DISPOSITION\n");
			break;

		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			stream << ("CAUSE: EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
			break;

		case EXCEPTION_PRIV_INSTRUCTION:
			stream << ("CAUSE: EXCEPTION_PRIV_INSTRUCTION\n");
			break;

		case EXCEPTION_SINGLE_STEP:
			stream << ("CAUSE: EXCEPTION_SINGLE_STEP\n");
			break;

		case EXCEPTION_STACK_OVERFLOW:
			stream << ("CAUSE: EXCEPTION_STACK_OVERFLOW\n");
			break;

		case DBG_CONTROL_C:
			stream << ("CAUSE: DBG_CONTROL_C\n");
			break;

		default:
			stream << ("CAUSE (OTHER): ") << std::hex << m_ExceptionCode << std::endl;
		}

		while (!MessageBoxA(nullptr, stream.str().c_str(), nullptr, MB_ICONERROR)) {
			std::this_thread::sleep_for(std::chrono::milliseconds(25));
		}
	}

	// keep searching for some exception?
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY CreateProcessHooked(
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
	std::wstring s(lpApplicationName);
	std::string temp(s.length(), ' ');
	std::copy(s.begin(), s.end(), temp.begin());

	std::wstring s2(lpApplicationName);
	std::string temp2(s.length(), ' ');
	std::copy(s2.begin(), s2.end(), temp2.begin());

	auto gay = temp + " | " + temp2;

	MessageBoxA(NULL, "[+] CreateProcessHooked", gay.c_str(), 0);

	return oCreateProcess(lpApplicationName, lpCommandLine,
		lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory,
		lpStartupInfo, lpProcessInformation);
}

FARPROC APIENTRY GetProcAddressHooked(
	HMODULE hModule,
	LPCSTR  lpProcName
) 
{
	MessageBoxA(NULL, "[+] GetProcAddressHooked", lpProcName, 0);

	return oGetProcAddress(hModule, lpProcName);
}

VOID APIENTRY FatalExitHooked(int uExitCode)
{
	std::cout << "\n[+] Blocked kernel32.dll!FatalExit call.";
	return;
}

void APIENTRY ExitProcessHooked(UINT uExitCode)
{
	std::cout << "\n[+] Blocked kernel32.dll!ExitProcess call.";
	return;
}

BOOL APIENTRY TerminateProcessHooked(HANDLE hProcess,UINT   uExitCode) 
{
	std::cout << "\n[+] Blocked kernel32.dll!TerminateProcess call.";
	return FALSE;
}

BOOL APIENTRY WriteProcessMemoryHooked(HANDLE hProcess, LPVOID lpBaseAddress, 
	LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
	auto pid = GetProcessId(hProcess);
	HANDLE hFile;
	DWORD BytesWritten;

	std::string name = "wpmDump_" + std::to_string(m_nGlobalNameIdentifier) + "_pid[" + std::to_string(pid) + "].bin";
	++m_nGlobalNameIdentifier;

	hFile = CreateFileW((LPCWSTR)name.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "meme", "CreateFile: Failed to write buffer to file", MB_SYSTEMMODAL | MB_ICONERROR);
		goto CALLFUNC;
	}

	if (!WriteFile(hFile, lpBuffer, nSize, &BytesWritten, NULL))
	{
		MessageBoxA(NULL, "meme", "WriteFile: Failed to write buffer to file!", MB_SYSTEMMODAL | MB_ICONERROR);
		goto CALLFUNC;
	}

	CALLFUNC:

	return oWPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL APIENTRY GetComputerNameHooked(LPSTR lpBuffer, LPDWORD nSize)
{
	std::string str = "Paster1337";
	lpBuffer = const_cast<char*>(str.c_str());
	return TRUE;
}

HANDLE WINAPI CreateRemoteThreadHooked(
	HANDLE hProcess,
	 LPSECURITY_ATTRIBUTES lpThreadAttributes,
	 SIZE_T dwStackSize,
	 LPTHREAD_START_ROUTINE lpStartAddress,
	 LPVOID lpParameter,
	 DWORD dwCreationFlags,
	 LPDWORD lpThreadId)
{
	MessageBoxA(NULL, "meme", "CreateRemoteThreadHooked!", MB_SYSTEMMODAL | MB_ICONERROR);
	return oCreateRemoteThread(
		hProcess,
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress, 
		lpParameter, 
		dwCreationFlags,
		lpThreadId);
}

DWORD APIENTRY SuspendThreadHooked(HANDLE hThread)
{
	MessageBoxA(NULL, "meme", "SuspendThreadHooked!", MB_SYSTEMMODAL | MB_ICONERROR);
	return oSuspendThread(hThread);
}

HANDLE APIENTRY OpenProcessHooked( DWORD dwDesiredAccess, BOOL  bInheritHandle,DWORD dwProcessId)
{
	std::cout << "\n[+] Blocked user32.dll!OpenProcessHooked call. ";
	return (HANDLE)1;
}

HWND APIENTRY FindWindowAHooked(LPCSTR lpClassName,LPCSTR lpWindowName) 
{
	std::cout << "\n[+] Blocked user32.dll!FindWindowA call. ";
	return NULL;
}

HANDLE APIENTRY CreateThreadHooked(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
)
{
	std::cout << "\n[+] Blocked kernel32.dll!CreateThread call.";
	return INVALID_HANDLE_VALUE;
}

PIMAGE_NT_HEADERS64 APIENTRY KDMapper_GetNtHeaders(void* image_base) 
{
	std::string name = "ntDump_" + std::to_string(m_nGlobalNameIdentifier) + ".bin";
	++m_nGlobalNameIdentifier;

	std::cout << "\n[+]KDMapper_GetNtHeaders called. Writing driver to " << name;
	WriteFileFromByteArray(name, (char*)image_base, sizeof image_base);

	return oGetNtHeaders(image_base);
}

int __cdecl SystemHooked(const char* cmd)
{
	if (strstr(cmd, "pause")) {
		printf("[+] system(pause) was called, and blocked!\n");
		return 1;
	}
		
	return oSystem(cmd);
}

LPVOID WINAPI VirtualAllocExHooked(
	 HANDLE hProcess,
	 LPVOID lpAddress,
	 SIZE_T dwSize,
	 DWORD flAllocationType,
	 DWORD flProtect
) 
{
	MessageBoxA(NULL, "meme", "VirtualAllocExHooked!", MB_SYSTEMMODAL | MB_ICONERROR);

	return oVirtualAllocEx(
		hProcess,
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect);
}

BOOL WINAPI VirtualFreeExHooked(HANDLE hProcess,LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) 
{

	MessageBoxA(NULL, "meme", "VirtualFreeExHooked!", MB_SYSTEMMODAL | MB_ICONERROR);
	return oVirtualFreeEx(
		hProcess,
		lpAddress,
		dwSize,
		dwFreeType);
}

BOOL WINAPI GetVolumeInformationAHooked(
	LPCSTR lpRootPathName,
	LPSTR lpVolumeNameBuffer,
	DWORD nVolumeNameSize,
	LPDWORD lpVolumeSerialNumber,
	LPDWORD lpMaximumComponentLength,
	LPDWORD lpFileSystemFlags,
	LPSTR lpFileSystemNameBuffer,
	DWORD nFileSystemNameSize
) 
{
	return TRUE;
}

bool WINAPI DeviceIoControlHooked(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
	LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) 
{
	printf_s("\nDeviceIoControlHooked: (0x%x, 0x%x)", hDevice, dwIoControlCode);
	return oDeviceControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}

HANDLE WINAPI CreateFileAHooked(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
	printf_s("\nCreateFileAHooked with lpFileName as %s", lpFileName);
	return oCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

int WSAAPI sendHooked(SOCKET s, const char* buf, int len, int flags) 
{
	std::string m_szName = "send_dump" + std::to_string(m_nGlobalNameIdentifier) + ".bin";
	++m_nGlobalNameIdentifier;

	WriteFileFromByteArray(m_szName, (char*)buf, len);

	return oSend(s, buf, len, flags);
}

int recvHooked(SOCKET s, char* buf, int len, int flags)
{
	std::string m_szName = "recv_dump" + std::to_string(m_nGlobalNameIdentifier) + ".bin";
	++m_nGlobalNameIdentifier;

	WriteFileFromByteArray(m_szName, (char*)buf, len);

	return oRecv(s, buf, len, flags);
}

unsigned long __stdcall init_Thread(void* reserved)
{
	// setup exception handler to identify force crash methods we may not detect.
	AddVectoredExceptionHandler(1ul, RunExceptionHandler);

	AllocConsole();
	freopen_s(reinterpret_cast<FILE**>(stdin), ("CONIN$"), ("r"), stdin);
	freopen_s(reinterpret_cast<FILE**>(stdout), ("CONOUT$"), ("w"), stdout);

	const uintptr_t m_ProcessBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
	printf_s("m_ProcessBase: 0x%X\n", m_ProcessBase);

	if (MH_Initialize() != MH_STATUS::MH_OK) {
		printf("[-] MH_Initialize() != MH_OK\n");
	}

	// Networking shit.
	{
		MH_CreateHook(&recv, recvHooked, (void**)&oRecv);
		MH_CreateHook(&send, sendHooked, (void**)&oSend);
	}

	// Maybe some IOCTL calls for HWID, etc in their loader?
	{
		MH_CreateHook(&DeviceIoControl, DeviceIoControlHooked, (void**)&oDeviceControl);
		MH_CreateHook(&CreateFileA, CreateFileAHooked, (void**)&oCreateFileA);
	}

	// Anti-HWID ban
	{
		MH_CreateHook(&GetVolumeInformationA, GetVolumeInformationAHooked, (void**)&oGetVolumeInformationA);
		MH_CreateHook(&GetComputerNameA, GetComputerNameHooked, (void**)&oGetComputerName);
	}

	// WPM hook to grab dll images, etc.
	{
		MH_CreateHook(&WriteProcessMemory, WriteProcessMemoryHooked, (void**)&oWPM);
	}

	// Anti-Process Exit
	{
		MH_CreateHook(&system, SystemHooked, (void**)&oSystem);
		MH_CreateHook(&TerminateProcess, TerminateProcessHooked, (void**)&oTerminateProcess);
		MH_CreateHook(&ExitProcess, ExitProcessHooked, (void**)&oExitProcess);
		MH_CreateHook(&FatalExit, FatalExitHooked, (void**)&oFatalExit);
	}

	// Anti-Process Anti-Debug
	{
		MH_CreateHook(&FindWindowA, FindWindowAHooked, (void**)&oFindWindow);
	}

	// Finding end/start of mapping of DLL's.
	{
		MH_CreateHook(&SuspendThread, SuspendThreadHooked, (void**)&oSuspendThread);
		MH_CreateHook(&CreateRemoteThread, CreateRemoteThreadHooked, (void**)&oCreateRemoteThread);

		MH_CreateHook(&VirtualAllocEx, VirtualAllocExHooked, (void**)&oVirtualAllocEx);
		MH_CreateHook(&VirtualFreeEx, VirtualFreeExHooked, (void**)&oVirtualFreeEx);
	}

	// Random memes tbh. Nothing more
	{
	//	MH_CreateHook(&OpenProcess, OpenProcessHooked, (void**)&oOpenProcess);
	//	MH_CreateHook(&CreateThread, CreateThreadHooked, (void**)&oCreateThread);
		MH_CreateHook(&CreateProcessW, CreateProcessHooked, (void**)&oCreateProcess);
	}

	// To find kernel communication functions p2c's are using :D
	{
		MH_CreateHook(&GetProcAddress, GetProcAddressHooked, (void**)&oGetProcAddress);
	}

	// KDMapper hooks to grab driver images.
	if (m_bKDMapperFunctionHooksEnabled) 
	{
		static uintptr_t KDMAPPER_GetNTHeaders_fn = FindIDAStyleSignature(
			"48 89 4C 24 ? 48 83 EC 18 48 8B 44 24 ? 48 89 04 24 48 8B 04 24 0F B7 00 3D ? ? ? ?"
		);

		if (KDMAPPER_GetNTHeaders_fn)
			MH_CreateHook(&KDMAPPER_GetNTHeaders_fn, KDMapper_GetNtHeaders, (void**)&oGetNtHeaders);
	}

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_STATUS::MH_OK) {
		printf("MH_EnableHook(MH_ALL_HOOKS) != MH_OK\n");
	}

	while (true)
		Sleep(15);

	return 0ul;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	  switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, static_cast<LPTHREAD_START_ROUTINE>(init_Thread), hModule, 0, 0);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

