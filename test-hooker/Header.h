#pragma once
#include <iostream>
#include <WinSock2.h>
#include "pch.h"
#include <Windows.h>
#include <Psapi.h>
#include "minhook.h"
#include <vector>
#include <cstdint>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

#define VCAST reinterpret_cast<void**>
#define REGISTERS uintptr_t ecx, uintptr_t edx
#define REGISTER_PARAMS ecx, edx


typedef BOOL(APIENTRY* ProtoType_WriteProcessMemory)
(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten
	);

typedef FARPROC(APIENTRY* ProtoType_GetProcAddress)
(
	HMODULE hModule,
	LPCSTR  lpProcName
	);

typedef BOOL(APIENTRY* ProtoType_CreateProcess)
(
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

typedef BOOL(APIENTRY* ProtoType_GetComputerName)
(
	LPSTR   lpBuffer,
	LPDWORD nSize
	);

typedef HANDLE(APIENTRY* ProtoType_OpenProcess)
(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);

typedef BOOL(APIENTRY* ProtoType_TerminateProcess)
(
	HANDLE hProcess,
	UINT   uExitCode
	);

typedef void(APIENTRY* ProtoType_ExitProcess)
(
	UINT   uExitCode
	);

typedef VOID(APIENTRY* ProtoType_FatalExit)
(
	int   uExitCode
	);

typedef DWORD(APIENTRY* ProtoType_SuspendThread)
(
	HANDLE hThread
	);

typedef HANDLE(APIENTRY* ProtoType_CreateThread)
(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);

typedef HWND(APIENTRY* ProtoType_FindWindow)
(
	LPCSTR lpClassName,
	LPCSTR lpWindowName
	);

typedef PIMAGE_NT_HEADERS64(APIENTRY* ProtoType_GetNTHeaders)
(
	void* image_base
	);
typedef HANDLE(WINAPI* ProtoType_CreateRemoteThread)
(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	);

typedef BOOL(WINAPI* ProtoType_VGetVolumeInformationA)
(
	LPCSTR lpRootPathName,
	LPSTR lpVolumeNameBuffer,
	DWORD nVolumeNameSize,
	LPDWORD lpVolumeSerialNumber,
	LPDWORD lpMaximumComponentLength,
	LPDWORD lpFileSystemFlags,
	LPSTR lpFileSystemNameBuffer,
	DWORD nFileSystemNameSize
	);

typedef BOOL(WINAPI* ProtoType_VirtualFreeEx)
(
	_In_ HANDLE hProcess,
	LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD dwFreeType
	);

typedef LPVOID(WINAPI* ProtoType_VirtualAllocEx)
(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);

typedef HANDLE(WINAPI* ProtoType_CreateFileA)
(
	LPCSTR lpFileName, 
	DWORD dwDesiredAccess, 
	DWORD dwShareMode, 
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, 
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);

typedef bool(WINAPI* ProtoType_DeviceIoControl)
(
	HANDLE hDevice,
	DWORD dwIoControlCode,
	LPVOID lpInBuffer,
	DWORD nInBufferSize,
	LPVOID lpOutBuffer,
	DWORD nOutBufferSize,
	LPDWORD lpBytesReturned,
	LPOVERLAPPED lpOverlapped
	);

typedef int(__cdecl* ProtoType_recv)
(
	SOCKET s,
	char* buf,
	int    len,
	int    flags
	);
typedef int(WSAAPI* ProtoType_send)
(
	SOCKET     s,
	const char* buf,
	int        len,
	int        flags
	);

typedef int(__cdecl* ProtoType_system)
(
	const char* cmd
	);
inline uintptr_t FindIDAStyleSignature(const char* pattern)
{
	uintptr_t moduleAdress = 0;
	moduleAdress = (uintptr_t)GetModuleHandleA(NULL);

	static auto patternToByte = [](const char* pattern)
	{
		auto       bytes = std::vector<int>{};
		const auto start = const_cast<char*>(pattern);
		const auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else { bytes.push_back(strtoul(current, &current, 16)); }
		}
		return bytes;
	};

	const auto dosHeader = (PIMAGE_DOS_HEADER)moduleAdress;
	const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)moduleAdress + dosHeader->e_lfanew);

	const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto       patternBytes = patternToByte(pattern);
	const auto scanBytes = reinterpret_cast<std::uint8_t*>(moduleAdress);

	const auto s = patternBytes.size();
	const auto d = patternBytes.data();

	for (auto i = 0ul; i < sizeOfImage - s; ++i)
	{
		bool found = true;
		for (auto j = 0ul; j < s; ++j)
		{
			if (scanBytes[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}
		if (found) { return reinterpret_cast<uintptr_t>(&scanBytes[i]); }
	}
	return NULL;
}


