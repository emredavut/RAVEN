#include <Windows.h>
#include "Structs.h"
#include "Header.h"


#define UP		-32
#define DOWN	32

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 Rotr32Hash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

VX_TABLE_ENTRY VxTbleEntry = { 0 };

typedef struct _NtdllConfig {
	PVOID pNtdll;
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS pNtHdr;
	PIMAGE_EXPORT_DIRECTORY pIED;
	PDWORD pdwAddressOfFunctions;
	PDWORD pdwAddressOfNames;
	PWORD pwAddressOfNameOrdinales;
} NtdllConfig, * PNtdllConfig;

NtdllConfig NtdllConfigStruct = { 0 };

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL InitializeNtdll() {

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	if (pPeb == NULL || pPeb->OSMajorVersion != 0xA) {
		return FALSE;
	}

	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PVOID pNtdll = pDte->DllBase;
	if (pNtdll == NULL) {
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pNtdll;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pNtdll + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdll + pNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);
	if (pIED == NULL) {
		return FALSE;
	}

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pNtdll + pIED->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pNtdll + pIED->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pNtdll + pIED->AddressOfNameOrdinals);


	NtdllConfigStruct.pNtdll = pNtdll;
	NtdllConfigStruct.pDosHdr = pDosHdr;
	NtdllConfigStruct.pNtHdr = pNtHdr;
	NtdllConfigStruct.pIED = pIED;
	NtdllConfigStruct.pdwAddressOfFunctions = pdwAddressOfFunctions;
	NtdllConfigStruct.pdwAddressOfNames = pdwAddressOfNames;
	NtdllConfigStruct.pwAddressOfNameOrdinales = pwAddressOfNameOrdinales;

	return TRUE;

}

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------


#define KEY1 0x82
#define KEY2 0x34
#define KEY3 0x46


BOOL FetshSyscall(DWORD64 Rotr32Hash) {

	if (NtdllConfigStruct.pNtdll == NULL ||
		NtdllConfigStruct.pdwAddressOfFunctions == NULL ||
		NtdllConfigStruct.pdwAddressOfNames == NULL ||
		NtdllConfigStruct.pwAddressOfNameOrdinales == NULL) {

		if (!InitializeNtdll()) {
			return FALSE;
		}
	}

	for (WORD cx = 0; cx < NtdllConfigStruct.pIED->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)NtdllConfigStruct.pNtdll + NtdllConfigStruct.pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)NtdllConfigStruct.pNtdll + NtdllConfigStruct.pdwAddressOfFunctions[NtdllConfigStruct.pwAddressOfNameOrdinales[cx]];
		if (Rotr32A(pczFunctionName) == Rotr32Hash) {
			VxTbleEntry.pAddress = pFunctionAddress;

			if (*((PBYTE)pFunctionAddress) == (0xCE ^ KEY1)				//0x4c
				&& *((PBYTE)pFunctionAddress + 1) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2) == (0x53 ^ KEY1)		//0xd1
				&& *((PBYTE)pFunctionAddress + 3) == (0x3A ^ KEY1)		//0xb8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				VxTbleEntry.wSystemCall = (high << 8) | low;

				return TRUE;
			}
			if (*((PBYTE)pFunctionAddress) == (0xDD ^ KEY2)) {							//0xe9	
				for (WORD idx = 1; idx <= 500; idx++) {
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == (0x78 ^ KEY2)		//0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == (0xBF ^ KEY2)	//0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == (0x8C ^ KEY2) //0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						VxTbleEntry.wSystemCall = (high << 8) | low - idx;

						return TRUE;
					}
					if (*((PBYTE)pFunctionAddress + idx * UP) == (0x78 ^ KEY2)			//0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == (0xBF ^ KEY2)	//0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == (0x8C ^ KEY2)	//0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						VxTbleEntry.wSystemCall = (high << 8) | low + idx;

						return TRUE;
					}

				}
				return FALSE;
			}
			if (*((PBYTE)pFunctionAddress + 3) == (0xAF ^ KEY3)) {						//0xe9	
				for (WORD idx = 1; idx <= 500; idx++) {
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == (0xCD ^ KEY3) //0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == (0x97 ^ KEY3) //0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == (0xFE ^ KEY3)	//0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						VxTbleEntry.wSystemCall = (high << 8) | low - idx;
						return TRUE;
					}
					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == (0xCD ^ KEY3) //0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == (0x97 ^ KEY3) //0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == (0xFE ^ KEY3) //0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						VxTbleEntry.wSystemCall = (high << 8) | low + idx;
						return TRUE;
					}

				}
				return FALSE;
			}
		}
	}
	return FALSE;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------

WORD FetshSysNmbr() {
	return VxTbleEntry.wSystemCall;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------



