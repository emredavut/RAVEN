#include <Windows.h>


#include "Header.h"
#include "Structs.h"


#define MAXDLLNAME 64
#define DEREF_64( name )*(DWORD64 *)(name)

typedef struct {

	HMODULE hModule;
	DWORD64 ModuleHash;


}ModuleStruct;

ModuleStruct ModulesDB[MAXDLLNAME];
int elements = 0;

BOOL IsFound(DWORD64 ModuleHash, HMODULE* hModule) {

	for (size_t i = 0; i < elements; i++) {
		if (ModulesDB[i].ModuleHash == ModuleHash && ModulesDB[i].hModule != NULL) {
			*hModule = ModulesDB[i].hModule;
			return TRUE;
		}
	}

	return FALSE;
}


FARPROC GetProcAddressF(DWORD64 ModuleHash, DWORD64 ApiHash) {

	HMODULE hModule = NULL;


	if (!IsFound(ModuleHash, &hModule)) {
		if ((hModule = GetModuleHandleH(ModuleHash)) == NULL)
			return NULL;

		if (elements <= MAXDLLNAME) {
			ModulesDB[elements].hModule = hModule;
			ModulesDB[elements].ModuleHash = ModuleHash;
			elements++;
		}

	}

	return GetProcAddressH(hModule, ApiHash);
}



HMODULE GetModuleHandleH(DWORD64 ModuleHash) {

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	while (pDte) {
		if (pDte->FullDllName.Buffer != NULL) {
			if (pDte->FullDllName.Length < MAXDLLNAME - 1) {
				CHAR DllName[MAXDLLNAME] = { 0 };
				DWORD i = 0;
				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1) {
					DllName[i] = UC((char)pDte->FullDllName.Buffer[i]);
					i++;
				}
				DllName[i] = '\0';
				if (Rotr32A(DllName) == ModuleHash) {
					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				}
			}
		}
		else {
			break;
		}

		pDte = (PLDR_DATA_TABLE_ENTRY)DEREF_64(pDte);
	}
	return NULL;
}


FARPROC GetProcAddressH(HMODULE hModule, DWORD64 ApiHash) {

	PBYTE					pFunctionName	= NULL;
	PIMAGE_DOS_HEADER		DosHdr			= NULL;
	PIMAGE_NT_HEADERS		NtHdr			= NULL;
	PIMAGE_FILE_HEADER		FileHdr			= NULL;
	PIMAGE_OPTIONAL_HEADER	OptHdr			= NULL;
	PIMAGE_EXPORT_DIRECTORY ExportTable		= NULL;
	
	DosHdr = (PIMAGE_DOS_HEADER)hModule;
	if (DosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	NtHdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHdr + DosHdr->e_lfanew);
	if (NtHdr->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	FileHdr = (PIMAGE_FILE_HEADER)((ULONG_PTR)hModule + DosHdr->e_lfanew + sizeof(DWORD));
	OptHdr = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)FileHdr + sizeof(IMAGE_FILE_HEADER));
	ExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + OptHdr->DataDirectory[0].VirtualAddress);

	PDWORD FunctionNameAddressArray = (PDWORD)((ULONG_PTR)hModule + ExportTable->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)((ULONG_PTR)hModule + ExportTable->AddressOfFunctions);
	PWORD FunctionOrdinalAddressArray = (PWORD)((ULONG_PTR)hModule + ExportTable->AddressOfNameOrdinals);


	for (DWORD i = 0; i < ExportTable->NumberOfNames; i++) {
		pFunctionName = FunctionNameAddressArray[i] + (ULONG_PTR)hModule;
		if (ApiHash == Rotr32A((PCHAR)pFunctionName))
			return (FARPROC)((ULONG_PTR)hModule + FunctionAddressArray[FunctionOrdinalAddressArray[i]]);
	}

	return NULL;
}




typedef NTSTATUS(__stdcall* fnLdrLoadDll)(
	PWCHAR             PathToFile,
	ULONG              Flags,
	PUNICODE_STRING    ModuleFileName,
	PHANDLE            ModuleHandle
	);

HMODULE LdrLoadDll(LPSTR ModuleName) {


	UNICODE_STRING  UnicodeString = { 0 };
	WCHAR           ModuleNameW[MAX_PATH] = { 0 };
	DWORD           dwModuleNameSize = StrLenA(ModuleName);
	HMODULE         hModule = NULL;

	AToW(ModuleNameW, ModuleName, dwModuleNameSize);

	if (ModuleNameW)
	{
		USHORT DestSize = StrLenW(ModuleNameW) * sizeof(WCHAR);
		UnicodeString.Length = DestSize;
		UnicodeString.MaximumLength = DestSize + sizeof(WCHAR);
		UnicodeString.Buffer = ModuleNameW;
	}

	fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)GetProcAddressF(NTDLLDLL_Rotr32, LdrLoadDll_Rotr32);
	if (pLdrLoadDll == NULL)
		return NULL;

	if (!NT_SUCCESS(pLdrLoadDll(NULL, 0, &UnicodeString, &hModule))) {
		return NULL;
	}

	return hModule;
}



