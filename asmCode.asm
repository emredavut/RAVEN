.data
	wSystemCall DWORD 000h

.code 

	PlaceSysNmbr PROC
		
		xor		rdx, rdx
		mov		edx, ecx
		sub		eax, 4
		mov		wSystemCall, 000h
		add		eax, 4
		mov		wSystemCall, edx
		xor		eax, eax
		ret

	PlaceSysNmbr ENDP

	;--------------------------------------------------------------------------------------

	SysExec PROC
		add		rdx, 52h
		mov		r10, rcx
		add		r9, 31
		mov		eax, wSystemCall
		sub		rdx, 52h
		sub		r9, 31
		syscall
		add		r10, 3
		sub		r10, 3
		ret
	
	SysExec ENDP



end