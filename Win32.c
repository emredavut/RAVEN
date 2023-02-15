#include <Windows.h>
#include "Header.h"

#define SEED 0x34


//------------------------------------------------------------------------------------------------------------------------------------

SIZE_T StrLenA(LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}


SIZE_T StrLenW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}


//------------------------------------------------------------------------------------------------------------------------------------

UINT32 HashStringRotr32SubA(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

DWORD64 Rotr32A(PCHAR String)
{
	DWORD64 Value = 0;

	for (INT Index = 0; Index < StrLenA(String); Index++)
		Value = String[Index] + HashStringRotr32SubA(Value, SEED);

	return Value;
}

//------------------------------------------------------------------------------------------------------------------------------------

VOID ZM2(PVOID Destination, SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

PVOID CP2(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

CHAR UC(char c){
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 'A';
	}
	return c;
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

SIZE_T AToW(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

wchar_t* _strcat(wchar_t* dest, const wchar_t* src)
{
	if ((dest == NULL) || (src == NULL))
		return dest;

	while (*dest != 0)
		dest++;

	while (*src != 0) {
		*dest = *src;
		dest++;
		src++;
	}

	*dest = 0;
	return dest;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

wchar_t* _strcpy(wchar_t* dest, const wchar_t* src)
{
	wchar_t* p;

	if ((dest == NULL) || (src == NULL))
		return dest;

	if (dest == src)
		return dest;

	p = dest;
	while (*src != 0) {
		*p = *src;
		p++;
		src++;
	}

	*p = 0;
	return dest;
}



