#pragma once

#include <windows.h>
#include "Instance.h"

typedef void (WINAPI* DLLMAIN)(
    _In_    HINSTANCE   hinstDll,
    _In_    DWORD       fdwReason,
    _In_    LPVOID      lpwReserved
);

/*  ---------------------
    Api.c 
--------------------- */
PVOID	ResolveEafGadgetAddress(
	_In_	PVOID	pModule
);

PVOID ResolveJmpRbxGadget(
	_In_	PVOID	    pModuleAddr
);

PVOID   ResolveModuleAddressWithHash(
    _In_    DWORD   dwModuleHash
);

PVOID   ResolveProcedureAddressWithHash(
	_In_	PVOID	pGadgetRead,
    _In_    PVOID   pModuleAddr, 
    _In_    DWORD   dwProcHash
);
   
BOOL	ResolveSyscallWithHash(
	_In_	PVOID	pFunction,
	_Inout_	PDWORD	pdwSyscall,
	_Inout_ PVOID* ppGadget
);

BOOL CalculateFunctionStackSizeWrapper(
	_In_	PINSTANCE	Inst,
	_In_    PVOID   	pFunction,
	_Inout_ PDWORD  	pdwStackSize
);

DWORD HashStringA(
    _In_    LPSTR   str
);

DWORD HashStringW(
    _In_    LPWSTR  str
);

VOID xMemcpy(
    _In_    PBYTE   dst, 
    _In_    PBYTE   src, 
    _In_    DWORD   size
);

VOID xMemset(
    _In_    PBYTE   dst, 
    _In_    BYTE    c, 
    _In_    DWORD   size
);

/*  ---------------------
    Spoof.c 
--------------------- */
PVOID	SpoofApiCall(
	_In_	PINSTANCE	Inst,
	_In_	PVOID		pFunction,
	_In_	DWORD		dwSyscall,
	_In_	PVOID	Rcx,
	_In_	PVOID	Rdx,
	_In_	PVOID	R8,
	_In_	PVOID	R9,
	_In_	PVOID	StackArg1,
	_In_	PVOID	StackArg2,
	_In_	PVOID	StackArg3,
	_In_	PVOID	StackArg4,
	_In_	PVOID	StackArg5,
	_In_	PVOID	StackArg6,
	_In_	PVOID	StackArg7,
	_In_	PVOID	StackArg8
);


/*  ---------------------
    Entry.s 
--------------------- */
PVOID   GetShellcodeStart();

/*  ---------------------
    End.s 
--------------------- */

PVOID   GetShellcodeEnd();

/*  ---------------------
    Utils.s 
--------------------- */
//extern PVOID SpoofStub(PVOID, ...);


extern ULONG_PTR SpoofStub(
    _In_    PVOID   Rcx,
    _In_    PVOID   Rdx, 
    _In_    PVOID   R8,
    _In_    PVOID   R9,
    _In_    PVOID   pParam,
    _In_    PVOID   pFunction,
    _In_    UINT_PTR   dwArgCount,
    _In_    PVOID   StackArg1,
    _In_    PVOID   StackArg2,
    _In_    PVOID   StackArg3,
    _In_    PVOID   StackArg4,
    _In_    PVOID   StackArg5,
    _In_    PVOID   StackArg6,
    _In_    PVOID   StackArg7,
    _In_    PVOID   StackArg8
);

/*  ---------------------
    Eaf.s 
--------------------- */
extern PVOID ReadMemFromGadget(
	_In_	PVOID	pAddressToRead,
	_In_	PVOID	pGadget
);
