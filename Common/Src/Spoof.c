#include "Instance.h"
#include "Macros.h"
#include "Vulcan.h"
#include "Ntdll.h"
#include "PreHash.h"
#include "Common.h"

D_SEC(B)
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
)
{
    if(dwSyscall) {
        Inst->Param.ssn = dwSyscall;
    }

    return SpoofStub(Rcx, Rdx, R8, R9,
		&Inst->Param, pFunction, 8,
		StackArg1, StackArg2, StackArg3, StackArg4, StackArg5, StackArg6, StackArg7, StackArg8);        
}
