#pragma once

#include "Macros.h"
#include "Ntdll.h"

BOOL PatchMemoryProtection(
	_In_	PVOID					pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS		pNtHeader,
    _In_    PINSTANCE               Inst
);