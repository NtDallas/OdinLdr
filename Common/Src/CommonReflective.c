#include "Macros.h"
#include "Instance.h"
#include "Ntdll.h"
#include "Common.h"
#include "PreHash.h"

typedef struct {
	WORD offset : 12;
	WORD type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

D_SEC(B)
VOID CopySections(
	_In_	PVOID				pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS	pNtHeader, 
	_In_	PVOID				peContent
)
{
	PIMAGE_SECTION_HEADER ppSecHeader = IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		PVOID pDataDst = (PVOID)(U_PTR(pMemPeAddr) + ppSecHeader[i].VirtualAddress);
		PVOID pDataSrc = (PVOID)(U_PTR(peContent) + ppSecHeader[i].PointerToRawData);
		DWORD dwDataSize = ppSecHeader[i].SizeOfRawData;

		xMemcpy(pDataDst, pDataSrc, dwDataSize);
	}
}

D_SEC(B)
BOOL ProcessImportTable(
	_In_	PVOID				pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS	pNtHeader,
    _In_    PINSTANCE           Inst
)
{
	PIMAGE_IMPORT_DESCRIPTOR pImgImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(U_PTR(pMemPeAddr) + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImgImportDescriptor->Name != 0)
	{
		LPSTR lpModuleName = (LPSTR)(U_PTR(pMemPeAddr) + pImgImportDescriptor->Name);
		HMODULE hModAddr = SPOOF_API(Inst->LoadLibraryA, 
			lpModuleName);

        if(!hModAddr)
            return FALSE;


		PIMAGE_THUNK_DATA pOgThunkData = (PIMAGE_THUNK_DATA)(U_PTR(pMemPeAddr) + pImgImportDescriptor->OriginalFirstThunk);

		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(U_PTR(pMemPeAddr) + pImgImportDescriptor->FirstThunk);

		while (pOgThunkData->u1.AddressOfData != 0)
		{
			PVOID pFunctionAddr = NULL;

			if (IMAGE_SNAP_BY_ORDINAL(pOgThunkData->u1.Ordinal))
			{
				pFunctionAddr = Inst->GetProcAddress(hModAddr, MAKEINTRESOURCEA(pOgThunkData->u1.Ordinal));
                if(!pFunctionAddr)
                    return FALSE;

				pFirstThunk->u1.Function = U_PTR(pFunctionAddr);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImgImportName = (PIMAGE_IMPORT_BY_NAME)(U_PTR(pMemPeAddr) + pOgThunkData->u1.AddressOfData);
				pFunctionAddr = Inst->GetProcAddress(hModAddr, pImgImportName->Name);
                if(!pFunctionAddr)
                    return FALSE;

				pFirstThunk->u1.Function = U_PTR(pFunctionAddr);
			}

			pOgThunkData++;
			pFirstThunk++;
		}

		pImgImportDescriptor++;
	}

    return TRUE;
}

D_SEC(B)
VOID ApplyBaseRelocations(
	_In_	PVOID				pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS	pNtHeader
)
{
	PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(U_PTR(pMemPeAddr) + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	ULONG_PTR uPtrDelta = U_PTR(pMemPeAddr) - pNtHeader->OptionalHeader.ImageBase;

	if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
	{
		return; // No base relocations to apply.
	}

	PIMAGE_BASE_RELOCATION pCurrentReloc = pImgBaseReloc;
	while (pCurrentReloc->SizeOfBlock > 0)
	{
		UINT_PTR uiRelocBase = U_PTR(pMemPeAddr) + pCurrentReloc->VirtualAddress;
		PIMAGE_RELOC pImgReloc = (PIMAGE_RELOC)(U_PTR(pCurrentReloc) + sizeof(IMAGE_BASE_RELOCATION));

		int numRelocations = (pCurrentReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

		for (size_t i = 0; i < numRelocations; ++i)
		{
			switch (pImgReloc->type)
			{
			case IMAGE_REL_BASED_DIR64:
				*(ULONG_PTR*)(uiRelocBase + pImgReloc->offset) += uPtrDelta;
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*(DWORD*)(uiRelocBase + pImgReloc->offset) += (DWORD)(uPtrDelta);
				break;

			case IMAGE_REL_BASED_HIGH:
				*(WORD*)(uiRelocBase + pImgReloc->offset) += HIWORD(uPtrDelta);
				break;

			case IMAGE_REL_BASED_LOW:
				*(WORD*)(uiRelocBase + pImgReloc->offset) += LOWORD(uPtrDelta);
				break;

			default:
				// Unsupported relocation type, handle appropriately if necessary.
				break;
			}

			pImgReloc = (PIMAGE_RELOC)((PBYTE)(pImgReloc) + sizeof(IMAGE_RELOC));
		}

		pCurrentReloc = (PIMAGE_BASE_RELOCATION)(U_PTR(pCurrentReloc) + pCurrentReloc->SizeOfBlock);
	}
}
