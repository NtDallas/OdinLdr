#pragma once

#include <windows.h>

#include "Ntdll.h"

#include "Macros.h"
#include "Vulcan.h"

typedef struct _SYS_INFO {
    void*   pAddress;
    WORD    syscall;
} SYS_INFO, *PSYS_INFO;

typedef ULONG (NTSYSAPI * xRtlRandomEx)(PULONG Seed);

typedef struct _INSTANCE
{
    struct
    {
        void* StartAddr;
        void* End;
        DWORD dwSize;
    } Info;

    struct 
    {
        void* Kernel32;
        void* Ntdll;
        void* Kernelbase;
    } Module;

    // Function for reflectiver loader
    void* NtAllocateVirtualMemory;
    void* NtProtectVirtualMemory;
    void* LoadLibraryA;
    void* RtlCreateHeap;
    void* RtlAllocateHeap;
    D_API(GetProcAddress);
    xRtlRandomEx RtlRandomEx;

    // FUnction for synthetic stackframe
    D_API(RtlLookupFunctionEntry);
    void* BaseThreadInitThunk;
    void* RtlUserThreadStart;

    SYNTHETIC_STACK_FRAME   stackFrame;
} INSTANCE, *PINSTANCE;