#pragma once

#include <windows.h>

#include "Ntdll.h"
#include "Macros.h"
//#include "Vulcan.h"

typedef struct _SYS_INFO {
    PVOID   pAddress;
    DWORD    wSyscall;
} SYS_INFO, *PSYS_INFO;

typedef struct _PRM
{
    PVOID       Fixup;             // 0
    PVOID       OG_retaddr;        // 8
    PVOID       rbx;               // 16
    PVOID       rdi;               // 24
    PVOID       BTIT_ss;           // 32
    PVOID       BTIT_retaddr;      // 40
    PVOID       Gadget_ss;         // 48
    PVOID       RUTS_ss;           // 56
    PVOID       RUTS_retaddr;      // 64
    PVOID       ssn;               // 72  
    PVOID       trampoline;        // 80
    PVOID       rsi;               // 88
    PVOID       r12;               // 96
    PVOID       r13;               // 104
    PVOID       r14;               // 112
    PVOID       r15;               // 120
} PRM, * PPRM;

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

    struct
    {
        SYS_INFO    NtAllocateVirtualMemory;
        SYS_INFO    NtProtectVirtualMemory;
    } Syscall;

    // Function for reflectiver loader
    void* LoadLibraryA;
    void* RtlCreateHeap;
    void* RtlAllocateHeap;

    D_API(GetProcAddress);
    D_API(RtlLookupFunctionEntry);

    PRM     Param;
} INSTANCE, *PINSTANCE;

typedef struct {
    char* start;
    DWORD length;
    DWORD offset;
} RDATA_SECTION, *PRDATA_SECTION;