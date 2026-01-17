#pragma once

#define D_API( x )  __typeof__( x ) * x
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define MODULE_SIZE(x)      ((PIMAGE_NT_HEADERS)((UINT_PTR)x + ((PIMAGE_DOS_HEADER)x)->e_lfanew))->OptionalHeader.SizeOfImage
#define DBREAK              __debugbreak()
#define DEREF( name )*(UINT_PTR *)(name)

#define U_PTR(x)   (UINT_PTR)x
#define C_DW64(x)			((DWORD64)x)

#define	EAF_READ_DW64(x)	(ReadMemFromGadget(x, pGadgetRead))
#define	EAF_READ_DW32(x)	((DWORD32)ReadMemFromGadget(x, pGadgetRead))
#define	EAF_READ_W(x)		((WORD)ReadMemFromGadget(x, pGadgetRead))

#define DOWN	                    32
#define SYSCALL_GADGET_OFFSET       0x12


#define SPOOF_SYSCALL_X(Name) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_A(Name, a) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_B(Name, a, b) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_C(Name, a, b, c) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_D(Name, a, b, c, d) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_E(Name, a, b, c, d, e) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_F(Name, a, b, c, d, e, f) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_G(Name, a, b, c, d, e, f, g) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_H(Name, a, b, c, d, e, f, g, h) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define SPOOF_SYSCALL_I(Name, a, b, c, d, e, f, g, h, i) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define SPOOF_SYSCALL_J(Name, a, b, c, d, e, f, g, h, i, j) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define SPOOF_SYSCALL_K(Name, a, b, c, d, e, f, g, h, i, j, k) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define SPOOF_SYSCALL_L(Name, a, b, c, d, e, f, g, h, i, j, k, l) \
    SpoofApiCall(Inst, Inst->Syscall.Name.pAddress, Inst->Syscall.Name.wSyscall, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define DCALL_EXPAND(x) x
#define DCALL_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define SPOOF_SYSCALL(Name, ...) \
    DCALL_EXPAND(DCALL_GET_MACRO(__VA_ARGS__, \
        SPOOF_SYSCALL_L, SPOOF_SYSCALL_K, SPOOF_SYSCALL_J, SPOOF_SYSCALL_I, \
        SPOOF_SYSCALL_H, SPOOF_SYSCALL_G, SPOOF_SYSCALL_F, SPOOF_SYSCALL_E, \
        SPOOF_SYSCALL_D, SPOOF_SYSCALL_C, SPOOF_SYSCALL_B, SPOOF_SYSCALL_A, \
        SPOOF_SYSCALL_X)(Name, __VA_ARGS__))


#define SPOOF_API_X(Name) \
    SpoofApiCall(Inst, Name, 0, \
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_A(Name, a) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_B(Name, a, b) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_C(Name, a, b, c) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_D(Name, a, b, c, d) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_E(Name, a, b, c, d, e) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_F(Name, a, b, c, d, e, f) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_G(Name, a, b, c, d, e, f, g) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define SPOOF_API_H(Name, a, b, c, d, e, f, g, h) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define SPOOF_API_I(Name, a, b, c, d, e, f, g, h, i) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define SPOOF_API_J(Name, a, b, c, d, e, f, g, h, i, j) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define SPOOF_API_K(Name, a, b, c, d, e, f, g, h, i, j, k) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define SPOOF_API_L(Name, a, b, c, d, e, f, g, h, i, j, k, l) \
    SpoofApiCall(Inst, Name, 0, \
        (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define SPOOF_API_EXPAND(x) x
#define SPOOF_API_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define SPOOF_API(Name, ...) \
    SPOOF_API_EXPAND(SPOOF_API_GET_MACRO(__VA_ARGS__, \
        SPOOF_API_L, SPOOF_API_K, SPOOF_API_J, SPOOF_API_I, \
        SPOOF_API_H, SPOOF_API_G, SPOOF_API_F, SPOOF_API_E, \
        SPOOF_API_D, SPOOF_API_C, SPOOF_API_B, SPOOF_API_A, \
        SPOOF_API_X)(Name, __VA_ARGS__))