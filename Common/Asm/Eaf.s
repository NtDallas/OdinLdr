[BITS 64]

global ReadMemFromGadget

[SECTION .text$B]
    ReadMemFromGadget:
        xor rax, rax 
		mov rax, rcx 
		call rdx 
		ret