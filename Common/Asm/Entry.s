[BITS 64]

extern PreMain

global EntryPoint
global GetShellcodeStart

[SECTION .text$A]

    EntryPoint:
        push rsi                            
        mov rsi, rsp                        
        and   rsp, 0xFFFFFFFFFFFFFFF0     
        sub   rsp, 0x20                     
        call  PreMain                   
        mov   rsp, rsi                      
        pop   rsi                           
        ret       

     GetShellcodeStart:
        call coucou

        coucou:
        pop rax
        and rax, 0xFFFFFFFFFFFFFF00 
        ret        