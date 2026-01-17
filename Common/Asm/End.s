[BITS 64]

global GetShellcodeEnd

[SECTION .text$Z]
    GetShellcodeEnd:
        call coucou

        coucou:
        pop rax
        add rax, 6
        ret       

    Leave:
        db 'R', 't', 'l', 'D', 'a', 'l', 'l', 'a' ,'s'