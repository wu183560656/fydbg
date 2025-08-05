.DATA
	extern deviceiocontrol:PROC
.CODE
ASM_transfer proc
	lea r10,[rsp+28h]
	push r9
	push r8
	push rdx
	push rcx
	mov rcx,rax
	mov rdx,rsp
	mov r8,r10
	sub rsp,28h
	call deviceiocontrol
	add rsp,28h
	pop rcx
	pop rdx
	pop r8
	pop r9
	ret
ASM_transfer endp

END