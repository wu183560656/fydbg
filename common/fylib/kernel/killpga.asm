.DATA
	extern MyKiPageFault:PROC
	extern hookKiPageFault:QWORD
.CODE
;idt stack:+0:rip,+8:cs,+10:rflags,+18:rsp,+20:ss
AsmKiPageFault proc
	lea rsp,[rsp-100h]
	mov [rsp+20h],rax
	mov [rsp+28h],rcx
	mov [rsp+30h],rdx
	mov [rsp+38h],r8
	mov [rsp+40h],r9
	mov [rsp+48h],r10
	mov [rsp+50h],r11

	mov rcx,[rsp+100h]
	lea rdx,[rsp+108h]
	lea r8,[rsp+120h]
	call MyKiPageFault
	test al,al

	mov r11,[rsp+50h]
	mov r10,[rsp+48h]
	mov r9,[rsp+40h]
	mov r8,[rsp+38h]
	mov rdx,[rsp+30h]
	mov rcx,[rsp+28h]
	mov rax,[rsp+20h]
	lea rsp,[rsp+100h]

	jnz $ret
	jmp [hookKiPageFault]
$ret:
	lea rsp,[rsp+8h]
	iretq
AsmKiPageFault endp

END