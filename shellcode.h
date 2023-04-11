/*
	Encabezado con el arreglo con los opcodes de la shellcode. 

	Y, además, la inicialización de las variables que almacenarán las direcciones 
		de las funciones que serán llamadas de kernel32.dll.
 */


/* Definimos la shellcode. */
unsigned char shellcode[35] = {
	0x31, 0xC9,					/* xor ecx, ecx 	*/
	0x51,						/* push ecx 		*/
								/* ecx = 0; 		*/

	/* Enviamos el primer parámetro de WinExec, un string con el nombre del programa a lanzar */
	0x68,						/* push 			*/						// shellcode[3]
	0x2E, 0x65, 0x78, 0x65,		/* string : .exe 	*/ 

	0x68,						/* push 			*/						// shellcode[8]
	0x63, 0x61,0x6C,0x63,		/* string : 'calc' 	*/						

	/* Copiamos el puntero a la pila en eax : *string */ 
	0x89, 0xE0,					/* mov eax, esp 	*/

	/* ?? */
	0x41,						/* inc ecx 			*/
	0x51,						/* push ecx 		*/ 
								/* ecx = 1; 		*/ 
	0x50,						/* push eax 		*/

	/* Copiamos en ebx la dirección a WinExec en kernel32.dll,
	 *	la dirección va desde shellcode[18+1] hasta shellcode[18+4]
	 */
	0xBB,						/* mov ebx, 	*/ 							// shellcode[18]		 
	0x00, 0x00, 0x00, 0x00, 	/* Dirección de WinExec en kernel32.dll */
	0xFF, 0xD3, 				/* call ebx 	*/ 
	
	0x31, 0xC0, 				/* xor eax, eax */ 
	0x50, 						/* push  eax    */ 

	0xB8, 						/* mov eax, 	*/ 							// shellcode[28]	 
	0x00, 0x00, 0x00, 0x00, 	/* Dirección de ExitProcess en kernel32.dll */ 
	0xFF, 0xE0					/* jmp eax 		*/ 
};
