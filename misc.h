/*
	File   		: misc.h 
	Author 		: tty503 (Christian Marquez)
	Description : 
		Posee los prototipos a funciones auxiliares que, permiten :
		-> Obtener las direcciones de memoria a las funciones WinExec / ExitProcess.
		-> Sobreescribir la shellcode con las direcciones correspondientes a estás funciones. 

		Y posee, la declaración de las variables que serán utilizadas para procesar estás direcciones. 
 */
#ifndef MISC_H
#define MISC_H

void getaddr(unsigned long *winexec_addr, unsigned long *exitprocess_addr);
void assign_addr(unsigned char shellcode[]);

#endif