/*
	File   		: misc.c
	Author 		: tty503 (Christian Marquez)
	Description : 
		Posee las definiciones a funciones auxiliares que, permiten :
		-> Obtener las direcciones de memoria a las funciones WinExec / ExitProcess.
		-> Sobreescribir la shellcode con las direcciones correspondientes a estás funciones. 
 */
#include "misc.h"
void getaddr(unsigned long *winexec_addr, unsigned long *exitprocess_addr)
/*
	Recibe como parámetros las direcciones a las variables en las que almacenará los resultados. 
 */
{ 
	/*
 	 	Hacemos uso de las WinAPI, y usamos las funciones GetModuleHandle y GetProcAddress
 	 	para obtener :
 	 		1. La dirección en memoria de la DLL kernel32.
 	 		2. La dirección en memoria de las funciones (definidas dentro de kernel32). 
	 */
	
	unsigned long kernel32_addr; // No volveremos a usar esto, por esa razón lo hacemos como variable local.
	kernel32_addr = GetModuleHandle("kernel32.dll"); 

	/* Almacenamos los valores devueltos en las variables definidas en el encabezado, estás serán
	 	utilizadas en otra rutina. 
	 */
	*exitprocess_addr = GetProcAddress(kernel32_addr, "ExitProcess"); 
	*winexec_addr 	  = GetProcAddress(kernel32_addr, "WinExec"); 
}
void assign_addr(unsigned char shellcode[])
/*
	Recibe como parámetro el arreglo de la shellcode.  
 */
{
	/* 
		¿Qué clase de herejía es esta? 
			Las direcciones de memoria a las funciones está definidas en la posición 18 y 28 
			del arreglo y poseen una longitud de 4 bytes. 

			El valor retornado por getaddr no nos conviene en el formato del shellcode, motivado
			a que, estamos trabajando con un procesador little-endian y debemos convertir esa dirección
			a dicho formato. 

			¿Cómo lo hacemos?
			Hacemos una mascará de bits y pasamos de 1 byte.

			Supongase que, la dirección devuelta por getaddr era : 0xAF5477FF.
			Lo que hacemos es, pasar el último byte a la primera posición y así sucesivamente.
			Hacemos un desplazamiento para eliminar los bytes sobrantes.  

			Y nos quedaría algo como : 0xFF7754AF.
	 */
	shellcode[18+1] = (winexec_addr & 0x000000FF); 
	shellcode[18+2] = (winexec_addr & 0x0000FF00) >> 8;
	shellcode[18+3] = (winexec_addr & 0x00FF0000) >> 16;
	shellcode[18+4] = (winexec_addr & 0xFF000000) >> 24; 

	shellcode[28+1] = (exitprocess_addr & 0x000000FF); 
	shellcode[28+2] = (exitprocess_addr & 0x0000FF00) >> 8;
	shellcode[28+3] = (exitprocess_addr & 0x00FF0000) >> 16;
	shellcode[28+4] = (exitprocess_addr & 0xFF000000) >> 24; 
}