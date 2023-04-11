/*
 	Una breve explicación, tenemos los siguientes archivos :
 	-> run.c :
 		Posee una plantilla que, utilizando un puntero a una función podemos asignarle
 		la dirección de nuestra shellcode.  
 	
 	-> shellcode.h :
 		Posee un arreglo con valores hexadecimales que son las instrucciones de nuestra shellcode
 		que serán pasadas al puntero de la función, ocasionando que se carguen en memoria.

 	-> misc.h / misc.c :
 		Tenenmos una rutina que nos permite obtener la dirección de memoria de la DLL, y las
 		direcciones de las funciones WinExec / ExitProcess que están declaradas en kernel32.dll.

 	-> stub_shellcode.c / stub_shellcode.asm :  
 		Un pequeño fragmento de lo queremos que haga la shellcode, podemos compilarlos a bytecode 
 		y visualizar en un dissambler los opcodes correspondientes de cada instrucción. 

 		El archivo C, es lo que usaremos como referencia del código en Assembler que queramos generar.

 	(Cada elemento, posee sus propios comentarios y otros elementos adjuntos que detallan su funcionalidad). 

 */

/*
	File        : run.c 
	Author 	    : tty503 (Christian Marquez)
	Description : 
		Asigna a un puntero de una función la dirección de memoria a la shellcode contenida en el arreglo.
		De está forma, despliega en memoria las instrucciones que él contiene y estás son ejecutadas.

		Es necesario aclarar que, está forma de utilizar una shellcode es una técnica de despliegue...
		Como un dropper y no lo que tradicionalmente sería una shellcode, es decir, código inyectado 
		después del "secuestro" del registro que apunta a la siguiente instrucción (eip, en las arquitecturas x86)
		esto por lo general se da en un desbordamiento de buffer o cualquier otra medida de explotación. 
 */

#include "misc.h"
#include "shellcode.h"

int main(void)
{
	/* Obtenemos las direcciones */ 
	getaddr(&winexec_addr, &exitprocess_addr); 


	/* Asignamos las direcciones */
	assign_addr(shellcode); 

	/* 	Declaramos un puntero a una función, 
		Es decir, estamos apuntando a la dirección de memoria de esa función y hasta este punto es desconocida.
		
		¿Qué función? el programa aún no sabe a que parte de la memoria dirigirse para ejecutar las instrucciones
		correspondientes a la función. 
	 */
	int(*func)();

	/*
		Le asignamos la dirección de memoria del arreglo con la shellcode al puntero.
		Hacemos un typecast del arreglo a un puntero de función con el mismo de tipo de retorno. 
	 */
	func = (int(*)())shellcode;

	/* Ejecutamos la función, y está salta a la shellcode, cargando en memoria todos los opcodes */ 
	(int)(*func)(); 
}