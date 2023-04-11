/*
	Código que queremos ejecutar como shellcode
 */
#include <windows.h>
int main(void)
{
	WinExec("calc.exe",0);
	ExitProcess(0); 
}