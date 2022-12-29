#include <stdio.h>
#include <Windows.h>
#include "MemLoadPe.h"
#include "resource1.h"

using namespace std;

int main()
{
	system("pause");
	MemLoadPe testLoad;
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_EXEDLL2), TEXT("EXEDLL")); //导入资源
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	PVOID lpBuffer = LockResource(hGlobal);
	testLoad.MemLoadDll(lpBuffer, NULL);
	printf("LoadBaseAddress = %p\n", testLoad.LoadBaseAddress);
	printf("EntryPointer = %p\n", (PVOID)testLoad.EntryPointer);
	printf("IsDll = %d\n", testLoad.IsDll);
	FreeResource(hGlobal);
	system("pause");
	printf("is runing!\n");
	system("pause");
	return 0;
}

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
