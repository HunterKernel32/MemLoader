#include <Windows.h>
#include <stdio.h>
#include "MemLoadPe.h"

MemLoadPe::MemLoadPe()
{
	DosHeader = NULL;
	PeHeader = NULL;
	SectionHeader = NULL;

	Mem_PeHeader = NULL;
	Mem_List_IID = NULL;
	Mem_List_INT = NULL;
	Mem_List_BRT = NULL;

	FileBuffer = NULL;

	LoadBaseAddress = NULL;
	EntryPointer = 0;
	IsDll = FALSE;
	NeedRepairBRT = FALSE;
	FileName = NULL;
}

MemLoadPe::~MemLoadPe()
{
	
}

HANDLE MemLoadPe::MemLoadDll(PVOID FileBuffer, PCWCH FileName)
{
	this->FileBuffer = FileBuffer;
	if (LoadPeHeader() == false)
	{
		printf("LoadPeHeader Error!\n");
		return NULL;
	}
	if (LoadSectionData() == false)
	{
		printf("LoadSectionData Error!\n");
		return NULL;
	}
	if (RepairList_IAT() == false)
	{
		printf("RepairList_IAT Error!\n");
		return NULL;
	}
	if (RepairList_BRT() == false)
	{
		printf("RepairList_BRT Error!\n");
		return NULL;
	}
	if (FileName != NULL)
	{
		this->FileName = FileName;
		RepairLdrLinks();
	}
	//CallEntryPoint(this);
	HANDLE hThread = NULL;//::CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CallEntryPoint, this, 0, NULL);
	return hThread;
}


bool MemLoadPe::CheckPeLegality()
{
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE || PeHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("This is not a PE file!\n");
		return false;
	}

#ifdef _WIN64
	if (PeHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("This is not a x64 file!\n");
		return false;
	}
#else
	if (PeHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("This is not a x32 file!\n");
		return false;
	}
#endif

	FileCharacteristics FileCmp;
	FileCmp.Value = PeHeader->FileHeader.Characteristics;
	if (FileCmp.BitField.IsDllFile == 0)
	{
		IsDll = FALSE;
	}
	else
	{
		IsDll = TRUE;
	}
	/*
	printf("{ %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d }\n",
		FileCmp.BitField.NoRelocation,
		FileCmp.BitField.IsExecutable,
		FileCmp.BitField.NoLineNumber,
		FileCmp.BitField.NoSymbolMsg,
		FileCmp.BitField.Aggressively,
		FileCmp.BitField.Is_x64Target,
		FileCmp.BitField.Unknown,
		FileCmp.BitField.ReverseLowByte,
		FileCmp.BitField.Is_x32Target,
		FileCmp.BitField.NoDebuggingMsg,
		FileCmp.BitField.RemovableMedia,
		FileCmp.BitField.NetworkMedia,
		FileCmp.BitField.IsSystemFile,
		FileCmp.BitField.IsDllFile,
		FileCmp.BitField.SingleProcessor,
		FileCmp.BitField.ReverseHighByte);
	*/

	return true;
}


bool MemLoadPe::LoadPeHeader()
{
	if (FileBuffer == NULL) { return false; }

	DosHeader = (PIMAGE_DOS_HEADER)FileBuffer;

	PeHeader = (PIMAGE_NT_HEADERS)(DosHeader->e_lfanew + (ULONG_PTR)DosHeader);

	if (!CheckPeLegality()) { return false; }

	SectionHeader = IMAGE_FIRST_SECTION(PeHeader);

	if (PeHeader->OptionalHeader.DataDirectory[5].Size == 0)
	{
		//printf("Not have BRT list!\n");

		LoadBaseAddress = VirtualAlloc((LPVOID)PeHeader->OptionalHeader.ImageBase, 
			PeHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		printf("VirtualAlloc = %p\n", LoadBaseAddress);
		if (LoadBaseAddress == NULL) { return false; }
		NeedRepairBRT = FALSE; //无需修复重定位
	}
	else
	{
		LoadBaseAddress = VirtualAlloc(NULL, PeHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (LoadBaseAddress == NULL) { return false; }
		NeedRepairBRT = TRUE; //需要修复重定位
	}

	memcpy(LoadBaseAddress, DosHeader, PeHeader->OptionalHeader.SizeOfHeaders);

	return true;

}

bool MemLoadPe::LoadSectionData()
{
	PVOID Copy_Start;
	DWORD Copy_Length;
	PVOID Copy_TargetAddr;
	WORD Count;
	for (Count = 0; Count < PeHeader->FileHeader.NumberOfSections; Count++)
	{		
		if (SectionHeader->SizeOfRawData != 0 && SectionHeader->VirtualAddress != 0) 
		{
			Copy_Start = (PVOID)((ULONG_PTR)DosHeader + SectionHeader->PointerToRawData);
			Copy_Length = SectionHeader->SizeOfRawData;//注意不能用VirtualSize,因为它在联合体中有歧义
			Copy_TargetAddr = (PVOID)((ULONG_PTR)LoadBaseAddress + SectionHeader->VirtualAddress);
			memcpy(Copy_TargetAddr, Copy_Start, Copy_Length);
		}
		SectionHeader++;
	}
	if (Count < 3) { return false; }

	PIMAGE_DOS_HEADER Mem_DosHeader = (PIMAGE_DOS_HEADER)LoadBaseAddress;
	Mem_PeHeader = (PIMAGE_NT_HEADERS)(Mem_DosHeader->e_lfanew + (ULONG_PTR)LoadBaseAddress);
	Mem_List_IID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)LoadBaseAddress +
		Mem_PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	Mem_List_BRT = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)LoadBaseAddress + 
		Mem_PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	EntryPointer = (ULONG_PTR)LoadBaseAddress + Mem_PeHeader->OptionalHeader.AddressOfEntryPoint;
	return true;
}


bool MemLoadPe::RepairList_IAT()
{
	
#ifdef _WIN64
	union
	{
		struct
		{
			ULONGLONG low : 63;
			ULONGLONG high : 1;
		}BitField;
		ULONGLONG Value;
	}TempUnio = { 0 };
#else
	union 
	{
		struct
		{
			ULONG low : 31;
			ULONG high : 1;
		}BitField;
		ULONG Value;
	}TempUnio = { 0 };
#endif 

	char* DllName;
	HMODULE hModule;
	PULONG_PTR pFuncAddr;
	PIMAGE_IMPORT_BY_NAME pFuncName;

	while (Mem_List_IID->Name != 0)
	{
		DllName = (char*)((ULONG_PTR)LoadBaseAddress + Mem_List_IID->Name);
		pFuncAddr = (PULONG_PTR)((ULONG_PTR)LoadBaseAddress + Mem_List_IID->FirstThunk);
		Mem_List_INT = (PIMAGE_THUNK_DATA)((ULONG_PTR)LoadBaseAddress + Mem_List_IID->OriginalFirstThunk);

		//printf("DllName :%s\n", DllName);
		hModule = LoadLibraryA(DllName);
		if (hModule == NULL)
		{
			//加载的模块不在当前目录或系统目录
			char stemp[80] = "找不到";
			strcat_s(stemp, DllName);
			strcat_s(stemp, "文件!\n");
			MessageBoxA(0, stemp, "错误", MB_ICONERROR);
			return false;
		}
		while (*pFuncAddr != 0)
		{
			TempUnio.Value = Mem_List_INT->u1.AddressOfData;

			if (TempUnio.BitField.high == 1)
			{
				//通过序号取函数地址
				*pFuncAddr = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)TempUnio.BitField.low);
			}
			else
			{
				//通过名称取函数地址
				pFuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)LoadBaseAddress + Mem_List_INT->u1.AddressOfData);
				*pFuncAddr = (ULONG_PTR)GetProcAddress(hModule, pFuncName->Name);
				//printf("0x%llX", *pFuncAddr);
				//printf(" || %s\n", pFuncName->Name);
			}
			Mem_List_INT++;
			pFuncAddr++;
		}

		Mem_List_IID++;
	}
	return true;
}

bool MemLoadPe::RepairList_BRT()
{
	if (NeedRepairBRT == FALSE) { return true; }

	int TypeOffsetCount = 0;
	struct MyWord
	{
		WORD VA : 12;
		WORD Type : 4;
	}*pTypeOffset = NULL;
	INT_PTR Difference = (INT_PTR)((ULONG_PTR)  //差值可以为负数
		LoadBaseAddress - PeHeader->OptionalHeader.ImageBase);
	PINT_PTR RepairAddr = NULL;

	while (Mem_List_BRT->VirtualAddress != 0)
	{
		//printf("0x%08X :\n", Mem_List_BRT->VirtualAddress);

		TypeOffsetCount = (Mem_List_BRT->SizeOfBlock - 8) / 2;
		pTypeOffset = (MyWord*)((ULONG_PTR)Mem_List_BRT + 8);

		for (int i = 0; i < TypeOffsetCount; i++)
		{
			if (pTypeOffset->Type != IMAGE_REL_BASED_ABSOLUTE)
			{
				RepairAddr = (PINT_PTR)((ULONG_PTR)LoadBaseAddress +
					Mem_List_BRT->VirtualAddress + pTypeOffset->VA);
				if (*RepairAddr <= 0) { return false; }
				*RepairAddr += Difference; 
				//printf("0x%llX\n", *RepairAddr);
			}
			pTypeOffset++;
		}
		Mem_List_BRT = (PIMAGE_BASE_RELOCATION)
			((ULONG_PTR)Mem_List_BRT + Mem_List_BRT->SizeOfBlock);
	}
	
	Mem_PeHeader->OptionalHeader.ImageBase = (ULONG_PTR)LoadBaseAddress;

	return true;
}

bool MemLoadPe::RepairLdrLinks()
{
#ifdef _WIN64
	PPEB_WIN10X64 pPeb = (PPEB_WIN10X64)*(PULONGLONG)((ULONG_PTR)NtCurrentTeb() + 0x60);
#else
	PPEB_WIN10X64 pPeb = (PPEB_WIN10X64)*(PDWORD)((ULONG_PTR)NtCurrentTeb() + 0x30);
#endif 
	PPEB_LDR_DATA_WIN10X64 pLdr = (PPEB_LDR_DATA_WIN10X64)pPeb->Ldr;
	PLIST_ENTRY64 HeadNode = (PLIST_ENTRY64)pLdr->InLoadOrderModuleList.Flink;
	HeadNode = (PLIST_ENTRY64)HeadNode->Blink;
	PLIST_ENTRY64 LastNode = (PLIST_ENTRY64)HeadNode->Blink;

	printf("FirstNode = %ws\n", (PWSTR)((PLDR_DATA_TABLE_ENTRY_WIN10X64)HeadNode->Flink)->BaseDllName.Buffer);

	UNICODE_STRING64 MyBaseDllName = { 0 };
	UNICODE_STRING64 MyFullDllName = { 0 };
	PWSTR BaseDllNameSTR = new WCHAR[130];
	PWSTR FullDllNameSTR = new WCHAR[130];
	ZeroMemory(BaseDllNameSTR, sizeof(WCHAR[130]));
	ZeroMemory(FullDllNameSTR, sizeof(WCHAR[130]));
	memcpy(BaseDllNameSTR, FileName, wcslen(FileName) * 2);
	GetCurrentDirectoryW(MAX_PATH, FullDllNameSTR);
	wcscat_s(FullDllNameSTR, MAX_PATH, BaseDllNameSTR);
	printf("BaseDllName = %ws\n", BaseDllNameSTR);
	printf("FullDllName = %ws\n", FullDllNameSTR);
	InitUnicodeString(BaseDllNameSTR, &MyBaseDllName);
	InitUnicodeString(FullDllNameSTR, &MyFullDllName);

	PLDR_DATA_TABLE_ENTRY_WIN10X64 pMyLdrDataEntry = (PLDR_DATA_TABLE_ENTRY_WIN10X64)
		VirtualAlloc(NULL, sizeof(LDR_DATA_TABLE_ENTRY_WIN10X64), MEM_COMMIT, PAGE_READWRITE);
	printf("pMyLdrDataEntry = %p\n", pMyLdrDataEntry);
	ZeroMemory(pMyLdrDataEntry, sizeof(LDR_DATA_TABLE_ENTRY_WIN10X64));
	pMyLdrDataEntry->DllBase = LoadBaseAddress;
	pMyLdrDataEntry->EntryPoint = (PVOID)EntryPointer;
	pMyLdrDataEntry->SizeOfImage = PeHeader->OptionalHeader.SizeOfImage;
	pMyLdrDataEntry->BaseDllName = MyBaseDllName;
	pMyLdrDataEntry->FullDllName = MyFullDllName;
	pMyLdrDataEntry->InLoadOrderLinks.Flink = (ULONGLONG)HeadNode;
	pMyLdrDataEntry->InMemoryOrderLinks.Flink = (ULONGLONG)HeadNode + 0x10;
	pMyLdrDataEntry->InInitializationOrderLinks.Flink = (ULONGLONG)HeadNode + 0x20;
	pMyLdrDataEntry->InLoadOrderLinks.Blink = (ULONGLONG)LastNode;
	pMyLdrDataEntry->InMemoryOrderLinks.Blink = (ULONGLONG)LastNode + 0x10;
	pMyLdrDataEntry->InInitializationOrderLinks.Blink = (ULONGLONG)LastNode + 0x20;
	pMyLdrDataEntry->LoadCount = 0xffff;
	pMyLdrDataEntry->TlsIndex = 0xffff;
	
	LastNode->Flink = (ULONGLONG)pMyLdrDataEntry;
	((PLIST_ENTRY64)((ULONGLONG)LastNode + 0x10))->Flink = (ULONGLONG)pMyLdrDataEntry + 0x10;
	((PLIST_ENTRY64)((ULONGLONG)LastNode + 0x20))->Flink = (ULONGLONG)pMyLdrDataEntry + 0x20;
	
	HeadNode->Blink = (ULONGLONG)pMyLdrDataEntry;
	((PLIST_ENTRY64)((ULONGLONG)HeadNode + 0x10))->Blink = (ULONGLONG)pMyLdrDataEntry + 0x10;
	((PLIST_ENTRY64)((ULONGLONG)HeadNode + 0x20))->Blink = (ULONGLONG)pMyLdrDataEntry + 0x20;

	return false;
}

void MemLoadPe::InitUnicodeString(PCWCH String, PUNICODE_STRING64 StringObject)
{
	StringObject->Buffer = (ULONG_PTR)String;
	StringObject->Length = (USHORT)(wcslen(String) * 2);
	StringObject->MaximumLength = StringObject->Length + 2;
}

void MemLoadPe::CallEntryPoint(MemLoadPe* Object)
{
	if (Object->IsDll)
	{
		typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpReserved);
		((DllEntryProc)Object->EntryPointer)((HINSTANCE)Object->LoadBaseAddress, DLL_PROCESS_ATTACH, NULL);
	}
	else
	{
		((void(*)())(Object->EntryPointer))();
	}
}

