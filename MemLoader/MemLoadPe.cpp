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
	Mem_List_IED = NULL;

	FileBuffer = NULL;

	LoadBaseAddress = NULL;
	EntryPointer = 0;
	IsDll = FALSE;
	NeedRepairBRT = FALSE;
	LoadStatus = FALSE;
}

MemLoadPe::~MemLoadPe()
{
	
}

BOOL MemLoadPe::MemLoadDll(PVOID FileBuffer,PHANDLE OutThreadHandle)
{
	this->FileBuffer = FileBuffer;
	if (LoadPeHeader() == false)
	{
		OutputDebugString(L"[Error]MemLoadDll.LoadPeHeader failed!");
		return FALSE;
	}
	if (LoadSectionData() == false)
	{
		OutputDebugString(L"[Error]MemLoadDll.LoadSectionData failed!");
		return FALSE;
	}
	if (RepairList_IAT() == false)
	{
		OutputDebugString(L"[Error]MemLoadDll.RepairList_IAT failed!");
		return FALSE;
	}
	if (RepairList_BRT() == false)
	{
		OutputDebugString(L"[Error]MemLoadDll.RepairList_BRT failed!");
		return FALSE;
	}
	if ((ULONG_PTR)LoadBaseAddress == EntryPointer)
	{
		//���ƫ�Ƶ���0(û����ں���)
		LoadStatus = TRUE;
		return TRUE;
	}
	if (OutThreadHandle != NULL)
	{
		//�����߳�ִ����ں���
		*OutThreadHandle = ::CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CallEntryPoint, this, 0, NULL);
		if (*OutThreadHandle != NULL) { LoadStatus = TRUE;  return TRUE; }
	}
	else
	{
		CallEntryPoint(this);
		LoadStatus = TRUE;
		return TRUE;
	}

	return FALSE;
}


bool MemLoadPe::CheckPeLegality()
{
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE || PeHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		OutputDebugString(L"This is not a PE file!");
		return false;
	}

#ifdef _WIN64
	if (PeHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		OutputDebugString(L"This is not a x64 file!");
		return false;
	}
#else
	if (PeHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		OutputDebugString(L"This is not a x32 file!");
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
		//������Ԥ���ص�ַ�����ڴ�
		LoadBaseAddress = VirtualAlloc((LPVOID)PeHeader->OptionalHeader.ImageBase, 
			PeHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (LoadBaseAddress == NULL) { return false; }
		NeedRepairBRT = FALSE; //�����޸��ض�λ
	}
	else
	{
		LoadBaseAddress = VirtualAlloc(NULL, PeHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (LoadBaseAddress == NULL) { return false; }
		NeedRepairBRT = TRUE; //��Ҫ�޸��ض�λ
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
			Copy_Length = SectionHeader->SizeOfRawData;//������VirtualSize
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
	Mem_List_IED = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)LoadBaseAddress + 
		Mem_PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
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

		hModule = LoadLibraryA(DllName);
		if (hModule == NULL)
		{
			//���ص�ģ�鲻�ڵ�ǰĿ¼��ϵͳĿ¼
			char stemp[80] = "�Ҳ���";
			strcat_s(stemp, DllName);
			strcat_s(stemp, "�ļ�!\n");
			MessageBoxA(0, stemp, "����", MB_ICONERROR);
			return false;
		}
		while (*pFuncAddr != 0)
		{
			TempUnio.Value = Mem_List_INT->u1.AddressOfData;

			if (TempUnio.BitField.high == 1)
			{
				//ͨ�����ȡ������ַ
				*pFuncAddr = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)TempUnio.BitField.low);
			}
			else
			{
				//ͨ������ȡ������ַ
				pFuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)LoadBaseAddress + Mem_List_INT->u1.AddressOfData);
				*pFuncAddr = (ULONG_PTR)GetProcAddress(hModule, pFuncName->Name);
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

	INT_PTR Difference = (INT_PTR)((ULONG_PTR)LoadBaseAddress - PeHeader->OptionalHeader.ImageBase);
	PINT_PTR RepairAddr = NULL;

	while (Mem_List_BRT->VirtualAddress != 0)
	{
		TypeOffsetCount = (Mem_List_BRT->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		pTypeOffset = (MyWord*)((ULONG_PTR)Mem_List_BRT + sizeof(IMAGE_BASE_RELOCATION));

		for (int i = 0; i < TypeOffsetCount; i++)
		{
			if (pTypeOffset->Type != IMAGE_REL_BASED_ABSOLUTE)
			{
                RepairAddr = (PINT_PTR)((ULONG_PTR)LoadBaseAddress + Mem_List_BRT->VirtualAddress + pTypeOffset->VA);
				*RepairAddr += Difference; 
			}
			pTypeOffset++;
		}
        Mem_List_BRT = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)Mem_List_BRT + Mem_List_BRT->SizeOfBlock);
	}
	
	Mem_PeHeader->OptionalHeader.ImageBase = (ULONG_PTR)LoadBaseAddress;

	return true;
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


PVOID MemLoadPe::GetExportFuncAddress(PCSTR FunctionName)
{
	if (LoadStatus == TRUE && Mem_PeHeader->OptionalHeader.DataDirectory[0].Size > 0)
	{
		PDWORD FuncNameTable = (PDWORD)((ULONG_PTR)LoadBaseAddress + Mem_List_IED->AddressOfNames);
		PDWORD FuncAddrTable = (PDWORD)((ULONG_PTR)LoadBaseAddress + Mem_List_IED->AddressOfFunctions);
        PWORD NameIndexTable = (PWORD)((ULONG_PTR)LoadBaseAddress + Mem_List_IED->AddressOfNameOrdinals);

        for (DWORD i = 0; i < Mem_List_IED->NumberOfNames; i++)
        {
            LPCSTR Name = (LPCSTR)((PUCHAR)LoadBaseAddress + FuncNameTable[i]);
            if (strcmp(FunctionName, Name) == 0)
            {
                return (PUCHAR)LoadBaseAddress + FuncAddrTable[NameIndexTable[i]];
            }
        }
	}

	return NULL;
}

/*
bool MemLoadPe::RepairLdrLinks()
{
	//*******************************************************************************************
	//��win10ϵͳ���޸�ldr_data_table_entry�ṹ����������ֱ�ӽ��MFCӦ�ó�����ڴ���س������⣬����Ҫ
	//ԭ����MFCӦ�ó���ִ�г�ʼ������ʱ��ʹ��GetModuleFileName�����������ڲ��������1��hMoudle����Ϊ����
	//��ִ��ResolveDelayLoadedAPI�������ڴ���ص�MFC�����޸���ldr���ǻ�ִ��ʧ�ܣ�ͨ��ʵ���޸�ִ�������ƹ�
	//ResolveDelayLoadedAPI��������һ��֧������������س����ˣ�����ͨ��HOOK����LdrGetDllFullName,���Ŀ
	//�������ڴ����DLL�ľ�����ƹ�ResolveDelayLoadedAPI����������⡣
	//����Ҫע���ڴ���ؼ�����Ӧ�ó���������MFC�����岻̫������Ͳ�����о���...
	//*******************************************************************************************

#ifdef _WIN64
	PPEB_WIN10X64 pPeb = (PPEB_WIN10X64)*(PULONGLONG)((ULONG_PTR)NtCurrentTeb() + 0x60);
	typedef BOOLEAN(WINAPI  *NTDLL)(OUT PUNICODE_STRING64  DestinationString, IN PCWSTR  SourceString);
#else
	PPEB_WIN10X64 pPeb = (PPEB_WIN10X64)*(PDWORD)((ULONG_PTR)NtCurrentTeb() + 0x30);
#endif
	PPEB_LDR_DATA_WIN10X64 pLdr = (PPEB_LDR_DATA_WIN10X64)pPeb->Ldr;
	PLIST_ENTRY64 HeadNode = (PLIST_ENTRY64)pLdr->InLoadOrderModuleList.Flink;
	HeadNode = (PLIST_ENTRY64)HeadNode->Blink;
	PLIST_ENTRY64 LastNode = (PLIST_ENTRY64)HeadNode->Blink;
	NTDLL RtlCreateUnicodeString = (NTDLL)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUnicodeString");

	printf("FirstNode = %ws\n", (PWSTR)((PLDR_DATA_TABLE_ENTRY_WIN10X64)HeadNode->Flink)->BaseDllName.Buffer);
	printf("LastNode = %ws\n", (PWSTR)((PLDR_DATA_TABLE_ENTRY_WIN10X64)LastNode)->BaseDllName.Buffer);

	PLDR_DATA_TABLE_ENTRY_WIN10X64 pMyLdrDataEntry = (PLDR_DATA_TABLE_ENTRY_WIN10X64)
		VirtualAlloc(NULL, sizeof(LDR_DATA_TABLE_ENTRY_WIN10X64), MEM_COMMIT, PAGE_READWRITE);
	printf("pMyLdrDataEntry = %p\n", pMyLdrDataEntry);
	pMyLdrDataEntry->DllBase = LoadBaseAddress;
	pMyLdrDataEntry->EntryPoint = NULL;
	pMyLdrDataEntry->SizeOfImage = PeHeader->OptionalHeader.SizeOfImage;
	RtlCreateUnicodeString(&pMyLdrDataEntry->BaseDllName, FileName);
	RtlCreateUnicodeString(&pMyLdrDataEntry->FullDllName, FullName);
	pMyLdrDataEntry->FlagGroup = 0x4 | 0x4000;
	pMyLdrDataEntry->LoadCount = -1;
	pMyLdrDataEntry->TlsIndex = -1;
	pMyLdrDataEntry->InLoadOrderLinks.Flink = (ULONGLONG)HeadNode;
	pMyLdrDataEntry->InLoadOrderLinks.Blink = (ULONGLONG)LastNode;
	PLDR_DDAG_NODE pDdag = (PLDR_DDAG_NODE)VirtualAlloc(NULL, sizeof(LDR_DDAG_NODE), MEM_COMMIT, PAGE_READWRITE);
	pDdag->Modules.Flink = (ULONGLONG)pDdag;
	pDdag->Modules.Blink = (ULONGLONG)pDdag;
	pMyLdrDataEntry->DdagNode = pDdag; //�ṹ�嵱�б�����������Ȼ�����������ƻ�����ṹ

	LastNode->Flink = (ULONGLONG)pMyLdrDataEntry;
	HeadNode->Blink = (ULONGLONG)pMyLdrDataEntry;
	system("pause");
	return false;
}
*/