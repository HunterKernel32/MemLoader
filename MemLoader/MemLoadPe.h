#pragma once

/*****************************************/
typedef struct _STRING64 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONGLONG  Buffer;
} STRING64;
typedef STRING64 *PSTRING64;

typedef STRING64 UNICODE_STRING64;
typedef UNICODE_STRING64 *PUNICODE_STRING64;

/*****************************************/

class MemLoadPe
{
public:
	MemLoadPe();
	~MemLoadPe();
public:
	HANDLE MemLoadDll(PVOID FileBuffer, PCWCH FileName);
	ULONG_PTR EntryPointer;
	PVOID LoadBaseAddress;
	BOOL IsDll;

private:
	bool CheckPeLegality(); //���PE��ʽ
	bool LoadPeHeader();    //����PEͷ
	bool LoadSectionData(); //��������
	bool RepairList_IAT();  //�޸������ַ��
	bool RepairList_BRT();  //�޸���ַ�ض�λ
	bool RepairLdrLinks();  //�޸�LDR����

	static void InitUnicodeString(PCWCH String, PUNICODE_STRING64 StringObject);
	static void CallEntryPoint(MemLoadPe* Object);

private:
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS PeHeader;
	PIMAGE_SECTION_HEADER SectionHeader;

	PIMAGE_NT_HEADERS Mem_PeHeader;
	PIMAGE_IMPORT_DESCRIPTOR Mem_List_IID;
	PIMAGE_THUNK_DATA Mem_List_INT;
	PIMAGE_BASE_RELOCATION Mem_List_BRT;

	PVOID FileBuffer;
	BOOL NeedRepairBRT;
	PCWCH FileName;
};


union FileCharacteristics
{
	struct
	{
		WORD NoRelocation : 1;
		WORD IsExecutable : 1;
		WORD NoLineNumber : 1;
		WORD NoSymbolMsg : 1;
		WORD Aggressively : 1;
		WORD Is_x64Target : 1;
		WORD Unknown : 1;
		WORD ReverseLowByte : 1;
		WORD Is_x32Target : 1;
		WORD NoDebuggingMsg : 1;
		WORD RemovableMedia : 1;
		WORD NetworkMedia : 1;
		WORD IsSystemFile : 1;
		WORD IsDllFile : 1;
		WORD SingleProcessor : 1;
		WORD ReverseHighByte : 1;
	}BitField;
	WORD Value;
};

/************* ��������Windows10 x64ϵͳ **************/

typedef struct _PEB_WIN10X64 {
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	BYTE BitField;
	BYTE Padding0[4];
	PVOID64 Mutant;
	PVOID64 ImageBaseAddress;
	PVOID64 Ldr;
	PVOID64 ProcessParameters;
} PEB_WIN10X64, *PPEB_WIN10X64;

typedef struct _PEB_LDR_DATA_WIN10X64 {
	DWORD Length;
	BYTE Initialized;
	PVOID64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
}PEB_LDR_DATA_WIN10X64, *PPEB_LDR_DATA_WIN10X64;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN10X64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	PVOID64 DllBase;
	PVOID64 EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	DWORD FlagGroup;
	WORD LoadCount;
	WORD TlsIndex;
	BYTE Unknown[176];
}LDR_DATA_TABLE_ENTRY_WIN10X64, *PLDR_DATA_TABLE_ENTRY_WIN10X64;

typedef struct _CURDIR
{
	UNICODE_STRING64 DosPath;
	PVOID64 Handle;
}CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_WIN10X64
{
	DWORD MaximumLength;
	DWORD Length;
	DWORD Flags;
	DWORD DebugFlags;
	PVOID64 ConsoleHandle;
	DWORD ConsoleFlags;
	PVOID64 StandardInput;
	PVOID64 StandardOutput;
	PVOID64 StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING64 DllPath;
	UNICODE_STRING64 ImagePathName;
	UNICODE_STRING64 CommandLine;
	BYTE Unknown[48];
	UNICODE_STRING64 WindowTitle;
	UNICODE_STRING64 DesktopInfo;
	UNICODE_STRING64 ShellInfo;
	UNICODE_STRING64 RuntimeData;
}RTL_USER_PROCESS_PARAMETERS_WIN10X64, *PRTL_USER_PROCESS_PARAMETERS_WIN10X64;



/***************************************************
1������PE�ļ�ͷ
2������SizeOfImage��С��PAGE_EXECUTE_READWRITE�ڴ�
3�������������䵽�ڴ��Ӧ��λ��
4���޸������ַ��
5���޸���ַ�ض�λ��
6��ִ����ں���dllmain()
   ע��MFCDLL��Ҫ�޸�PEB�е�˫������������
   ע���ڴ���سɹ������˳��ᵼ��ĸ�����˳���
   ���ⴴ���߳�ִ�м���ʱ�����س����˳���ĸ���Ƿ�����
   ��װʱ���Լ����쳣������

***************************************************/