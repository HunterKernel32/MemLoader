#pragma once

class MemLoadPe
{
public:
	MemLoadPe();
	~MemLoadPe();
public:
	HANDLE MemLoadDll(PVOID FileBuffer);
	ULONG_PTR EntryPointer;
	PVOID LoadBaseAddress;
	BOOL IsDll;

private:
	bool CheckPeLegality(); //���PE��ʽ
	bool LoadPeHeader();    //����PEͷ
	bool LoadSectionData(); //��������
	bool RepairList_IAT();  //�޸������ַ��
	bool RepairList_BRT();  //�޸���ַ�ض�λ

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