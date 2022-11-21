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
	bool CheckPeLegality(); //检查PE格式
	bool LoadPeHeader();    //加载PE头
	bool LoadSectionData(); //加载区段
	bool RepairList_IAT();  //修复导入地址表
	bool RepairList_BRT();  //修复基址重定位

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
1、解析PE文件头
2、申请SizeOfImage大小的PAGE_EXECUTE_READWRITE内存
3、将解析结果填充到内存对应的位置
4、修复导入地址表
5、修复基址重定位表
6、执行入口函数dllmain()
   注意MFCDLL需要修复PEB中的双向链表！！！！
   注意内存加载成功后自退出会导致母进程退出！
   留意创建线程执行加载时，加载程序退出后母体是否会结束
   封装时可以加入异常处理功能

***************************************************/