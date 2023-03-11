#pragma once
#include "../capstone-4.0.2-win32/include/capstone/capstone.h"
#include "../keystone-0.9.2-win32/include/keystone/keystone.h"
#include <ctime>
#include <cstdio>
#include <vector>
#include <deque>
#include <Windows.h>

using namespace std;

#define STRING_(s) #s
#define STRING(s) STRING_(s)
#define WARNING(msg)  message(__FILE__ "(" STRING(__LINE__) ") : warning: " #msg)


//控制是否进行调试输出
//#define DEBUG_OBFUSCATE

#ifdef DEBUG_OBFUSCATE
#pragma WARNING(调试已开启)
	#define DBG_PRINT(...)	printf(__VA_ARGS__)
#else
	#define DBG_PRINT(...)
#endif // DEBUG_OBFUSCATE




class obf
{
public:
	obf()
	{
		zero_member();
	}
	~obf() {}
	void zero_member();
	void update_member();
	bool init(IN char* file_path);

	bool obf_begin_set(IN DWORD start, IN DWORD end);
	void obf_end_set();
	bool obf_disasm(IN size_t virtual_address);
	bool obf_asm(IN const char* buffer);
	void update_jcc_table();

	void obf_out_of_order(IN DWORD maximum);
	void obf_jmp_label_by_retn();
	void obf_vector_jmp();
	void obf_equivalent_variation();
	void obf_local_obf();
	void obf_no_jcc();

	void obf_flatten();
	void obf_fake_jcc(IN BYTE* buffer,IN DWORD size);
	void obf_vm();
	void expand_buffer(IN OUT void*& buffer,IN OUT DWORD& size);

	bool add_section(IN const char* section_name, IN const BYTE* buffer, IN const DWORD size);
	bool save_file();
	void print_last_error_string();

	LPCSTR					m_file_path;		//文件路径
	HANDLE					m_hFile;			//PE文件句柄
	LPBYTE					m_pFileBuf;			//PE文件缓冲区
	DWORD					m_dwFileSize;		//文件大小
	DWORD					m_dwImageSize;		//镜像大小
	PIMAGE_DOS_HEADER		m_pDosHeader;		//Dos头
	PIMAGE_NT_HEADERS		m_pNtHeader;		//NT头
	PIMAGE_SECTION_HEADER	m_pSectionHeader;		//第一个SECTION结构体指针
	DWORD					m_dwImageBase;		//镜像基址
	DWORD					m_dwCodeBase;		//代码基址
	DWORD					m_dwCodeSize;		//代码大小
	DWORD					m_dwPEOEP;			//OEP地址
	DWORD					m_dwSizeOfHeader;	//文件头大小
	DWORD					m_dwSectionNum;		//区段数量

	DWORD					m_dwFileAlign;		//文件对齐
	DWORD					m_dwMemAlign;		//内存对齐

	DWORD					m_IATSectionBase;	//IAT所在段基址
	DWORD					m_IATSectionSize;	//IAT所在段大小

	IMAGE_DATA_DIRECTORY	m_PERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	m_PEImportDir;		//导入表信息

	size_t m_start;
	size_t m_end;
	size_t m_obf_entry;


	const size_t max_size=1024*1024;

	csh m_handle;							//capstone句柄
	cs_insn* m_insn;						//capstone反汇编的所有指令
	size_t m_count=0;						//指令数
	size_t m_obf_base;						//混淆代码被放在一个新节，节的virtual_address
	char* m_obf_asm_buffer;					//混淆汇编代码缓冲区
	BYTE* m_binary_buffer;					//二进制缓冲区
	size_t m_size;							//二进制缓冲区大小
	vector<size_t> m_jcc_table;				//第i条指令是否是jcc跳转，值=目标指令或者-1




	// BYTE* vm_bytes_buffer;
	// size_t vm_bytes;
	// struct handler
	// {
	// 	size_t index;
	// 	char buffer[10240];
	// };


};