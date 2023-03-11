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


//�����Ƿ���е������
//#define DEBUG_OBFUSCATE

#ifdef DEBUG_OBFUSCATE
#pragma WARNING(�����ѿ���)
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

	LPCSTR					m_file_path;		//�ļ�·��
	HANDLE					m_hFile;			//PE�ļ����
	LPBYTE					m_pFileBuf;			//PE�ļ�������
	DWORD					m_dwFileSize;		//�ļ���С
	DWORD					m_dwImageSize;		//�����С
	PIMAGE_DOS_HEADER		m_pDosHeader;		//Dosͷ
	PIMAGE_NT_HEADERS		m_pNtHeader;		//NTͷ
	PIMAGE_SECTION_HEADER	m_pSectionHeader;		//��һ��SECTION�ṹ��ָ��
	DWORD					m_dwImageBase;		//�����ַ
	DWORD					m_dwCodeBase;		//�����ַ
	DWORD					m_dwCodeSize;		//�����С
	DWORD					m_dwPEOEP;			//OEP��ַ
	DWORD					m_dwSizeOfHeader;	//�ļ�ͷ��С
	DWORD					m_dwSectionNum;		//��������

	DWORD					m_dwFileAlign;		//�ļ�����
	DWORD					m_dwMemAlign;		//�ڴ����

	DWORD					m_IATSectionBase;	//IAT���ڶλ�ַ
	DWORD					m_IATSectionSize;	//IAT���ڶδ�С

	IMAGE_DATA_DIRECTORY	m_PERelocDir;		//�ض�λ����Ϣ
	IMAGE_DATA_DIRECTORY	m_PEImportDir;		//�������Ϣ

	size_t m_start;
	size_t m_end;
	size_t m_obf_entry;


	const size_t max_size=1024*1024;

	csh m_handle;							//capstone���
	cs_insn* m_insn;						//capstone����������ָ��
	size_t m_count=0;						//ָ����
	size_t m_obf_base;						//�������뱻����һ���½ڣ��ڵ�virtual_address
	char* m_obf_asm_buffer;					//���������뻺����
	BYTE* m_binary_buffer;					//�����ƻ�����
	size_t m_size;							//�����ƻ�������С
	vector<size_t> m_jcc_table;				//��i��ָ���Ƿ���jcc��ת��ֵ=Ŀ��ָ�����-1




	// BYTE* vm_bytes_buffer;
	// size_t vm_bytes;
	// struct handler
	// {
	// 	size_t index;
	// 	char buffer[10240];
	// };


};