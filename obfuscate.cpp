#include "obfuscate.h"

#include <regex>
#include <string>
#include <Shlwapi.h>
#include <Windows.h>

#pragma comment(lib,"shlwapi.lib")




const char* rand_x32_reg()
{
	switch (rand() % 8)
	{
	case 0:
		return "eax";
	case 1:
		return "ebx";
	case 2:
		return "ecx";
	case 3:
		return "edx";
	case 4:
		return "esi";
	case 5:
		return "edi";
	case 6:
		return "ebp";
	case 7:
		return "esp";
	default:
		return "";
	}
}


const char* rand_x16_reg()
{

	switch (rand() % 8)
	{
	case 0:
		return "ax";
	case 1:
		return "bx";
	case 2:
		return "cx";
	case 3:
		return "dx";
	case 4:
		return "si";
	case 5:
		return "di";
	case 6:
		return "bp";
	case 7:
		return "sp";
	default:
		return "";
	}


}
const char* rand_x8_reg()
{
	//if (x16_reg == nullptr)
	{
		switch (rand() % 8)
		{
		case 0:
			return "al";
		case 1:
			return "bl";
		case 2:
			return "cl";
		case 3:
			return "dl";
		case 4:
			return "ah";
		case 5:
			return "bh";
		case 6:
			return "ch";
		case 7:
			return "dh";
		default:
			return "";
		}
	}
}

const char* rand_flag_insn()
{
	switch (rand() % 5)
	{
	case 0:
		return "clc";
	case 1:
		return "stc";
	case 2:
		return "cmc";
		// case 3:
		// 	return "cld";
		// case 4:
		// 	return "std";
	default:
		return "clc";
	}
};


bool is_x32_reg(const char* s)
{
	if (strcmp(s, "eax") == 0)
	{
		return true;
	}
	else if (strcmp(s, "ebx") == 0)
	{
		return true;
	}
	else if (strcmp(s, "ecx") == 0)
	{
		return true;
	}
	else if (strcmp(s, "edx") == 0)
	{
		return true;
	}
	else if (strcmp(s, "esi") == 0)
	{
		return true;
	}
	else if (strcmp(s, "edi") == 0)
	{
		return true;
	}
	else if (strcmp(s, "ebp") == 0)
	{
		return true;
	}
	else if (strcmp(s, "esp") == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}
bool is_x16_reg(const char* s)
{
	if (strcmp(s, "ax") == 0)
	{
		return true;
	}
	else if (strcmp(s, "bx") == 0)
	{
		return true;
	}
	else if (strcmp(s, "cx") == 0)
	{
		return true;
	}
	else if (strcmp(s, "dx") == 0)
	{
		return true;
	}
	else if (strcmp(s, "si") == 0)
	{
		return true;
	}
	else if (strcmp(s, "di") == 0)
	{
		return true;
	}
	else if (strcmp(s, "bp") == 0)
	{
		return true;
	}
	else if (strcmp(s, "sp") == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}
bool is_x8_reg(const char* s)
{
	if (strcmp(s, "al") == 0)
	{
		return true;
	}
	else if (strcmp(s, "bl") == 0)
	{
		return true;
	}
	else if (strcmp(s, "cl") == 0)
	{
		return true;
	}
	else if (strcmp(s, "dl") == 0)
	{
		return true;
	}
	else if (strcmp(s, "ah") == 0)
	{
		return true;
	}
	else if (strcmp(s, "bh") == 0)
	{
		return true;
	}
	else if (strcmp(s, "ch") == 0)
	{
		return true;
	}
	else if (strcmp(s, "dh") == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

const char* to_x32_reg(const char* s)
{

	if (strcmp(s, "ax") == 0)
	{
		return "eax";
	}
	else if (strcmp(s, "bx") == 0)
	{
		return "ebx";
	}
	else if (strcmp(s, "cx") == 0)
	{
		return "ecx";
	}
	else if (strcmp(s, "dx") == 0)
	{
		return "edx";
	}
	else if (strcmp(s, "si") == 0)
	{
		return "esi";
	}
	else if (strcmp(s, "di") == 0)
	{
		return "edi";
	}
	else if (strcmp(s, "bp") == 0)
	{
		return "ebp";
	}
	else if (strcmp(s, "sp") == 0)
	{
		return "esp";
	}

	else if (strcmp(s, "al") == 0)
	{
		return "eax";
	}
	else if (strcmp(s, "bl") == 0)
	{
		return "ebx";
	}
	else if (strcmp(s, "cl") == 0)
	{
		return "ecx";
	}
	else if (strcmp(s, "dl") == 0)
	{
		return "edx";
	}
	else if (strcmp(s, "ah") == 0)
	{
		return "eax";
	}
	else if (strcmp(s, "bh") == 0)
	{
		return "ebx";
	}
	else if (strcmp(s, "ch") == 0)
	{
		return "ecx";
	}
	else if (strcmp(s, "dh") == 0)
	{
		return "edx";
	}
	else
	{
		DBG_PRINT("Error to x32_reg");
	}
}

const char* to_x16_reg(const char* s)
{
	if (strcmp(s, "eax") == 0)
	{
		return "ax";
	}
	else if (strcmp(s, "ebx") == 0)
	{
		return "bx";
	}
	else if (strcmp(s, "ecx") == 0)
	{
		return "cx";
	}
	else if (strcmp(s, "edx") == 0)
	{
		return "dx";
	}
	else if (strcmp(s, "esi") == 0)
	{
		return "si";
	}
	else if (strcmp(s, "edi") == 0)
	{
		return "di";
	}
	else if (strcmp(s, "ebp") == 0)
	{
		return "bp";
	}
	else if (strcmp(s, "esp") == 0)
	{
		return "sp";
	}
	else if (strcmp(s, "al") == 0)
	{
		return "ax";
	}
	else if (strcmp(s, "bl") == 0)
	{
		return "bx";
	}
	else if (strcmp(s, "cl") == 0)
	{
		return "cx";
	}
	else if (strcmp(s, "dl") == 0)
	{
		return "dx";
	}
	else if (strcmp(s, "ah") == 0)
	{
		return "ax";
	}
	else if (strcmp(s, "bh") == 0)
	{
		return "bx";
	}
	else if (strcmp(s, "ch") == 0)
	{
		return "cx";
	}
	else if (strcmp(s, "dh") == 0)
	{
		return "dx";
	}
	else
	{
		DBG_PRINT("Error to x16_reg");
	}
}


const char* to_x8_reg(const char* s, const bool& is_low)
{
	if (strcmp(s, "eax") == 0)
	{
		if (is_low)
		{
			return "al";
		}
		else
		{
			return "ah";
		}
	}
	else if (strcmp(s, "ebx") == 0)
	{
		if (is_low)
		{
			return "bl";
		}
		else
		{
			return "bh";
		}
	}
	else if (strcmp(s, "ecx") == 0)
	{
		if (is_low)
		{
			return "cl";
		}
		else
		{
			return "ch";
		}
	}
	else if (strcmp(s, "edx") == 0)
	{
		if (is_low)
		{
			return "dl";
		}
		else
		{
			return "dh";
		}
	}
	else if (strcmp(s, "esi") == 0)
	{
		return "si";
	}
	else if (strcmp(s, "edi") == 0)
	{
		return "di";
	}
	else if (strcmp(s, "ebp") == 0)
	{
		return "bp";
	}
	else if (strcmp(s, "esp") == 0)
	{
		return "sp";
	}
	else if (strcmp(s, "ax") == 0)
	{
		if (is_low)
		{
			return "al";
		}
		else
		{
			return "ah";
		}
	}
	else if (strcmp(s, "bx") == 0)
	{
		if (is_low)
		{
			return "bl";
		}
		else
		{
			return "bh";
		}
	}
	else if (strcmp(s, "cx") == 0)
	{
		if (is_low)
		{
			return "cl";
		}
		else
		{
			return "ch";
		}
	}
	else if (strcmp(s, "dx") == 0)
	{
		if (is_low)
		{
			return "dl";
		}
		else
		{
			return "dh";
		}
	}
	else if (strcmp(s, "si") == 0)
	{
		DBG_PRINT("Error to x8_reg");
	}

}


//----------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------

/**
 * \brief 清空所有成员变量
 */
void obf::zero_member()
{
	m_file_path = NULL;
	m_hFile = NULL;
	m_pFileBuf = NULL;
	m_pDosHeader = NULL;
	m_pNtHeader = NULL;
	m_pSectionHeader = NULL;
	m_dwFileSize = 0;
	m_dwImageSize = 0;
	m_dwImageBase = 0;
	m_dwCodeBase = 0;
	m_dwCodeSize = 0;
	m_dwPEOEP = 0;

	m_dwSizeOfHeader = 0;
	m_dwSectionNum = 0;
	m_dwFileAlign = 0;
	m_dwMemAlign = 0;
	m_PERelocDir = { 0 };
	m_PEImportDir = { 0 };
	m_IATSectionBase = 0;
	m_IATSectionSize = 0;


}



/**
 * \brief 获取PE信息，更新成员变量
 */
void obf::update_member()
{
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	m_dwImageSize = m_pNtHeader->OptionalHeader.SizeOfImage;
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	m_dwFileAlign = m_pNtHeader->OptionalHeader.FileAlignment;
	m_dwMemAlign = m_pNtHeader->OptionalHeader.SectionAlignment;
	m_dwImageBase = m_pNtHeader->OptionalHeader.ImageBase;
	m_dwPEOEP = m_pNtHeader->OptionalHeader.AddressOfEntryPoint;
	m_dwCodeBase = m_pNtHeader->OptionalHeader.BaseOfCode;
	m_dwCodeSize = m_pNtHeader->OptionalHeader.SizeOfCode;
	m_dwSizeOfHeader = m_pNtHeader->OptionalHeader.SizeOfHeaders;
	m_dwSectionNum = m_pNtHeader->FileHeader.NumberOfSections;
	m_pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	//保存重定位目录信息
	m_PERelocDir = IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	//保存IAT信息目录信息
	m_PEImportDir = IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	//获取IAT所在的区段的起始位置和大小
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		if (m_PEImportDir.VirtualAddress >= pSectionHeader->VirtualAddress &&
			m_PEImportDir.VirtualAddress <= pSectionHeader[1].VirtualAddress)
		{
			//保存该区段的起始地址和大小
			m_IATSectionBase = pSectionHeader->VirtualAddress;
			m_IATSectionSize = pSectionHeader[1].VirtualAddress - pSectionHeader->VirtualAddress;
			break;
		}
	}
}


/**
 * \brief 初始化函数
 * \param file_path [in]文件路径
 * \return 如果成功返回真，否则返回假
 */
bool obf::init(IN char* file_path)
{
	zero_member();
	m_file_path = file_path;
	//打开文件
	m_hFile = CreateFileA(file_path,
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (m_hFile == INVALID_HANDLE_VALUE)
	{
		//加载文件失败
		m_hFile = NULL;
		return FALSE;
	}

	//将PE以文件分布格式读取到内存
	m_dwFileSize = GetFileSize(m_hFile, NULL);
	m_pFileBuf = new BYTE[m_dwFileSize];
	DWORD ReadSize = 0;
	ReadFile(m_hFile, m_pFileBuf, m_dwFileSize, &ReadSize, NULL);
	CloseHandle(m_hFile);
	m_hFile = NULL;

	//判断是否为PE文件
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//不是有效的PE文件！原因：文件不以MZ开头
		delete[] m_pFileBuf;
		return FALSE;
	}
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	if (m_pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		//不是有效的PE文件！原因：PE文件签名e_lfanew不为PE00
		delete[] m_pFileBuf;
		return FALSE;
	}

	update_member();

	//-------------------计算新增加节的virtual_address--------------------------

	PIMAGE_SECTION_HEADER pLastSection = &m_pSectionHeader[m_pNtHeader->FileHeader.NumberOfSections - 1];
	//判断PE头是否有足够的空间添加新的区段
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)m_pNtHeader) + 0x4);	//标准PE头
	//条件：SizeOfHeader - (DOS + 垃圾数据 + PE标记 + 标准PE头 + 可选PE头 + 已存在节表) >= 2个节表的大小 （如果只有一个节表以上的空间也可以加不会报错，但是会有安全隐患）
	DWORD rest_size = m_pNtHeader->OptionalHeader.SizeOfHeaders - (m_pDosHeader->e_lfanew + sizeof(m_pNtHeader->Signature) + sizeof(m_pNtHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((m_pNtHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER)));
	if (rest_size < sizeof(IMAGE_SECTION_HEADER))
	{
		//数据缓冲区太小无法添加节表！
		return false;
	}
	//VOffset(1000对齐)
	DWORD tmp = (pLastSection->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
	if (pLastSection->Misc.VirtualSize % m_dwMemAlign)
	{
		tmp += m_dwMemAlign;
	}
	m_obf_base = m_dwImageBase + pLastSection->VirtualAddress + tmp;


	return TRUE;
}



/**
 * \brief 初始化，地址左闭右开
 * \param start 混淆开始的地址
 * \param end 混淆结束的地址
 */
bool obf::obf_begin_set(IN DWORD start, IN DWORD end)
{
	m_start = start;
	m_end = end;
	m_size = end - start;
	if (end < start)
	{
		//输入有误，end不应该小于start
		return false;
	}
	if (m_size < 1 + sizeof(size_t))
	{
		//区间太小
		return false;
	}
	m_binary_buffer = new BYTE[m_size];	//存放指定代码片段的二进制
	memset(m_binary_buffer, 0, m_size);
	//查找指定代码的位置（文件分布）
	PIMAGE_SECTION_HEADER section_code = m_pSectionHeader;
	DWORD i = 0;
	for (i = 1; i <= m_dwSectionNum; i++)
	{
		if (m_dwImageBase + section_code->VirtualAddress <= start &&
			end <= m_dwImageBase + section_code->VirtualAddress + section_code->SizeOfRawData
			)
		{
			break;
		}
		else section_code++;
	}
	//判断是否找到代码所在的节
	if (i == m_dwSectionNum + 1) return false;


	//指定代码段在文件中相对于代码节数据开头的偏移=在内存中相对于代码节数据开头的偏移
	//计算出在内存中的偏移，再加上code_base即为指定代码段在文件中的位置
	BYTE* code_base = m_pFileBuf + section_code->PointerToRawData;
	DWORD offset = start - m_dwImageBase - section_code->VirtualAddress;
	memcpy_s(m_binary_buffer, m_size, code_base + offset, m_size);

	//反汇编
	obf_disasm(start);

	//初始化混淆反汇编指令
	const size_t max_size = 1024 * 1024;
	if (m_obf_asm_buffer != NULL)
	{
		delete[] m_obf_asm_buffer;
		m_obf_asm_buffer = NULL;
	}
	m_obf_asm_buffer = new char[max_size];
	memset(m_obf_asm_buffer, 0, max_size);


	//-----------给每个指令添加标签，将jcc imm指令转换为jcc label--------------
	//生成跳转表
	m_jcc_table.clear();
	for (size_t i = 0; i < m_count; i++)
	{
		//判断是否是jcc imm
		if (
			cs_insn_group(m_handle, &m_insn[i], CS_GRP_JUMP) &&
			m_insn[i].detail->x86.operands[0].type == X86_OP_IMM

			)
		{
			//如果是，寻找跳转到的目标指令，和他的label
			size_t target_address = 0;
			sscanf_s(m_insn[i].op_str, "%x", &target_address);

			for (size_t j = 0; j < m_count; j++)
			{
				if (target_address == m_insn[j].address)
				{
					m_jcc_table.push_back(j);
					goto find_next;
				}
			}
			//没找到，这可能是个跨函数跳转
			DBG_PRINT("fail to find jcc target\n");
		}
		m_jcc_table.push_back(-1);
	find_next:;
	}

	//给每一行增加label，修复jcc
	for (i = 0; i < m_count; i++)
	{
		char tmp[200] = {};
		if (m_jcc_table[i] != -1)
		{
			sprintf_s(tmp, 200, "label%d: %s label%d\n", i, m_insn[i].mnemonic, m_jcc_table[i]);
			strcat_s(m_obf_asm_buffer, max_size, tmp);
		}
		else
		{
			sprintf_s(tmp, 200, "label%d: %s %s\n", i, m_insn[i].mnemonic, m_insn[i].op_str);
			strcat_s(m_obf_asm_buffer, max_size, tmp);
		}
		//如果当前代码是最后一句代码，附加一行jmp到end地址
		if (i == m_count - 1)
		{
			strcat_s(m_obf_asm_buffer, max_size, "jmp 0x");
			char tmp[20] = {};
			_itoa_s(m_end, tmp, 20, 16);
			strcat_s(m_obf_asm_buffer, max_size, tmp);
			strcat_s(m_obf_asm_buffer, max_size, "\n");
		}
	}
	return true;
}

void obf::obf_end_set()
{
	//清空start到end的代码

	//查找指定代码的位置（文件分布）
	PIMAGE_SECTION_HEADER section_code = m_pSectionHeader;
	DWORD i = 0;
	for (i = 1; i <= m_dwSectionNum; i++)
	{
		if (m_dwImageBase + section_code->VirtualAddress <= m_start &&
			m_end <= m_dwImageBase + section_code->VirtualAddress + section_code->SizeOfRawData
			)
		{
			break;
		}
		else section_code++;
	}
	//判断是否找到代码所在的节
	if (i == m_dwSectionNum + 1) {
		DBG_PRINT("obf_end_set fail!\n");
		return;
	}

	//指定代码段在文件中相对于代码节数据开头的偏移=在内存中相对于代码节数据开头的偏移
	//计算出在内存中的偏移，再加上code_base即为指定代码段在文件中的位置
	BYTE* code_base = m_pFileBuf + section_code->PointerToRawData;
	DWORD offset = m_start - m_dwImageBase - section_code->VirtualAddress;
	for (size_t i = 0; i < m_end - m_start; i++)
	{
		code_base[offset + i] = rand() % 0xFF;
	}
	code_base[offset] = 0xE9;
	*(DWORD*)(code_base + offset + 1) = m_obf_entry - m_start - 5;
	return;
}









bool obf::obf_disasm(IN size_t virtual_address)
{
	//初始化
	if (m_insn != NULL)
	{
		cs_free(m_insn, m_count);
		m_insn = NULL;
	}
	m_count = 0;

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &m_handle) != CS_ERR_OK) return false;
	cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
	m_count = cs_disasm(m_handle, m_binary_buffer, m_size, virtual_address, 0, &m_insn);
	if (m_count > 0) {
		size_t j;
		for (j = 0; j < m_count; j++) {
			DBG_PRINT("0x%08llX\t%s\t%s\n", m_insn[j].address, m_insn[j].mnemonic, m_insn[j].op_str);
			//保存反汇编结果

			//m_vec_insn.push_back(m_insn[j]);
			// char tmp[100]={};
			// sprintf_s(tmp,"%s %s",insn[j].mnemonic,insn[j].op_str);
			// strcat_s(buffer_disasm,strlen(insn[j].mnemonic)+strlen(insn[j].op_str)+1,tmp);

		}
		//cs_free(insn, m_insn_count);//记得free)
	}
	else {
		DBG_PRINT("ERROR: Failed to disassemble given code!\n");
		cs_close(&m_handle);
		return false;
	}
	//cs_close(&m_handle);//(记得关)
	return true;
}



void obf::obf_equivalent_variation()
{
	update_jcc_table();
	size_t i = 0, j = 0;
	size_t tot = 0;	//增加的指令数

	//初始化
	char* new_asm_buffer = new char[max_size];
	memset(new_asm_buffer, 0, max_size);
	char* new_insn = new char[max_size];
	char* p1 = m_obf_asm_buffer;


	//设置入口点混淆基址
	//在m_obf_asm_buffer字符串开头插入jmp label0
	tot++;
	sprintf_s(new_asm_buffer, max_size, "label%d: jmp label0\n", m_count + tot);
	m_obf_entry = m_obf_base;


	for (i = 0; i < m_count; ++i)
	{
		char* p2 = strchr(p1, '\n');

		//混淆jmp imm;
		if (strcmp(m_insn[i].mnemonic, "jmp") == 0 &&
			m_insn[i].detail->x86.operands[0].type == X86_OP_IMM &&
			m_jcc_table[i] == -1
			)
		{
			//读取当前行指令
			char label[32] = {};
			char jcc[32] = {};
			char target[32] = {};
			sscanf_s(p1, "%s %s %s\n", label, 32, jcc, 32, target, 32);
			//初始化混淆指令
			int rnd;					//随机数
			char rnd_reg[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);
			//开始混淆
			size_t rules = 1;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
				//push imm
				//ret
				sprintf_s(tmp, sizeof(tmp), " push %s\n", target);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			default:
				DBG_PRINT("obf_equivalent_variation error jmp imm\n");
			}

			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		//混淆 push imm
		else if (strcmp(m_insn[i].mnemonic, "push") == 0 &&
			m_insn[i].detail->x86.operands[0].type == X86_OP_IMM
			)
		{
			//读取当前行指令
			char label[32] = {};
			char prefix[32] = {};
			size_t imm = 0;
			sscanf_s(p1, "%s %s %x\n", label, 32, prefix, 32, &imm);
			//初始化混淆指令
			int rnd;					//随机数
			char rnd_reg[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);
			//开始混淆
			size_t rules = 11;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
				//push imm^rand
				//xor [esp], rand
				rnd = rand() * rand();
				imm ^= rnd;
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xor dword ptr [esp], %#x\n", m_count + tot, rnd);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 2:
				//push imm+rand
				//sub [esp], rand
				rnd = rand() * rand();
				imm += rnd;
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sub dword ptr [esp], %#x\n", m_count + tot, rnd);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 3:
				//push imm-rand
				//add [esp], rand
				rnd = rand() * rand();
				imm -= rnd;
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: add dword ptr [esp], %#x\n", m_count + tot, rnd);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 4:
				//push (imm循环左移n)	(1<=n<=0xff)
				//ror [esp], n
				rnd = rand() % 0xff + 1;
				imm = (imm << rnd) | (imm >> (32 - rnd));
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ror dword ptr [esp], %#x\n", m_count + tot, rnd);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 5:
				//push (imm循环右移n)	(1<=n<=0xff)
				//rol [esp], n
				rnd = rand() % 0xff + 1;
				imm = (imm >> rnd) | (imm << (32 - rnd));
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: rol dword ptr [esp], %#x\n", m_count + tot, rnd);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 6:
				//push imm | rand
				//and [esp], imm
				rnd = rand() * rand();
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm | rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and dword ptr [esp], %#x\n", m_count + tot, imm);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 7:
				//push imm & rand
				//or [esp], imm
				rnd = rand() * rand();
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm & rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: or dword ptr [esp], %#x\n", m_count + tot, imm);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 8:
				//push imm-1
				//inc [esp]
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm - 1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: inc dword ptr [esp]\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 9:
				//push imm+1
				//dec [esp]
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", imm + 1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: dec dword ptr [esp]\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 10:
				//enc = imm%0x10000==0x0 ? imm+0xffff : imm-0x1;
				//push rand
				//mov [esp], reg
				//mov reg, enc
				//inc x16 reg
				//xchg reg, [esp]
				strcpy_s(rnd_reg, sizeof(rnd_reg), rand_x32_reg());
				while (strcmp(rnd_reg, "esp") == 0)
				{
					strcpy_s(rnd_reg, sizeof(rnd_reg), rand_x32_reg());
				}
				rnd = rand() * rand();
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], %s\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov %s, %#x\n", m_count + tot, rnd_reg, imm % 0x10000 == 0x0 ? imm + 0xffff : imm - 0x1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: inc %s\n", m_count + tot, to_x16_reg(rnd_reg));
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp]\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 11:
				//enc = imm%0x10000==0xffff ? imm-0xffff : imm+0x1;
				//push rand
				//mov [esp], reg
				//mov reg, enc
				//dec x16 reg
				//xchg reg, [esp]
				strcpy_s(rnd_reg, sizeof(rnd_reg), rand_x32_reg());
				while (strcmp(rnd_reg, "esp") == 0)
				{
					strcpy_s(rnd_reg, sizeof(rnd_reg), rand_x32_reg());
				}
				rnd = rand() * rand();
				sprintf_s(tmp, sizeof(tmp), " push %#x\n", rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], %s\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov %s, %#x\n", m_count + tot, rnd_reg, imm % 0x10000 == 0xffff ? imm - 0xffff : imm + 0x1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: dec %s\n", m_count + tot, to_x16_reg(rnd_reg));
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp]\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				break;
			default:
				DBG_PRINT("obf_equivalent_variation error push imm\n");
			}

			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		//混淆push mem
		else if (strcmp(m_insn[i].mnemonic, "push") == 0 &&
			(m_insn[i].detail->x86.operands[0].type == X86_OP_MEM)
			)
		{
			//读取当前行指令
			char label[32] = {};
			sscanf_s(p1, "%s\n", label, 32);
			//初始化混淆指令
			int rnd;					//随机数
			char rnd_reg[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);
			//开始混淆
			size_t rules = 1;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
				//push reg
				//mov reg, target
				//push reg
				//xchg reg, [esp+4]
				//pop dword ptr [esp]
				strcpy_s(rnd_reg, sizeof(rnd_reg), rand_x32_reg());
				while (strcmp(rnd_reg, "esp") == 0)
				{
					strcpy_s(rnd_reg, sizeof(rnd_reg), rand_x32_reg());
				}
				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov %s, %s\n", m_count + tot, rnd_reg, m_insn[i].op_str);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 4]\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop dword ptr [esp]\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				break;
			default:
				DBG_PRINT("obf_equivalent_variation error push mem\n");
			}

			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		//混淆push reg
		else if (strcmp(m_insn[i].mnemonic, "push") == 0 &&
			m_insn[i].detail->x86.operands[0].type == X86_OP_REG &&
			strcmp(m_insn[i].op_str, "esp") != 0 && strcmp(m_insn[i].op_str, "sp") != 0
			)
		{


			//读取当前行指令
			char label[32] = {};
			sscanf_s(p1, "%s\n", label, 32);
			//初始化混淆指令
			int rnd;					//随机数
			char rnd_reg[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);
			//开始混淆
			size_t rules = 4;		//规则数
		begin_push_reg:
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
				//lea esp, [esp - 4]
				//mov [esp], reg
				sprintf_s(tmp, sizeof(tmp), " lea esp, [esp - 4]\n");
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], %s\n", m_count + tot, m_insn[i].op_str);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 2:
				//lea esp, [esp - 4]
				//push reg
				//pop [esp]
				sprintf_s(tmp, sizeof(tmp), " lea esp, [esp - 4]\n");
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, m_insn[i].op_str);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop dword ptr [esp]\n", m_count + tot, m_insn[i].op_str);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 3:
				//lea reg, [reg + rnd]
				//push reg
				//pushfd
				//sub [esp + 4], rnd
				//popfd
				if (!is_x32_reg(m_insn[i].op_str))
				{
					goto begin_push_reg;
				}
				rnd = rand() * rand();
				sprintf_s(tmp, sizeof(tmp), " lea %s, dword ptr [%s + %#x]\n", m_insn[i].op_str, m_insn[i].op_str, rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, m_insn[i].op_str);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sub dword ptr [esp + 0x4], %#x\n", m_count + tot, rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: popfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 4:
				//lea reg, [reg - rnd]
				//push reg
				//pushfd
				//add [esp + 4], rnd
				//popfd
				if (!is_x32_reg(m_insn[i].op_str))
				{
					goto begin_push_reg;
				}
				rnd = rand() * rand();
				sprintf_s(tmp, sizeof(tmp), " lea %s, dword ptr [%s - %#x]\n", m_insn[i].op_str, m_insn[i].op_str, rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, m_insn[i].op_str);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: add dword ptr [esp + 0x4], %#x\n", m_count + tot, rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: popfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			default:
				DBG_PRINT("obf_equivalent_variation error push mem\n");
			}
			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		//混淆call
		else if (strcmp(m_insn[i].mnemonic, "call") == 0
			)
		{
			//读取当前行指令
			char label[32] = {};
			sscanf_s(p1, "%s\n", label, 32);
			//读取下一行label
			char retn[32] = {};
			sscanf_s(p2 + 1, "%[^:]", retn, 32);

			//初始化混淆指令
			int rnd;					//随机数
			char rnd_reg1[10] = {};		//随机寄存器
			char rnd_reg2[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);
			//开始混淆
			size_t rules = 1;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
				//push reg
				//reg = reg2+retn+rand_imm
				//reg -= reg2
				//reg -= rand_imm
				//xchg reg, [esp]

				//push reg2
				//xor reg2, reg2
				//xor reg2, target
				//xchg reg2, [esp]
				//ret
				rnd = rand() * rand();
				strcpy_s(rnd_reg1, rand_x32_reg());
				while (strcmp(rnd_reg1, "esp") == 0)
				{
					strcpy_s(rnd_reg1, rand_x32_reg());
				}
				strcpy_s(rnd_reg2, rand_x32_reg());
				while (strcmp(rnd_reg1, rnd_reg2) == 0)
				{
					strcpy_s(rnd_reg2, rand_x32_reg());
				}
				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, es:[%s + %s + %#x]\n", m_count + tot, rnd_reg1, rnd_reg2, retn, rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				//发现问题，如果rand_reg_2是esp，那么keystone汇编会识别出错，把rand_reg_2放前面没有此问题
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, fs:[%s + %s]\n", m_count + tot, rnd_reg1, rnd_reg2, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, gs:[%s + 0x%x]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);

				do
				{
					strcpy_s(rnd_reg1, sizeof(rnd_reg1), rand_x32_reg());
				} while (strcmp(rnd_reg1, "esp") == 0);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xor %s, %s\n", m_count + tot, rnd_reg1, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xor %s, %s\n", m_count + tot, rnd_reg1, m_insn[i].op_str);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: popfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
				/*case 1:
					//lea esp, [esp-4]
					//mov [esp], retn
					//push target
					//ret
					sprintf_s(tmp, sizeof(tmp), " lea esp, [esp - 4]\n");
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], %s\n", m_count + tot, retn);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, m_insn[i].op_str);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 2:
					//lea esp, [esp-4]
					//mov [esp], retn
					//jmp target
					sprintf_s(tmp, sizeof(tmp), " lea esp, [esp - 4]\n");
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], %s\n", m_count + tot, retn);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: jmp %s\n", m_count + tot, m_insn[i].op_str);
					strcat_s(new_insn, max_size, tmp);
					break;*/
			default:
				DBG_PRINT("obf_equivalent_variation error call\n");
			}

			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		//混淆mov dst,target

		else if (strcmp(m_insn[i].mnemonic, "mov") == 0
			)
		{

			//读取当前行指令
			char label[32] = {};
			char target[100] = {};
			char dst[100] = {};
			sscanf_s(p1, "%s mov %[^,], %[^\n]", label, 32, dst, 100, target, 100);
			if (dst[strlen(dst) - 1] == ']' && target[strlen(target) - 1] != ']' &&
				(is_x32_reg(target) || is_x16_reg(target) || is_x8_reg(target))
				)
			{
				//mov ptr mem,reg

				//初始化混淆指令
				int rnd;					//随机数
				char rnd_reg[10] = {};		//随机寄存器
				char tmp[200] = {};
				memset(new_insn, 0, max_size);
				strcpy_s(new_insn, max_size, label);
				//开始混淆
				size_t rules = 1;		//规则数
				size_t flag = rand() % rules + 1;
				switch (flag)
				{
				case 1:
					//push reg
					//pop mem
					sprintf_s(tmp, sizeof(tmp), " push %s\n", target);
					strcat_s(new_insn, max_size, tmp);
					//------todo----------
					if (is_x32_reg(target))
					{
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, dst);
						strcat_s(new_insn, max_size, tmp);
					}
					else if (is_x16_reg(target))
					{
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, dst);
						strcat_s(new_insn, max_size, tmp);
					}
					else if (is_x8_reg(target))
					{
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, dst);
						strcat_s(new_insn, max_size, tmp);
					}
					else DBG_PRINT("Error obf_equivalent_variation mov ptr mem,reg\nunknown reg: %s\n", target);
					break;
				default:
					DBG_PRINT("obf_equivalent_variation error mov mem, reg\n");
				}
			}
			else if (dst[strlen(dst) - 1] == ']' && target[strlen(target) - 1] != ']' &&
				m_insn[i].detail->x86.operands[m_insn[i].detail->x86.op_count - 1].type == X86_OP_IMM

				)
			{
				//mov ptr mem,imm

				//初始化混淆指令
				int rnd;					//随机数
				int n;
				char rnd_reg[10] = {};		//随机寄存器
				char tmp[200] = {};
				memset(new_insn, 0, max_size);
				strcpy_s(new_insn, max_size, label);
				//开始混淆
				size_t rules = 6;		//规则数
				size_t flag = rand() % rules + 1;
				switch (flag)
				{
				case 1:
					//mov mem, ~imm
					//not mem
					sprintf_s(tmp, sizeof(tmp), " mov %s, %#x\n", dst, ~(m_insn[i].detail->x86.operands[m_insn[i].detail->x86.op_count - 1].imm));
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, dst);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 2:
					//mov mem, imm ^ rnd
					//xor mem, rnd
					rnd = rand() * rand();
					sprintf_s(tmp, sizeof(tmp), " mov %s, %#x\n", dst, (m_insn[i].detail->x86.operands[m_insn[i].detail->x86.op_count - 1].imm) ^ rnd);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: xor %s, %#x\n", m_count + tot, dst, rnd);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 3:
					//mov mem, imm + rnd
					//add mem, rnd
					rnd = rand() * rand();
					sprintf_s(tmp, sizeof(tmp), " mov %s, %#x\n", dst, (m_insn[i].detail->x86.operands[m_insn[i].detail->x86.op_count - 1].imm) + rnd);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: add %s, %#x\n", m_count + tot, dst, rnd);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 4:
					//mov mem, imm - rnd
					//sub mem, rnd
					rnd = rand() * rand();
					sprintf_s(tmp, sizeof(tmp), " mov %s, %#x\n", dst, (m_insn[i].detail->x86.operands[m_insn[i].detail->x86.op_count - 1].imm) - rnd);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: sub %s, %#x\n", m_count + tot, dst, rnd);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 5:

					//mov mem, n(imm循环左移rnd)	(1<=n<=0xff)
					//ror mem, rnd
					rnd = rand() % 0xff + 1;
					n = m_insn[i].detail->x86.operands[m_insn[i].detail->x86.op_count - 1].imm;
					n = (n << rnd) | (n >> (32 - rnd));
					sprintf_s(tmp, sizeof(tmp), " mov %s, %#x\n", dst, n);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: ror %s, %#x\n", m_count + tot, dst, rnd);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 6:
					//mov mem, n(imm循环右移rnd)	(1<=n<=0xff)
					//rol [esp], rnd
					rnd = rand() % 0xff + 1;
					n = m_insn[i].detail->x86.operands[m_insn[i].detail->x86.op_count - 1].imm;
					n = (n >> rnd) | (n << (32 - rnd));
					sprintf_s(tmp, sizeof(tmp), " mov %s, %#x\n", dst, n);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: rol %s, %#x\n", m_count + tot, dst, rnd);
					strcat_s(new_insn, max_size, tmp);
					break;
				default:
					DBG_PRINT("obf_equivalent_variation error mov mem, imm\n");
				}
			}
			else if (dst[strlen(dst) - 1] != ']' && target[strlen(target) - 1] == ']')
			{
				//mov reg, ptr mem

				//初始化混淆指令
				int rnd;					//随机数
				char rnd_reg[10] = {};		//随机寄存器
				char tmp[200] = {};
				memset(new_insn, 0, max_size);
				strcpy_s(new_insn, max_size, label);
				//开始混淆
				size_t rules = 1;		//规则数
				size_t flag = rand() % rules + 1;
				switch (flag)
				{
				case 1:
					if (is_x32_reg(dst))
					{
						//push edi
						//push esi
						//lea esi, target
						//lea esp, [esp - 4]
						//mov edi, esp
						//movs dword ptr [edi], dword ptr [esi]
						//push reg(非esp)
						//xchg reg, [esp]
						//xchg reg, [esp + 8]
						//xchg reg, [esp + 4]
						//xchg reg, [esp] 
						//pop esi
						//pop edi
						//pop dst
						do
						{
							strcpy_s(rnd_reg, 10, rand_x32_reg());
						} while (strcmp(rnd_reg, "esp") == 0);
						sprintf_s(tmp, sizeof(tmp), " push edi\n");
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: push esi\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: lea esi, %s\n", m_count + tot, target);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: lea esp, [esp - 4]\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: mov edi, esp\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: movs dword ptr [edi], dword ptr [esi]\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp]\n", m_count + tot, rnd_reg);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp + 8]\n", m_count + tot, rnd_reg);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp + 4]\n", m_count + tot, rnd_reg);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp]\n", m_count + tot, rnd_reg);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop esi\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop edi\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, dst);
						strcat_s(new_insn, max_size, tmp);
					}
					else if (is_x16_reg(dst))
					{
						DBG_PRINT("pass\n");
						__asm int 3
					}
					else if (is_x8_reg(dst))
					{
						//push edi
						//push esi
						//lea esi, target
						//lea esp, [esp - 4]
						//mov edi, esp
						//movs dword ptr [edi], dword ptr [esi]
						//xor x8_reg, x8_reg
						//or x8_reg, [esp]
						//pop [esp - 4]
						//pop esi
						//pop edi

						sprintf_s(tmp, sizeof(tmp), " push edi\n");
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: push esi\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: lea esi, %s\n", m_count + tot, target);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: lea esp, [esp - 4]\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: mov edi, esp\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: movs dword ptr [edi], dword ptr [esi]\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						//++tot;
						//sprintf_s(tmp, sizeof(tmp), "label%d: mov %s, byte ptr [esp]\n", m_count + tot, dst);
						//strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: xor %s, %s\n", m_count + tot, dst, dst);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: or %s, byte ptr [esp + 4]\n", m_count + tot, dst);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: popfd\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop dword ptr [esp - 4]\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop esi\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
						++tot;
						sprintf_s(tmp, sizeof(tmp), "label%d: pop edi\n", m_count + tot);
						strcat_s(new_insn, max_size, tmp);
					}
					else DBG_PRINT("Error obf_equivalent_variation mov reg, ptr mem\nunknown reg: %s\n", target);
					break;
				default:
					DBG_PRINT("obf_equivalent_variation error mov \n");
				}
			}
			else if (dst[strlen(dst) - 1] != ']' && target[strlen(target) - 1] != ']' &&
				(is_x32_reg(target) || is_x16_reg(target) || is_x8_reg(target))
				)
			{
				//mov reg, reg

				//初始化混淆指令
				int rnd;					//随机数
				char rnd_reg[10] = {};		//随机寄存器
				char tmp[200] = {};
				memset(new_insn, 0, max_size);
				strcpy_s(new_insn, max_size, label);
				//开始混淆
			begin_mov_reg_reg:
				size_t rules = 3;		//规则数
				size_t flag = rand() % rules + 1;
				switch (flag)
				{
				case 1:
					//push reg
					//pop reg
					sprintf_s(tmp, sizeof(tmp), " push %s\n", target);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, dst);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 2:
					//push target
					//xchg dst, target
					//pop target
					if (strcmp(dst, "esp") == 0 || strcmp(target, "esp") == 0)
					{
						goto begin_mov_reg_reg;
					}
					sprintf_s(tmp, sizeof(tmp), " push %s\n", target);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, %s\n", m_count + tot, dst, target);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, target);
					strcat_s(new_insn, max_size, tmp);
					break;
				case 3:
					//pushfd
					//xor target, dst
					//xor dst, target
					//xor target, dst
					//popfd
					if (strcmp(dst, "esp") == 0 || strcmp(target, "esp") == 0)
					{
						goto begin_mov_reg_reg;
					}
					sprintf_s(tmp, sizeof(tmp), " pushfd\n");
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: xor %s, %s\n", m_count + tot, target, dst);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: xor %s, %s\n", m_count + tot, dst, target);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: xor %s, %s\n", m_count + tot, target, dst);
					strcat_s(new_insn, max_size, tmp);
					++tot;
					sprintf_s(tmp, sizeof(tmp), "label%d: popfd\n", m_count + tot);
					strcat_s(new_insn, max_size, tmp);
					break;
				}
			}
			else if (dst[strlen(dst) - 1] != ']' && target[strlen(target) - 1] != ']' &&
				m_insn[i].detail->x86.operands[1].type == X86_OP_IMM
				)
			{
				//mov reg, imm
				strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
				p1 = strchr(p1, '\n');
				p1++;
				continue;
			}
			else {
				DBG_PRINT("Error obf mov dst, target\nor mov dst, imm\n");
			}


			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		else
		{
			//直接复制原始指令
			strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
		}
		//处理下一行
		p1 = strchr(p1, '\n');
		p1++;
	}
	delete[] new_insn;
	//保存
	if (m_obf_asm_buffer != NULL)
	{
		delete[] m_obf_asm_buffer;
		m_obf_asm_buffer = NULL;
	}
	m_obf_asm_buffer = new_asm_buffer;
	DBG_PRINT("%s\n", m_obf_asm_buffer);
	obf_asm(m_obf_asm_buffer);
	obf_disasm(m_obf_base);

}



void obf::obf_local_obf()
{
	update_jcc_table();
	size_t i = 0, j = 0;
	size_t tot = 0;	//增加的指令数

	//初始化
	char* new_asm_buffer = new char[max_size];
	memset(new_asm_buffer, 0, max_size);
	char* new_insn = new char[max_size];
	char* p1 = m_obf_asm_buffer;

	//设置入口点混淆基址
	//在m_obf_asm_buffer字符串开头插入jmp label0
	tot++;
	sprintf_s(new_asm_buffer, max_size, "label%d: jmp label0\n", m_count + tot);
	m_obf_entry = m_obf_base;

	for (i = 0; i < m_count; ++i)
	{
		char* p2 = strchr(p1, '\n');
		//混淆jmp label;
		if (strcmp(m_insn[i].mnemonic, "test") == 0 || strcmp(m_insn[i].mnemonic, "cmp") == 0
			)
		{
			//初始化混淆指令
			int rnd = 0;					//随机数
			char rnd_reg_1[10] = {};		//随机寄存器
			char rnd_reg_2[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);

			size_t rules = 5;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{

			case 1:
				//test x32_reg, x32_reg
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: test %s, %s\n", m_count + tot, rand_x32_reg(), rand_x32_reg());
				strcat_s(new_insn, max_size, tmp);
				break;
			case 2:
				//cmp x32_reg, x32_reg
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: cmp %s, %s\n", m_count + tot, rand_x32_reg(), rand_x32_reg());
				strcat_s(new_insn, max_size, tmp);
				break;
			case 3:
				//test x16_reg, x16_reg
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: test %s, %s\n", m_count + tot, rand_x16_reg(), rand_x16_reg());
				strcat_s(new_insn, max_size, tmp);
				break;
			case 4:
				//cmp x16_reg, x16_reg
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: cmp %s, %s\n", m_count + tot, rand_x16_reg(), rand_x16_reg());
				strcat_s(new_insn, max_size, tmp);
				break;
			case 5:
				//插入无用设置标志位指令
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: %s\n", m_count + tot, rand_flag_insn());
				strcat_s(new_insn, max_size, tmp);
				break;
			default:
				DBG_PRINT("obf_local_obf error\n");
			}
			//保存添加的无用指令
			strcat_s(new_asm_buffer, max_size, new_insn);
			//保存原始指令
			strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
		}
		else
		{
			//直接复制原始指令
			strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
		}
		//处理下一行
		p1 = strchr(p1, '\n');
		p1++;
	}
	delete[] new_insn;
	//保存
	if (m_obf_asm_buffer != NULL)
	{
		delete[] m_obf_asm_buffer;
		m_obf_asm_buffer = NULL;
	}
	m_obf_asm_buffer = new_asm_buffer;
	DBG_PRINT("%s\n", m_obf_asm_buffer);
	obf_asm(m_obf_asm_buffer);
	obf_disasm(m_obf_base);

}



void obf::obf_no_jcc()
{
	update_jcc_table();
	size_t i = 0, j = 0;
	size_t tot = 0;	//增加的指令数

	//初始化
	char* new_asm_buffer = new char[max_size];
	memset(new_asm_buffer, 0, max_size);
	char* new_insn = new char[max_size];
	char* p1 = m_obf_asm_buffer;

	//设置入口点混淆基址
	//在m_obf_asm_buffer字符串开头插入jmp label0
	tot++;
	sprintf_s(new_asm_buffer, max_size, "label%d: jmp label0\n", m_count + tot);
	m_obf_entry = m_obf_base;

	for (i = 0; i < m_count; ++i)
	{
		char* p2 = strchr(p1, '\n');
		//混淆jcc
		if (//cs_insn_group(m_handle, &m_insn[i], CS_GRP_JUMP)&&
			strcmp(m_insn[i].mnemonic, "jz") == 0 || strcmp(m_insn[i].mnemonic, "je") == 0
			)
		{
			//读取当前行指令
			char label[32] = {};
			sscanf_s(p1, "%s\n", label, 32);
			//读取jcc目标地址的label
			char label1[32] = {};
			for (j = 0; j < m_count; ++j)
			{
				if (m_insn[j].address == m_insn[i].detail->x86.operands[0].imm)
				{
					char* p3 = m_obf_asm_buffer;
					for (int k = 0; k < j; ++k)
					{
						p3 = strchr(p3, '\n');
						++p3;
					}
					sscanf_s(p3, "%[^:]", label1, 32);
					break;
				}
			}
			//读取下一行label
			char label2[32] = {};
			sscanf_s(p2 + 1, "%[^:]", label2, 32);
			//初始化混淆指令
			int rnd = 0;					//随机数
			char rnd_reg1[10] = {};		//随机寄存器
			char rnd_reg2[10] = {};		//随机寄存器
			char rnd_reg3[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);

			size_t rules = 2;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{

			case 1:
				//push reg1
				//push reg2
				//push reg3
				//pushfd
				//pop reg3
				//shl reg3, 25
				//shr reg3, 31
				//neg reg3
				//lea reg1, [label1]		(todo 混淆，不用pushfd用lahf,sahf)
				//lea reg2, [label2]
				//and reg1, reg3
				//not reg3
				//and reg2, reg3
				//lea reg1, [reg1+reg2]
				//xchg reg1, [esp + 8]
				//pop reg3
				//pop reg2
				//ret

				do {
					strcpy_s(rnd_reg1, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, "esp") == 0);
				do {
					strcpy_s(rnd_reg2, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg2, "esp") == 0);
				do {
					strcpy_s(rnd_reg3, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg2, rnd_reg3) == 0 || strcmp(rnd_reg3, "esp") == 0);

				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sal %s, 0x19\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: shr %s, 0x1f\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: neg %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg1, label1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg2, label2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg1, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg2, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s+%s]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 8]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 2:
				//push reg1
				//push reg2
				//push reg3
				//lahf
				//shl reg3, 25
				//shr reg3, 31
				//neg reg3
				//lea reg1, [label1]		(todo 混淆，不用pushfd用lahf,sahf)
				//lea reg2, [label2]
				//and reg1, reg3
				//not reg3
				//and reg2, reg3
				//lea reg1, [reg1+reg2]
				//xchg reg1, [esp + 8]
				//pop reg3
				//pop reg2
				//ret
				strcpy_s(rnd_reg3, 10, "eax");
				do {
					strcpy_s(rnd_reg1, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg1, "esp") == 0);
				do {
					strcpy_s(rnd_reg2, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg2, rnd_reg3) == 0 || strcmp(rnd_reg2, "esp") == 0);

				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lahf\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sal %s, 0x11\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: shr %s, 0x1f\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: neg %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg1, label1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg2, label2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg1, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg2, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s+%s]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 8]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;

			default:
				DBG_PRINT("obf_no_jcc error\n");
			}
			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);

		}
		else if (//cs_insn_group(m_handle, &m_insn[i], CS_GRP_JUMP)&&
			strcmp(m_insn[i].mnemonic, "jnz") == 0 || strcmp(m_insn[i].mnemonic, "jne") == 0
			)
		{
			//读取当前行指令
			char label[32] = {};
			sscanf_s(p1, "%s\n", label, 32);
			//读取jcc目标地址的label
			char label1[32] = {};
			for (j = 0; j < m_count; ++j)
			{
				if (m_insn[j].address == m_insn[i].detail->x86.operands[0].imm)
				{
					char* p3 = m_obf_asm_buffer;
					for (int k = 0; k < j; ++k)
					{
						p3 = strchr(p3, '\n');
						++p3;
					}
					sscanf_s(p3, "%[^:]", label1, 32);
					break;
				}
			}
			//读取下一行label
			char label2[32] = {};
			sscanf_s(p2 + 1, "%[^:]", label2, 32);
			//初始化混淆指令
			int rnd = 0;					//随机数
			char rnd_reg1[10] = {};		//随机寄存器
			char rnd_reg2[10] = {};		//随机寄存器
			char rnd_reg3[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);

			size_t rules = 2;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{

			case 1:
				//push reg1
				//push reg2
				//push reg3
				//pushfd
				//pop reg3
				//shl reg3, 25
				//shr reg3, 31
				//neg reg3
				//lea reg1, [label1]		(todo 混淆，不用pushfd用lahf,sahf)
				//lea reg2, [label2]
				//not reg3
				//and reg1, reg3
				//not reg3
				//and reg2, reg3
				//lea reg1, [reg1+reg2]
				//xchg reg1, [esp + 8]
				//pop reg3
				//pop reg2
				//ret

				do {
					strcpy_s(rnd_reg1, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, "esp") == 0);
				do {
					strcpy_s(rnd_reg2, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg2, "esp") == 0);
				do {
					strcpy_s(rnd_reg3, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg2, rnd_reg3) == 0 || strcmp(rnd_reg3, "esp") == 0);

				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sal %s, 0x19\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: shr %s, 0x1f\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: neg %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg1, label1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg2, label2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg1, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg2, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s+%s]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 8]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;

			case 2:
				//push reg1
				//push reg2
				//push reg3
				//lahf
				//shl reg3, 17
				//shr reg3, 31
				//neg reg3
				//lea reg1, [label1]
				//lea reg2, [label2]
				//not reg3
				//and reg1, reg3
				//not reg3
				//and reg2, reg3
				//lea reg1, [reg1+reg2]
				//xchg reg1, [esp + 8]
				//pop reg3
				//pop reg2
				//ret
				strcpy_s(rnd_reg3, 10, "eax");
				do {
					strcpy_s(rnd_reg1, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg1, "esp") == 0);
				do {
					strcpy_s(rnd_reg2, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg2, rnd_reg3) == 0 || strcmp(rnd_reg2, "esp") == 0);

				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lahf\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sal %s, 0x11\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: shr %s, 0x1f\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: neg %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg1, label1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg2, label2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg1, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg2, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s+%s]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 8]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;

			default:
				DBG_PRINT("obf_no_jcc error\n");
			}
			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);

		}
		else if (
			strcmp(m_insn[i].mnemonic, "jc") == 0 || strcmp(m_insn[i].mnemonic, "jb") == 0 || strcmp(m_insn[i].mnemonic, "jnae") == 0
			)
		{
			//读取当前行指令
			char label[32] = {};
			sscanf_s(p1, "%s\n", label, 32);
			//读取jcc目标地址的label
			char label1[32] = {};
			for (j = 0; j < m_count; ++j)
			{
				if (m_insn[j].address == m_insn[i].detail->x86.operands[0].imm)
				{
					char* p3 = m_obf_asm_buffer;
					for (int k = 0; k < j; ++k)
					{
						p3 = strchr(p3, '\n');
						++p3;
					}
					sscanf_s(p3, "%[^:]", label1, 32);
					break;
				}
			}
			//读取下一行label
			char label2[32] = {};
			sscanf_s(p2 + 1, "%[^:]", label2, 32);
			//初始化混淆指令
			int rnd = 0;					//随机数
			char rnd_reg1[10] = {};		//随机寄存器
			char rnd_reg2[10] = {};		//随机寄存器
			char rnd_reg3[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);

			size_t rules = 3;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{

			case 1:
				//push reg1
				//push reg2
				//push reg3
				//pushfd
				//pop reg3
				//shl reg3, 31
				//shr reg3, 31
				//neg reg3
				//lea reg1, [label1]		(todo 混淆，不用pushfd用lahf,sahf)
				//lea reg2, [label2]
				//and reg1, reg3
				//not reg3
				//and reg2, reg3
				//lea reg1, [reg1+reg2]
				//xchg reg1, [esp + 8]
				//pop reg3
				//pop reg2
				//ret

				do {
					strcpy_s(rnd_reg1, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, "esp") == 0);
				do {
					strcpy_s(rnd_reg2, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg2, "esp") == 0);
				do {
					strcpy_s(rnd_reg3, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg2, rnd_reg3) == 0 || strcmp(rnd_reg3, "esp") == 0);

				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sal %s, 0x1f\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: shr %s, 0x1f\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: neg %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg1, label1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg2, label2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg1, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg2, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s + %s]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 8]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 2:
				//push reg1
				//push reg2
				//push reg3
				//lahf
				//shl reg3, 0x17
				//shr reg3, 0x1f
				//neg reg3
				//lea reg1, [label1]		(todo 混淆，不用pushfd用lahf,sahf)
				//lea reg2, [label2]
				//and reg1, reg3
				//not reg3
				//and reg2, reg3
				//lea reg1, [reg1+reg2]
				//xchg reg1, [esp + 8]
				//pop reg3
				//pop reg2
				//ret
				strcpy_s(rnd_reg3, 10, "eax");
				do {
					strcpy_s(rnd_reg1, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg1, "esp") == 0);
				do {
					strcpy_s(rnd_reg2, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg2, rnd_reg3) == 0 || strcmp(rnd_reg2, "esp") == 0);

				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lahf\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sal %s, 0x17\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: shr %s, 0x1f\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: neg %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg1, label1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg2, label2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg1, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg2, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s+%s]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 8]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 3:
				//push reg1
				//push reg2
				//push reg3
				//pushfd
				//and [esp], 1
				//pop reg3
				//neg reg3
				//lea reg1, [label1]		(todo 混淆，不用pushfd用lahf,sahf)
				//lea reg2, [label2]
				//and reg1, reg3
				//not reg3
				//and reg2, reg3
				//lea reg1, [reg1 + reg2]
				//xchg reg1, [esp + 8]
				//pop reg3
				//pop reg2
				//ret
				strcpy_s(rnd_reg3, 10, "eax");
				do {
					strcpy_s(rnd_reg1, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg1, "esp") == 0);
				do {
					strcpy_s(rnd_reg2, 10, rand_x32_reg());
				} while (strcmp(rnd_reg1, rnd_reg2) == 0 || strcmp(rnd_reg1, rnd_reg3) == 0 || strcmp(rnd_reg2, rnd_reg3) == 0 || strcmp(rnd_reg2, "esp") == 0);

				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: push %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pushfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and dword ptr [esp], 0x1\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: neg %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg1, label1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s]\n", m_count + tot, rnd_reg2, label2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg1, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: and %s, %s\n", m_count + tot, rnd_reg2, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, [%s + %s]\n", m_count + tot, rnd_reg1, rnd_reg1, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, [esp + 8]\n", m_count + tot, rnd_reg1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg3);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: pop %s\n", m_count + tot, rnd_reg2);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			default:
				DBG_PRINT("obf_no_jcc error\n");
			}
			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);

		}
		else
		{
			//直接复制原始指令
			strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
		}
		//处理下一行
		p1 = strchr(p1, '\n');
		p1++;
	}
	delete[] new_insn;
	//保存
	if (m_obf_asm_buffer != NULL)
	{
		delete[] m_obf_asm_buffer;
		m_obf_asm_buffer = NULL;
	}
	m_obf_asm_buffer = new_asm_buffer;
	DBG_PRINT("%s\n", m_obf_asm_buffer);
	obf_asm(m_obf_asm_buffer);
	obf_disasm(m_obf_base);

}






void obf::obf_flatten()
{

}


void obf::obf_fake_jcc(IN BYTE* buffer, IN DWORD size)
{

}



/**
 * \brief 混淆jmp指令
 *
 */
void obf::obf_jmp_label_by_retn()
{
	update_jcc_table();
	size_t i = 0, j = 0;
	size_t tot = 0;	//增加的指令数

	//初始化
	char* new_asm_buffer = new char[max_size];
	memset(new_asm_buffer, 0, max_size);
	char* new_insn = new char[max_size];
	char* p1 = m_obf_asm_buffer;

	//设置入口点混淆基址
	//在m_obf_asm_buffer字符串开头插入jmp label0
	tot++;
	sprintf_s(new_asm_buffer, max_size, "label%d: jmp label0\n", m_count + tot);
	m_obf_entry = m_obf_base;


	for (i = 0; i < m_count; ++i)
	{
		char* p2 = strchr(p1, '\n');
		//混淆jmp label;
		if (strcmp(m_insn[i].mnemonic, "jmp") == 0 &&
			m_jcc_table[i] != -1
			)
		{
			//读取当前行指令
			char label[32] = {};
			char jcc[32] = {};
			char target[32] = {};
			sscanf_s(p1, "%s %s %s\n", label, 32, jcc, 32, target, 32);
			//初始化混淆指令
			int rnd;					//随机数
			char rnd_reg[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);
			//开始混淆
			size_t rules = 8;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
				//lea esp, dword ptr [esp-4]
				//mov dword ptr [esp], 标签
				//ret
				strcat_s(new_insn, max_size, " lea esp, dword ptr [esp-4]\n");
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 2:
				//push reg
				//mov dword ptr [esp], 标签
				//ret
				sprintf_s(tmp, sizeof(tmp), " push %s\n", rand_x32_reg());
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 3:
				//call $+5
				//mov dword ptr [esp], 标签
				//ret
				sprintf_s(tmp, sizeof(tmp), " call label%d\n", m_count + tot + 1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 4:
				//pushfd
				//mov dword ptr [esp], 标签
				//ret
				strcat_s(new_insn, max_size, " pushfd\n");
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
				//
			case 5:
				//pushad
				//mov dword ptr [esp], 标签
				//ret 0x20
				strcat_s(new_insn, max_size, " pushad\n");
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret 0x1c\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 6:
			case_6:
				//CLC、STC、CMC、CLD、STD用作混淆
				//pushfd		//保护EFLAGS
				//sub esp, 4	
				//mov dword ptr [esp], 标签
				//xchg reg, dword ptr [esp]
				//xchg reg, dword ptr [esp+4]
				//xchg reg, dword ptr [esp]
				//popfd
				//ret

				strcpy_s(rnd_reg, rand_x32_reg());
				while (strcmp(rnd_reg, "esp") == 0)
				{
					strcpy_s(rnd_reg, rand_x32_reg());
				}
				strcat_s(new_insn, max_size, " pushfd\n");
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: sub esp, 4\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: %s\n", m_count + tot, rand_flag_insn());
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: %s\n", m_count + tot, rand_flag_insn());
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp]\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: %s\n", m_count + tot, rand_flag_insn());
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp+4]\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: %s\n", m_count + tot, rand_flag_insn());
				strcat_s(new_insn, max_size, tmp);

				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp]\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: popfd\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 7:
				//lea esp, dword ptr [esp-n]	(n>=4, n<=0x20)
				//mov dword ptr [esp], 标签
				//ret n-4
				rnd = rand() % (0x20 - 4) + 4;
				sprintf_s(tmp, sizeof(tmp), " lea esp, dword ptr [esp-0x%x]\n", rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret 0x%x\n", m_count + tot, rnd - 4);
				strcat_s(new_insn, max_size, tmp);
				break;
			case 8:
				//push reg	(除了esp)
				//mov reg,label
				//xchg dword ptr [esp], reg
				//ret
				strcpy_s(rnd_reg, rand_x32_reg());
				while (strcmp(rnd_reg, "esp") == 0)
				{
					strcpy_s(rnd_reg, rand_x32_reg());
				}
				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov %s, label%d\n", m_count + tot, rnd_reg, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg dword ptr [esp], %s\n", m_count + tot, rnd_reg);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			default:;
				//DBG_PRINT("obf_encrypt_jcc error\n");
				//case 6
				goto case_6;
			}

			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);

		}
		else
		{
			//直接复制原始指令
			strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
		}
		//处理下一行
		p1 = strchr(p1, '\n');
		p1++;
	}
	delete[] new_insn;
	//保存
	if (m_obf_asm_buffer != NULL)
	{
		delete[] m_obf_asm_buffer;
		m_obf_asm_buffer = NULL;
	}
	m_obf_asm_buffer = new_asm_buffer;
	DBG_PRINT("%s\n", m_obf_asm_buffer);
	obf_asm(m_obf_asm_buffer);
	obf_disasm(m_obf_base);




	// size_t i=0,j=0;
	// size_t tot=0;	//增加的指令数
	//
	// //初始化
	// string tmp = m_obf_asm_buffer;
	//
	// //用正则表达式将new_asm_buffer中的"jmp label*"指令替换为"push label*\nret"
	// //regex reg_jmp("jmp\\s+label\\d+");
	// regex reg_jmp("jmp\\s+([a-zA-Z0-9_]+)");
	// smatch sm;
	// string new_asm_buffer;
	// while (regex_search(tmp, sm, reg_jmp))
	// {
	// 	new_asm_buffer += sm.prefix().str();
	// 	new_asm_buffer += "lea esp, dword ptr [esp-4]\nmov dword ptr [esp], "+sm[1].str()+"\nret";
	// 	tmp = sm.suffix().str();
	// }
	//
	// //保存
	// if(m_obf_asm_buffer!=NULL)
	// {
	// 	delete[] m_obf_asm_buffer;
	// 	m_obf_asm_buffer = NULL;
	// }
	// m_obf_asm_buffer = new char[new_asm_buffer.length() + 1];
	// memset(m_obf_asm_buffer, 0, new_asm_buffer.length() + 1);
	// strcpy_s(m_obf_asm_buffer, new_asm_buffer.length() + 1, new_asm_buffer.c_str());
	//
	// DBG_PRINT("%s\n", m_obf_asm_buffer);
	// obf_asm(m_obf_asm_buffer);
	// obf_disasm(m_obf_base);

}



void obf::obf_vm()
{
	update_jcc_table();
	size_t i = 0, j = 0;
	size_t tot = 0;	//增加的指令数

	//初始化
	char* new_asm_buffer = new char[max_size];
	memset(new_asm_buffer, 0, max_size);
	char* new_insn = new char[max_size];
	char* p1 = m_obf_asm_buffer;

	//设置入口点混淆基址
	//在m_obf_asm_buffer字符串开头插入jmp label0
	tot++;
	sprintf_s(new_asm_buffer, max_size, "label%d: jmp vm_start\n", m_count + tot);
	m_obf_entry = m_obf_base;


	//生成虚拟机代码














	for (i = 0; i < m_count; ++i)
	{
		char* p2 = strchr(p1, '\n');
		//混淆jmp label;
		if (strcmp(m_insn[i].mnemonic, "jmp") == 0 &&
			m_jcc_table[i] != -1
			)
		{
			//读取当前行label
			char label[32] = {};
			sscanf_s(p1, "%s\n", label, 32);
			//初始化混淆指令
			int rnd;					//随机数
			char rnd_reg[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);
			//开始混淆
			size_t rules = 1;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
				//lea esp, dword ptr [esp-4]
				//mov dword ptr [esp], 标签
				//ret
				strcat_s(new_insn, max_size, " lea esp, dword ptr [esp-4]\n");
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: mov dword ptr [esp], label%d\n", m_count + tot, m_jcc_table[i]);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;
			}
			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		else
		{
			//直接复制原始指令
			strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
		}
		//处理下一行
		p1 = strchr(p1, '\n');
		p1++;
	}
	delete[] new_insn;
	//保存
	if (m_obf_asm_buffer != NULL)
	{
		delete[] m_obf_asm_buffer;
		m_obf_asm_buffer = NULL;
	}
	m_obf_asm_buffer = new_asm_buffer;
	DBG_PRINT("%s\n", m_obf_asm_buffer);
	obf_asm(m_obf_asm_buffer);
	obf_disasm(m_obf_base);
}




void obf::obf_vector_jmp()
{
	update_jcc_table();
	size_t i = 0, j = 0;
	size_t tot = 0;	//增加的指令数

	//初始化
	char* new_asm_buffer = new char[max_size];
	memset(new_asm_buffer, 0, max_size);
	char* new_insn = new char[max_size];
	char* p1 = m_obf_asm_buffer;

	//设置入口点混淆基址
	//在m_obf_asm_buffer字符串开头插入jmp label0
	tot++;
	sprintf_s(new_asm_buffer, max_size, "label%d: jmp label0\n", m_count + tot);
	m_obf_entry = m_obf_base;

	for (i = 0; i < m_count; ++i)
	{
		char* p2 = strchr(p1, '\n');
		//混淆jmp label;
		if (strcmp(m_insn[i].mnemonic, "jmp") == 0 &&
			m_jcc_table[i] != -1
			)
		{
			//读取当前行指令
			char label[32] = {};
			char jcc[32] = {};
			char target[32] = {};
			char extra[32] = {};
			sscanf_s(p1, "%s %s %s %[^\n]", label, 32, jcc, 32, target, 32, extra, 32);
			//初始化混淆指令
			int rnd = 0;					//随机数
			char rnd_reg_1[10] = {};		//随机寄存器
			char rnd_reg_2[10] = {};		//随机寄存器
			char tmp[200] = {};
			memset(new_insn, 0, max_size);
			strcpy_s(new_insn, max_size, label);

			size_t rules = 1;		//规则数
			size_t flag = rand() % rules + 1;
			switch (flag)
			{
			case 1:
			case_1:
				//push reg
				//reg = reg2+target+rand_imm
				//reg -= reg2
				//reg -= rand_imm
				//xchg reg, [esp]
				//ret
				rnd = rand() * rand();
				strcpy_s(rnd_reg_1, rand_x32_reg());
				while (strcmp(rnd_reg_1, "esp") == 0)
				{
					strcpy_s(rnd_reg_1, rand_x32_reg());
				}
				strcpy_s(rnd_reg_2, rand_x32_reg());
				while (strcmp(rnd_reg_1, rnd_reg_2) == 0)
				{
					strcpy_s(rnd_reg_2, rand_x32_reg());
				}
				sprintf_s(tmp, sizeof(tmp), " push %s\n", rnd_reg_1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, gs:[%s + label%d + 0x%x]\n", m_count + tot, rnd_reg_1, rnd_reg_2, m_jcc_table[i], rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg_1);
				strcat_s(new_insn, max_size, tmp);

				//发现问题，如果rand_reg_2是esp，那么keystone汇编会识别出错，把rand_reg_2放前面没有此问题
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, fs:[%s + %s]\n", m_count + tot, rnd_reg_1, rnd_reg_2, rnd_reg_1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg_1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg_1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: lea %s, es:[%s + 0x%x]\n", m_count + tot, rnd_reg_1, rnd_reg_1, rnd);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: not %s\n", m_count + tot, rnd_reg_1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: xchg %s, dword ptr [esp]\n", m_count + tot, rnd_reg_1);
				strcat_s(new_insn, max_size, tmp);
				++tot;
				sprintf_s(tmp, sizeof(tmp), "label%d: ret\n", m_count + tot);
				strcat_s(new_insn, max_size, tmp);
				break;

			default:
				goto case_1;
			}
			//保存
			strcat_s(new_asm_buffer, max_size, new_insn);
		}
		else
		{
			//直接复制原始指令
			strncat_s(new_asm_buffer, max_size, p1, p2 - p1 + 1);
		}
		//处理下一行
		p1 = strchr(p1, '\n');
		p1++;
	}
	delete[] new_insn;
	//保存
	if (m_obf_asm_buffer != NULL)
	{
		delete[] m_obf_asm_buffer;
		m_obf_asm_buffer = NULL;
	}
	m_obf_asm_buffer = new_asm_buffer;
	DBG_PRINT("%s\n", m_obf_asm_buffer);
	obf_asm(m_obf_asm_buffer);
	obf_disasm(m_obf_base);
}




















/**
 * \brief 代码乱序
 * \param maximum 一个片段的最多指令数
 */
void obf::obf_out_of_order(IN DWORD maximum)
{
	update_jcc_table();
	vector<size_t> vec_order;				//反汇编指令编号新顺序的集合
	size_t i = 0, j = 0;

	while (i != m_count)
	{
		size_t n = rand() % maximum + 1;			//一个片段的指令数
		if (n >= m_count - i) n = m_count - i;		//如果快要处理完成，设置为剩下的指令数
		size_t flag = rand() & 1;				//取0、1随机数，表示这个代码片段的下一个代码片段，从头部还是尾部插入其指令到vec_obf_insn

		if (!flag)							//这个代码片段的下一个代码片段从头部插入
		{
			for (size_t j = 0; j < n; ++j)
			{
				vec_order.insert(vec_order.begin() + j, i);
				i++;
			}
		}
		else								//从尾部插入
		{
			for (size_t j = 0; j < n; ++j)
			{
				vec_order.push_back(i);
				i++;
			}
		}
	}

	//------------生成了混淆的指令顺序，现在修复混淆代码jcc，并生成二进制------------------

	size_t tot = 0;			//添加了多少条指令，计数器
	char* new_asm_buffer = new char[max_size];
	memset(new_asm_buffer, 0, max_size);
	//设置入口点混淆基址
	//在m_obf_asm_buffer字符串开头插入jmp label0
	tot++;
	sprintf_s(new_asm_buffer, max_size, "label%d: jmp label0\n", m_count + tot);
	//sprintf_s(new_asm_buffer, max_size, "label%d: .byte 0x0\n", m_count + tot);
	m_obf_entry = m_obf_base;


	for (i = 0; i < m_count; i++)
	{
		if (m_jcc_table[vec_order[i]] != -1)
		{
			char* p1 = m_obf_asm_buffer;
			for (j = 0; j < vec_order[i]; ++j)
			{
				p1 = strchr(p1, '\n');
				p1++;
			}
			char label[32] = {};
			char op[32] = {};
			sscanf_s(p1, "%s %s", label, 32, op, 32);
			char tmp[200] = {};
			sprintf_s(tmp, 200, "%s %s label%d\n", label, op, m_jcc_table[vec_order[i]]);
			strcat_s(new_asm_buffer, max_size, tmp);
		}
		else
		{
			//将m_obf_asm_buffer的内容拷贝到new_asm_buffer
			char* p1 = m_obf_asm_buffer;
			for (j = 0; j < vec_order[i]; ++j)
			{
				p1 = strchr(p1, '\n');
				p1++;
			}
			char* p2 = strchr(p1, '\n');
			if (p2 == NULL) strcat_s(new_asm_buffer, max_size, p1);
			else strncat_s(new_asm_buffer, max_size, p1, p2 - p1);
			strcat_s(new_asm_buffer, max_size, "\n");
		}


		//连接代码片段
		//防越界，并且特判最后一句代码
		//如果是混淆后最后一句代码，并且他不是原来最后一句代码
		//或者他不是原来最后一句代码，并且他的下一句代码不是原来后一句代码
		if ((i == m_count - 1 && vec_order[i] != m_count - 1) ||
			(vec_order[i] != m_count - 1 && vec_order[i] != vec_order[i + 1] - 1)
			)
		{
			++tot;
			//获取vec_order[i]+1行的label
			char* p1 = m_obf_asm_buffer;
			for (j = 0; j < vec_order[i] + 1; ++j)
			{
				p1 = strchr(p1, '\n');
				p1++;
			}
			char label[32] = {};
			sscanf_s(p1, "%[^:]", label, 32);
			char tmp[200] = {};
			sprintf_s(tmp, 200, "label%d: jmp %s\n", m_count + tot, label);
			strcat_s(new_asm_buffer, max_size, tmp);
		}
		//如果当前代码是最后一句代码，特殊处理，附加一行jmp到end地址（即使乱序后并不是最后一句执行）
		if (vec_order[i] == m_count - 1)
		{
			++tot;
			char tmp[200] = {};
			sprintf_s(tmp, 200, "label%d: jmp 0x%x\n", m_count + tot, m_end);
			strcat_s(new_asm_buffer, max_size, tmp);
		}
	}
	delete[] m_obf_asm_buffer;
	m_obf_asm_buffer = new_asm_buffer;
	DBG_PRINT("%s\n", m_obf_asm_buffer);
	obf_asm(m_obf_asm_buffer);
	obf_disasm(m_obf_base);
	//delete[] new_asm_buffer;






	// string tmp_s = m_obf_asm_buffer;	
	// size_t line=0;						//当前行数
	// regex reg_line(".*\n+");		//匹配一行
	// size_t tot = 0;						//计数器，添加的jmp数目
	// smatch sm;
	// string new_asm_buffer;
	//
	// //设置入口点位混淆基址
	// //在m_obf_asm_buffer字符串开头插入jmp label0
	// tot++;
	// new_asm_buffer += "label"+to_string(m_count+tot)+": "+"jmp label0\n";
	// m_obf_entry = m_obf_base;
	//
	// //一行一行处理字符串m_obf_asm_buffer
	// while (regex_search(tmp_s, sm, reg_line))
	// {
	// 	new_asm_buffer += sm.prefix().str();
	// 	//如果是jcc imm指令，修复成jcc label
	// 	if(m_jcc_table[vec_order[line]]!=-1)
	// 	{
	// 		DBG_PRINT("%s",sm[0].str().c_str());
	// 		char label[10]={};
	// 		sscanf_s(sm[0].str().c_str(), "%s", label, sizeof(label));
	// 		new_asm_buffer+=string(label)+" "+ m_insn[vec_order[line]].mnemonic + string(" label") + to_string(m_jcc_table[vec_order[line]]) + "\n";
	//
	// 		//new_asm_buffer += m_insn[line].mnemonic + string(" label") + to_string(m_jcc_table[vec_order[line]]) + "\n";
	// 	}
	// 	else new_asm_buffer+= sm[0].str();
	//
	//
	// 	if ((line == m_count - 1 && vec_order[line] != m_count - 1) ||
	// 		(vec_order[line] != m_count - 1 && vec_order[line] != vec_order[line + 1] - 1)
	// 		)
	// 	{
	// 		new_asm_buffer+="jmp label"+to_string(vec_order[line]+1)+'\n';
	// 	}
	// 	//如果当前代码是原先最后一句代码，特殊处理，附加一行jmp到end地址（即使多次乱序后并不是最后一句执行）
	// 	if (vec_order[line] == m_count - 1)
	// 	{
	// 		tot++;
	// 		new_asm_buffer += "label"+ to_string(m_count + tot) +": " + "jmp 0x" + to_string(m_end) + '\n';
	// 	}
	// 	tmp_s = sm.suffix().str();
	// 	++line;
	// }
	// strcpy_s(m_obf_asm_buffer, max_size, new_asm_buffer.c_str());
	// DBG_PRINT("%s\n", m_obf_asm_buffer);
	// obf_asm(m_obf_asm_buffer);
	// obf_disasm(m_obf_base);


}













































bool obf::obf_asm(IN const char* buffer)
{
	ks_engine* ks;
	ks_err err = KS_ERR_ARCH;
	BYTE* binary;
	size_t cnt;
	ks_err(*ks_open)(ks_arch arch, int mode, ks_engine * *ks);
	int (*ks_asm)(ks_engine * ks,
		const char* string,
		uint64_t address,
		unsigned char** encoding, size_t * encoding_size,
		size_t * stat_count);
	ks_err(*ks_close)(ks_engine * ks);
	ks_err(*ks_errno)(ks_engine * ks);
	void (*ks_free)(unsigned char* p);
	ks_err(*ks_option)(ks_engine * ks, ks_opt_type type, size_t value);

	HMODULE hmodule = LoadLibraryA("keystone.dll");
	if (hmodule == NULL)
	{
		DBG_PRINT("加载模块失败");
		return false;
	}
	ks_open = (ks_err(*)(ks_arch, int, ks_engine**))GetProcAddress(hmodule, "ks_open");
	ks_asm = (int(*)(ks_engine*, const char*, uint64_t, unsigned char**, size_t*, size_t*))GetProcAddress(hmodule, "ks_asm");
	ks_close = (ks_err(*)(ks_engine*))GetProcAddress(hmodule, "ks_close");
	ks_errno = (ks_err(*)(ks_engine*))GetProcAddress(hmodule, "ks_errno");
	ks_free = (void(*)(unsigned char*))GetProcAddress(hmodule, "ks_free");
	ks_option = (ks_err(*)(ks_engine*, ks_opt_type, size_t))GetProcAddress(hmodule, "ks_option");

	ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
	ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
	m_size = 0;
	ks_asm(ks, buffer, m_obf_base, &binary, &m_size, &cnt);
	if (m_binary_buffer != NULL)
	{
		delete[] m_binary_buffer;
		m_binary_buffer = NULL;
	}
	m_binary_buffer = new BYTE[m_size];
	memcpy_s(m_binary_buffer, m_size, binary, m_size);
	DBG_PRINT("%d\n", ks_errno(ks));
	ks_close(ks);
	ks_free(binary);
	return true;
}




void obf::update_jcc_table()
{
	m_jcc_table.clear();

	//如果是，寻找跳转到的目标指令，和他的label

	char* p1 = m_obf_asm_buffer;
	for (size_t i = 0; i < m_count; i++)
	{
		//判断是否是jcc imm
		if (
			cs_insn_group(m_handle, &m_insn[i], CS_GRP_JUMP) &&
			m_insn[i].detail->x86.operands[0].type == X86_OP_IMM
			)
		{
			char filter[32] = {};
			size_t label = 0;
			//labelxx: jcc labelxx
			//labelxx: jcc imm
			sscanf_s(p1, "%s %s %s\n", filter, 32, filter, 32, filter, 32);
			if (filter[0] == '0')
			{
				DBG_PRINT("imm\n");
			}
			else if (filter[0] == 'l')
			{
				sscanf_s(filter, "label%d", &label);
				DBG_PRINT("label%d\n", label);
				m_jcc_table.push_back(label);
				goto find_next;
			}
			else {
				DBG_PRINT("error!!!!!!!!!!!!!!!!\n");
			}

		}
		m_jcc_table.push_back(-1);

	find_next:;
		p1 = strchr(p1, '\n');
		p1++;
	}



	// for(size_t i=0;i<m_count;i++)
	// {
	// 	//判断是否是jcc imm
	// 	if (
	// 		cs_insn_group(m_handle, &m_insn[i], CS_GRP_JUMP)&&
	// 		m_insn[i].detail->x86.operands[0].type == X86_OP_IMM
	// 		
	// 		)
	// 	{
	// 		//如果是，寻找跳转到的目标指令，和他的label
	// 		size_t target_address=0;
	// 		sscanf_s(m_insn[i].op_str, "%x", &target_address);
	// 		char* p1 = m_obf_asm_buffer;
	// 		for (size_t j = 0; j < m_count; j++)
	// 		{
	// 			if (target_address == m_insn[j].address)
	// 			{
	// 				//m_jcc_table.push_back(j);
	// 				size_t label = -1;
	// 				sscanf_s(p1, "label%d", &label);
	// 				m_jcc_table.push_back(label);
	// 				goto find_next;
	// 			}
	// 			p1 = strchr(p1, '\n');
	// 			p1++;
	// 		}
	// 		//没找到，这可能是个跨函数跳转
	// 		DBG_PRINT("fail to find jcc target\n");
	// 	}
	// 	m_jcc_table.push_back(-1);
	// 	find_next:;
	// }
}





/**
 * \brief 增加节
 * \param section_name	[in]新节名
*  \param buffer		[in]新节数据
 * \return 成功返回真，失败返回假
 */
bool obf::add_section(IN const char* section_name, IN const BYTE* buffer, IN const DWORD size)
{
	//获取最后一个区段的信息
	PIMAGE_SECTION_HEADER pLastSection = &m_pSectionHeader[m_pNtHeader->FileHeader.NumberOfSections - 1];

	//判断PE头是否有足够的空间添加新的区段
	//标准PE头
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)m_pNtHeader) + 0x4);
	//条件：SizeOfHeader - (DOS + 垃圾数据 + PE标记 + 标准PE头 + 可选PE头 + 已存在节表) >= 2个节表的大小 （如果只有一个节表以上的空间也可以加不会报错，但是会有安全隐患）
	DWORD rest_size = m_pNtHeader->OptionalHeader.SizeOfHeaders - (m_pDosHeader->e_lfanew + sizeof(m_pNtHeader->Signature) + sizeof(m_pNtHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((m_pNtHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER)));
	if (rest_size < sizeof(IMAGE_SECTION_HEADER))
	{
		//数据缓冲区太小无法添加节表！
		return false;
	}

	//1.修改区段数量
	m_pNtHeader->FileHeader.NumberOfSections += 1;
	//2.编辑区段表头结构体信息
	PIMAGE_SECTION_HEADER pAddSection = &m_pSectionHeader[m_pNtHeader->FileHeader.NumberOfSections - 1];
	memcpy_s(pAddSection->Name, 8, section_name, strlen(section_name));

	DWORD tmp = 0;
	//修改PE头文件属性，镜像大小
	tmp = (size / m_dwMemAlign) * m_dwMemAlign;
	if (size % m_dwMemAlign)
	{
		tmp += m_dwMemAlign;
	}
	m_pNtHeader->OptionalHeader.SizeOfImage += tmp;
	//VOffset(1000对齐)
	tmp = (pLastSection->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
	if (pLastSection->Misc.VirtualSize % m_dwMemAlign)
	{
		tmp += m_dwMemAlign;
	}
	pAddSection->VirtualAddress = pLastSection->VirtualAddress + tmp;
	//Vsize（实际添加的大小）
	pAddSection->Misc.VirtualSize = size;
	//ROffset（旧文件的末尾）
	pAddSection->PointerToRawData = m_dwFileSize;
	//RSize(200对齐)
	tmp = (size / m_dwFileAlign) * m_dwFileAlign;
	if (tmp != size) //if (size % m_dwFileAlign)
	{
		tmp += m_dwFileAlign;
	}
	pAddSection->SizeOfRawData = tmp;

	//标志 0xE0000040
	pAddSection->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	BYTE* pNewFileBuf = new BYTE[m_dwFileSize + tmp];
	DWORD new_size = m_dwFileSize + tmp;
	memset(pNewFileBuf, 0, new_size);
	memcpy_s(pNewFileBuf, new_size, m_pFileBuf, m_dwFileSize);
	memcpy_s(pNewFileBuf + m_dwFileSize, tmp, buffer, size);
	if (m_pFileBuf != nullptr)
	{
		delete[] m_pFileBuf;
		m_pFileBuf = nullptr;
	}
	m_pFileBuf = pNewFileBuf;
	m_dwFileSize = new_size;

	update_member();
	return true;
}

/**
 * \brief 保存文件
 * \return 成功返回真，失败返回假
 */
bool obf::save_file()
{
	//获取保存路径
	char output_path[MAX_PATH] = { 0 };
	const char* suffix = PathFindExtensionA(m_file_path);
	strncpy_s(output_path, MAX_PATH, m_file_path, strlen(m_file_path));
	PathRemoveExtensionA(output_path);
	strcat_s(output_path, MAX_PATH, "_new");
	strcat_s(output_path, MAX_PATH, suffix);

	HANDLE hNewFile = CreateFileA(output_path, GENERIC_READ | GENERIC_WRITE,
		0, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
	{
		//保存文件失败！
		return FALSE;
	}
	DWORD WriteSize = 0;
	BOOL result = WriteFile(hNewFile, m_pFileBuf, m_dwFileSize, &WriteSize, NULL);
	if (result)
	{
		CloseHandle(hNewFile);
		return TRUE;
	}
	else
	{
		CloseHandle(hNewFile);
		//保存文件失败！
		return FALSE;
	}
}





void obf::print_last_error_string()
{
	DWORD err_code = GetLastError();
	if (err_code == 0)
	{
		puts("没有错误信息\n");
		return;
	}
	char* buffer = nullptr;
	//int size = FormatMessageA
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL);
	printf("%s", buffer);
	LocalFree(buffer);
}


