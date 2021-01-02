#include<Windows.h>
#include <stdio.h>
#include "mine.h"
#define MESSAGE_BOX_ADDRESS (DWORD)&MessageBox
/*
* 函数功能：加载文件
* 参数说明：filename：文件名
* 返回值：通过malloc分配的内存的大小，若无法分配则返回0
* 使用该函数后需要调用free（）函数释放堆空间
*/
DWORD LoadFile(const char* fileName, LPVOID* ppfBuffer)
{
	FILE* fp;
	DWORD FileSize = 0;
	fopen_s(&fp, fileName, "rb");
	if (fp == NULL)
	{
		printf("cannot open %s", fileName);
		exit(EXIT_FAILURE);
	}
	fseek(fp, 0, SEEK_END);
	FileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	*ppfBuffer = (LPVOID*)malloc(FileSize);
	if (*ppfBuffer == NULL)
	{
		printf("cannot malloc");
		return 0;
	}

	memset(*ppfBuffer, 0, FileSize);
	fread(*ppfBuffer, FileSize, 1, fp);
	if (fclose(fp) != 0)
	{
		printf("cannot close file");
		exit(EXIT_FAILURE);
	}
	return FileSize;

	/*
	* 函数功能：打印PE头信息
	* 参数说明：filename：文件名
	* 返回值：无
	*
	*/
}
void showPEheader(const char* fileName)
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	LoadFile(fileName, &pFileBuffer);
	if (pFileBuffer == NULL)
	{
		printf("cannot open file");
		exit(EXIT_FAILURE);
	}
	//判断是否为MZ
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	printf("***********DOS Header**********\n");
	printf("pDosHeader->e_magic	MZ 标志:%x\n", pDosHeader->e_magic);
	printf("pDosHeader->e_lfanew	PE 偏移:%x\n", pDosHeader->e_lfanew);
	//判断PE偏移是否有效
	if (*(PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志");
		free(pFileBuffer);
		return;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	printf("*********NT Header**************\n");
	printf("pNtHeaders->Signature	PE 标志 :%x\n", pNtHeaders->Signature);
	puts("*********PE Header**************");
	printf("FileHeader.Machine		CPU平台:%x\n", pNtHeaders->FileHeader.Machine);
	printf("pNtHeaders->FileHeader.NumberOfSections	PE文件中区块数量:%x\n", pNtHeaders->FileHeader.NumberOfSections);
	printf("pNtHeaders->FileHeader.Characteristics		(描述文件属性）:%x\n", pNtHeaders->FileHeader.Characteristics);
	puts("*********Optional PE Header**************");
	printf("pNtHeaders->OptionalHeader.Magic	可选PE头幻数：%x\n", pNtHeaders->OptionalHeader.Magic);
	printf("pNtHeaders->OptionalHeader.AddressOfEntryPoint		:OEP程序入口点 %x\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("ImageBase      	:%x\n", pNtHeaders->OptionalHeader.ImageBase);






	free(pFileBuffer);

	return;
}
/*
	* 函数功能：打印所有节信息
	* 参数说明：filename：文件名
	* 返回值：无
	*
	*/
void showSection(const char* fileName)
{
	LPVOID pFileBuffer = NULL;
	LoadFile(fileName, &pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if (pFileBuffer == NULL)
	{
		printf("cannot load file");
		return;
	}

	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是标准的PE文件");
		return;
	}

	printf("*******Section *********\n");
	WORD sectionNum = pNtHeader->FileHeader.NumberOfSections;
	LPVOID base = (LPVOID)(pDosHeader->e_lfanew + sizeof(DWORD) + (BYTE*)pFileBuffer + sizeof(_IMAGE_FILE_HEADER)\
		+ pNtHeader->FileHeader.SizeOfOptionalHeader);

	for (size_t i = 0; i < sectionNum; i++)
	{
		LPVOID nowSection = (LPVOID)((BYTE*)base + i * sizeof(_IMAGE_SECTION_HEADER));
		pSectionHeader = (PIMAGE_SECTION_HEADER)nowSection;
		printf("*******Section %u*********\n", i);

		printf("name:");
		for (size_t i = 0; i < 8; i++)
		{
			printf("%c", pSectionHeader->Name[i]);
		}
		printf("\n");
		printf("VirtualAddress:%x\n", pSectionHeader->VirtualAddress);
		printf("PointerToRawData:%x\n", pSectionHeader->PointerToRawData);
		printf("MISC:%x\n", pSectionHeader->Misc.VirtualSize);
		printf("SizeOfRawData:%x\n", pSectionHeader->SizeOfRawData);

	}
	free(pFileBuffer);
	printf("END SECTION");
	return;
}
/*
	* 函数功能：寻找DOS头
	* 参数说明：pFileBuffer：文件缓冲指针
	* 返回值：DOS头指针
	*注意：无
	*/
PIMAGE_DOS_HEADER FileToDosHeader(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (pFileBuffer == NULL)
	{
		printf("不接受NULL");
		return NULL;
	}
	//检测MZ头
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是标准MZ头！");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}



/*
函数功能：接受文件缓冲区指针，返回NT头指针
参数：文件缓冲区指针
返回值：如果鉴别出符合标准PE文件，返回NT头，否则返回NULL
注意：无
*/
PIMAGE_NT_HEADERS FileToNtHeader(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	if (pFileBuffer == NULL)
	{
		printf("FileToNtHeader函数不接受NULL");
		return NULL;
	}
	//检测MZ头
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是标准MZ头！");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//检测PE签名
	if (*(DWORD*)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer) != IMAGE_NT_SIGNATURE)
	{
		printf("不是标准NT头！");
		return NULL;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	return pNtHeaders;
}
/*
函数功能：接受文件缓冲区指针，返回第一个节表的地址
参数：文件缓冲区指针
返回值：如果鉴别出符合标准PE文件，返回第一个节表的地址，否则返回NULL
注意：无
*/
PIMAGE_SECTION_HEADER LocateSectionBase(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	if (pFileBuffer == NULL)
	{
		printf("不接受NULL");
		return NULL;
	}
	//检测MZ头
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是标准MZ头！");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//检测PE签名
	if (*(DWORD*)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer) != IMAGE_NT_SIGNATURE)
	{
		printf("不是标准NT头！");
		return NULL;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	pSectionHeaderBase = (PIMAGE_SECTION_HEADER)((BYTE*)pFileBuffer + pDosHeader->e_lfanew + sizeof(DWORD)\
		+ sizeof(IMAGE_FILE_HEADER) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	return pSectionHeaderBase;
}





/*
 函数功能：FileBufferToImageBuffer
参数说明：pFileBuffer：文件缓冲指针
返回值：内存映像指针
注意：用完记得free（）哦
*/
LPVOID FileBufferToImageBuffer(LPVOID pFileBuffer)
{
	DWORD SizeOfImage = 0;
	DWORD SizeOfHeaders = 0;
	WORD NumberOfSections = 0;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	LPVOID pImageBuffer = NULL;

	if (pFileBuffer == NULL)
	{
		printf("cannot transform NULL\n");
		return NULL;
	}
	pNtHeaders = FileToNtHeader(pFileBuffer);
	if (pNtHeaders == NULL)
	{
		printf("NT头为空！\n");
		return NULL;
	}
	SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	SizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
	NumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	pSectionHeaderBase = LocateSectionBase(pFileBuffer);

	pImageBuffer = malloc(SizeOfImage);
	if (pImageBuffer == NULL)
	{
		printf("cannot malloc memory");
		return NULL;
	}

	memset(pImageBuffer, 0, SizeOfImage);
	memcpy(pImageBuffer, pFileBuffer, SizeOfHeaders);

	for (size_t i = 0; i < NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)pSectionHeaderBase + sizeof(IMAGE_SECTION_HEADER) * i);
		memcpy((BYTE*)pImageBuffer + pSectionHeader->VirtualAddress,
			(BYTE*)pFileBuffer + pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	return pImageBuffer;
}
/*
函数功能：ImageBufferToFileBuffer
参数说明：pImageBuffer：内存映像指针
返回值：pFileBuffer
注意：记得free（）哦
*/
LPVOID ImageBufferToFileBuffer(LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	DWORD FileSize = 0;
	PIMAGE_SECTION_HEADER SectionBase = NULL;
	DWORD NumberOfSections = 0;
	if (pNtHeaders == NULL)
	{
		printf("error");
		exit(0);
	}
	SectionBase = LocateSectionBase(pImageBuffer);
	NumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)\
		((BYTE*)SectionBase + (NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));
	FileSize = pLastSection->SizeOfRawData + pLastSection->PointerToRawData;
	LPVOID pFileBuffer = malloc(FileSize);
	if (pFileBuffer == NULL)
	{
		printf("cannot malloc");
		return NULL;
	}
	memset(pFileBuffer, 0, FileSize);
	memcpy(pFileBuffer, pImageBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);



	for (size_t i = 0; i < NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + i * sizeof(IMAGE_SECTION_HEADER));
		memcpy((BYTE*)pFileBuffer + pSectionHeader->PointerToRawData,
			(BYTE*)pImageBuffer + pSectionHeader->VirtualAddress,
			pSectionHeader->SizeOfRawData);
	}


	return pFileBuffer;

}
/*
函数功能：从pFilBuffer指向的地址开始，FileSize大小的数据保存于str指定的绝对地址中
参数：文件缓冲指针，将保存文件的绝对地址，文件大小
返回值：无
注意：无
*/
void SaveFile(LPVOID pFileBuffer, const char* str, DWORD FileSize)
{
	FILE* fp;
	fopen_s(&fp, str, "wb");
	if (fp == NULL)
	{
		printf("cannot open %s", str);
		return;
	}
	fwrite(pFileBuffer, FileSize, 1, fp);
	if (fclose(fp) != 0)
	{
		printf("cannot close %s", str);
		return;
	}
	return;
}
/*
函数功能：转换RVA为FOA，返回之
参数：RVA，内存映像指针
返回值：FOA，转换失败则返回-1
注意：无
*/
DWORD RVAtoFOA(DWORD RVA, LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	PIMAGE_SECTION_HEADER SectionBase = LocateSectionBase(pImageBuffer);
	WORD NumberOfSection = 0;
	if (pNtHeaders == NULL || SectionBase == NULL)
	{
		printf("无法找到指针指向的NT头或节表基址");
		return -1;
	}
	NumberOfSection = pNtHeaders->FileHeader.NumberOfSections;
	for (size_t i = 0; i < NumberOfSection; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + i * sizeof(IMAGE_SECTION_HEADER));
		PIMAGE_SECTION_HEADER pNextSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + (i + 1) * sizeof(IMAGE_SECTION_HEADER));
		if (i == NumberOfSection - 1)
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		else if (RVA > pSectionHeader->VirtualAddress && RVA < pNextSectionHeader->VirtualAddress)
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	return 0;


}
/*
函数功能：在代码节添加shellcode
参数：pFileBuffer：文件缓冲区指针,ShellCode:以字节为单位
的16进制shellcode，ShellCodeLen：ShellCode长度
返回值：成功添加则返回1，否则返回0
注意:此函数假定第一个节就是代码区,且此函数使用多个其他内置函数
另外默认shellcode最后为E9 00 00 00 00 E8 00 00 00 00
*/
BOOL AddCodeToTextSection(LPVOID* pFileBuffer, BYTE* ShellCode, DWORD ShellCodeLen)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pTextSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSecondSectionHeader = NULL;
	LPVOID pImageBuffer = NULL;
	DWORD OrigionalOEP = 0;
	int iShellCodeBaseAddress = 0;
	long Offset = 0;
	if (*pFileBuffer == NULL)
	{
		printf("AddCodeToTextSection函数不接受NULL！");
		return 0;
	}
	pNtHeaders = FileToNtHeader(*pFileBuffer);
	if (pNtHeaders == NULL)
	{
		printf("不是标准PE文件!");
		return 0;
	}
	pTextSectionHeader = LocateSectionBase(*pFileBuffer);
	pSecondSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pTextSectionHeader + sizeof(IMAGE_SECTION_HEADER));
	if (pTextSectionHeader == NULL)
	{
		printf("不是标准PE文件!");
		return 0;
	}
	//5为 jmp原oep 的指令长
	if (ShellCodeLen > (pSecondSectionHeader->VirtualAddress - \
		(pTextSectionHeader->Misc.VirtualSize + pTextSectionHeader->VirtualAddress)))
	{
		printf("代码区剩余空间不足");
		return 0;
	}
	iShellCodeBaseAddress = pTextSectionHeader->Misc.VirtualSize + pTextSectionHeader->VirtualAddress;
	//计算Call偏移
	DWORD CallOffset = MESSAGE_BOX_ADDRESS - (iShellCodeBaseAddress + ShellCodeLen - 5 + pNtHeaders->OptionalHeader.ImageBase);
	for (size_t i = 1; i <= 4; i++)
	{
		ShellCode[ShellCodeLen - 5 - i] = CallOffset >> ((4 - i) * 8) & 0xFF;
	}


	//计算jmp偏移
	OrigionalOEP = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	Offset = OrigionalOEP - (iShellCodeBaseAddress + ShellCodeLen);
	for (size_t i = 1; i <= 4; i++)
	{
		ShellCode[ShellCodeLen - i] = Offset >> ((4 - i) * 8) & 0xFF;
	}


	//移动ShellCode到代码空白区
	pImageBuffer = FileBufferToImageBuffer(*pFileBuffer);
	memcpy((BYTE*)pImageBuffer + iShellCodeBaseAddress,
		ShellCode,
		ShellCodeLen);
	//修改OEP
	PIMAGE_NT_HEADERS cao = FileToNtHeader(pImageBuffer);
	cao->OptionalHeader.AddressOfEntryPoint = iShellCodeBaseAddress;
	//保存
	free(*pFileBuffer);
	*pFileBuffer = ImageBufferToFileBuffer(pImageBuffer);
	return 1;
}
/*
函数功能：在任一节添加shellcode
参数：iSection:添加ShellCode的节的编号pFileBuffer：文件缓冲区指针
,ShellCode:16进制shellcode，ShellCodeLen：ShellCode长度
返回值：成功添加则返回1，否则返回0
注意:此函数假定第一个节就是代码区,且此函数使用多个其他内置函数
另外默认shellcode最后为E9 00 00 00 00 E8 00 00 00 00
*/
BOOL AddCodeToSection(DWORD iSection, LPVOID* pFileBuffer, BYTE* ShellCode, DWORD ShellCodeLen)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSecondSectionHeader = NULL;
	LPVOID pImageBuffer = NULL;
	DWORD NumberOfSections = 0;
	DWORD OrigionalOEP = 0;
	int iShellCodeBaseAddress = 0;
	long Offset = 0;
	if (*pFileBuffer == NULL)
	{
		printf("AddCodeToSection函数不接受NULL！");
		return 0;
	}
	pNtHeaders = FileToNtHeader(*pFileBuffer);
	if (pNtHeaders == NULL)
	{
		printf("不是标准PE文件!");
		return 0;
	}
	NumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	if (iSection > NumberOfSections)
	{
		printf("超出节的范围");
		return 0;
	}
	pSectionHeader = iSection - 1 + LocateSectionBase(*pFileBuffer);
	pSecondSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pSectionHeader + sizeof(IMAGE_SECTION_HEADER));
	if (pSectionHeader == NULL)
	{
		printf("不是标准PE文件!");
		return 0;
	}
	if (iSection == NumberOfSections)
	{
		printf("不想考虑这一层");
		return 0;
	}
	else if (ShellCodeLen > (pSecondSectionHeader->VirtualAddress - \
		(pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress)))
	{
		printf("该节剩余空间不足");
		return 0;
	}
	iShellCodeBaseAddress = pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress;
	//计算Call偏移
	DWORD CallOffset = MESSAGE_BOX_ADDRESS - (iShellCodeBaseAddress + ShellCodeLen - 5 + pNtHeaders->OptionalHeader.ImageBase);
	for (size_t i = 1; i <= 4; i++)
	{
		ShellCode[ShellCodeLen - 5 - i] = CallOffset >> ((4 - i) * 8) & 0xFF;
	}


	//计算jmp偏移
	OrigionalOEP = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	Offset = OrigionalOEP - (iShellCodeBaseAddress + ShellCodeLen);
	for (size_t i = 1; i <= 4; i++)
	{
		ShellCode[ShellCodeLen - i] = Offset >> ((4 - i) * 8) & 0xFF;
	}

	//移动ShellCode到代码空白区
	pImageBuffer = FileBufferToImageBuffer(*pFileBuffer);
	memcpy((BYTE*)pImageBuffer + iShellCodeBaseAddress,
		ShellCode,
		ShellCodeLen);
	//修改节的属性
	pSectionHeader->Characteristics |= (pSectionHeader - (iSection - 1))->Characteristics;
	//修改OEP
	PIMAGE_NT_HEADERS pImageNtHeader = FileToNtHeader(pImageBuffer);
	pImageNtHeader->OptionalHeader.AddressOfEntryPoint = iShellCodeBaseAddress;
	//保存
	free(*pFileBuffer);
	*pFileBuffer = ImageBufferToFileBuffer(pImageBuffer);
	return 1;
}
/*
内置用于解决对齐问题的函数
*/
DWORD ALIGNING(DWORD size, DWORD aligning)
{
	return size % aligning ? (size / aligning + 1) * aligning : size;
}



/*
函数功能：在PE文件末尾添加一个节
参数：pFileBuffer:文件缓冲区指针，*SectionName:节的名字（字符串首地址）
iVirtualSize：节的VirtualSize，iCharacters:节的属性
返回值：成功添加返回添加后PE文件的大小，否则返回0
注意：若节表与节中间空隙不足，则舍弃DosStub（头向上移）
此函数使用多个其他内置函数,不考虑无节表的情况
*/
DWORD AddSectionAtLast(LPVOID* pFileBuffer, CONST CHAR* SectionName, DWORD iVirtualSize, DWORD iCharacters)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionBase = NULL;
	PIMAGE_SECTION_HEADER pNewSectionHeader = NULL;
	DWORD FileAligning = 0;
	DWORD SectionAligning = 0;
	DWORD NumberOfSection = 0;
	DWORD BlankArea = 0;
	DWORD iReturnFileSize = 0;
	if (*pFileBuffer == NULL)
	{
		printf("pFileBuffer函数不接受NULL!");
		return 0;
	}
	pNtHeaders = FileToNtHeader(*pFileBuffer);
	if (pNtHeaders == NULL)
	{
		printf("不是标准PE头！");
		return 0;
	}
	FileAligning = pNtHeaders->OptionalHeader.FileAlignment;
	SectionAligning = pNtHeaders->OptionalHeader.SectionAlignment;
	NumberOfSection = pNtHeaders->FileHeader.NumberOfSections;
	pSectionBase = LocateSectionBase(*pFileBuffer);
	BlankArea = pNtHeaders->OptionalHeader.SizeOfHeaders
		- (NumberOfSection) * sizeof(IMAGE_SECTION_HEADER);
	if (BlankArea >= 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		pNewSectionHeader = pSectionBase + NumberOfSection;

		//重置内存空间
		memset((void*)pNewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
		//改名
		memcpy((VOID*)pNewSectionHeader, (VOID*)SectionName, 8);
		//改iVirtualSize
		pNewSectionHeader->Misc.VirtualSize = iVirtualSize;
		//改virtualAddress
		pNewSectionHeader->VirtualAddress = (pNewSectionHeader - 1)->VirtualAddress\
			+ ALIGNING((pNewSectionHeader - 1)->Misc.VirtualSize, SectionAligning);
		//改SizeOfRawData
		pNewSectionHeader->SizeOfRawData = ALIGNING(iVirtualSize, FileAligning);
		//改PointToRawData
		pNewSectionHeader->PointerToRawData = (pNewSectionHeader - 1)->PointerToRawData\
			+ (pNewSectionHeader - 1)->SizeOfRawData;
		//改characters
		pNewSectionHeader->Characteristics = iCharacters;
		//改SizeOfImage
		pNtHeaders->OptionalHeader.SizeOfImage += ALIGNING(iVirtualSize, SectionAligning);
		//改NumberOfSection
		pNtHeaders->FileHeader.NumberOfSections += 1;
		//增节
		iReturnFileSize = (pNewSectionHeader - 1)->PointerToRawData\
			+ (pNewSectionHeader - 1)->SizeOfRawData + pNewSectionHeader->SizeOfRawData;
		realloc(*pFileBuffer, iReturnFileSize);
		if (*pFileBuffer == NULL)
		{
			printf("内存重新分配失败");
			return 0;
		}
		//增加的节全置CC
		//memset((void**)(*pFileBuffer) + pNewSectionHeader->PointerToRawData, 0xCC, pNewSectionHeader->SizeOfRawData);
		return iReturnFileSize;
	}
	else
	{
		printf("等一下再写");
		return 0;
	}
}
