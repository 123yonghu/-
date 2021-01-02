
#include<Windows.h>
#include <stdio.h>

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

	 LoadFile(fileName,&pFileBuffer);
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
	LoadFile(fileName,&pFileBuffer);
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
	pDosHeader=(PIMAGE_DOS_HEADER)pFileBuffer;
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
	pSectionHeaderBase = (PIMAGE_SECTION_HEADER)((BYTE*)pFileBuffer+pDosHeader->e_lfanew+sizeof(DWORD)\
		+sizeof(IMAGE_FILE_HEADER)+pNtHeaders->FileHeader.SizeOfOptionalHeader);
	return pSectionHeaderBase;
}





/*
 函数功能：FileBufferToImageBuffer
参数说明：pFileBuffer：文件缓冲指针
返回值：内存映像指针
注意：无
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
	NumberOfSections=pNtHeaders->FileHeader.NumberOfSections;
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
		memcpy((BYTE*)pImageBuffer+ pSectionHeader->VirtualAddress,
			(BYTE*)pFileBuffer+pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	return pImageBuffer;
}
/*
函数功能：ImageBufferToFileBuffer
参数说明：pImageBuffer：内存映像指针,FileSize：原FileBuffer大小
返回值：pFileBuffer
注意：无
*/
LPVOID ImageBufferToFileBuffer(LPVOID pImageBuffer,DWORD FileSize)
{
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	if (pNtHeaders == NULL)
	{
		printf("error");
		exit(0);
	}

	PIMAGE_SECTION_HEADER SectionBase = NULL;
	DWORD NumberOfSections = 0;
	LPVOID pFileBuffer = malloc(FileSize);
	if (pFileBuffer == NULL)
	{
		printf("cannot malloc");
		return NULL;
	}
	memset(pFileBuffer, 0, FileSize);
	memcpy(pFileBuffer, pImageBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

	SectionBase = LocateSectionBase(pImageBuffer);
	NumberOfSections = pNtHeaders->FileHeader.NumberOfSections;

	for (size_t i = 0; i < NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader =(PIMAGE_SECTION_HEADER)\
			((BYTE*) SectionBase + i * sizeof(IMAGE_SECTION_HEADER));
		memcpy((BYTE*)pFileBuffer + pSectionHeader->PointerToRawData,
			(BYTE*)pImageBuffer + pSectionHeader->VirtualAddress,
			pSectionHeader->SizeOfRawData);
	}

	printf("ImageBufferToFileBuffer end\n");
	return pFileBuffer;

}
/*
函数功能：从pFilBuffer指向的地址开始，FileSize大小的数据保存于str指定的绝对地址中
参数：文件缓冲指针，将保存文件的绝对地址，文件大小
返回值：无
注意：无
*/
void SaveFile(LPVOID pFileBuffer,const char* str,DWORD FileSize)
{
	FILE* fp;
	fopen_s(&fp, str, "wb");
	if (fp == NULL)
	{
		printf("cannot open %s", str);
		return;
	}
	fwrite(pFileBuffer,FileSize ,1,fp);
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
DWORD RVAtoFOA(DWORD RVA,LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	PIMAGE_SECTION_HEADER SectionBase = LocateSectionBase(pImageBuffer);
	WORD NumberOfSection = 0;
	if (pNtHeaders == NULL||SectionBase==NULL)
	{
		printf("无法找到指针指向的NT头或节表基址");
		return -1;
	}
	NumberOfSection=pNtHeaders->FileHeader.NumberOfSections;
	for (size_t i = 0; i < NumberOfSection; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + i * sizeof(IMAGE_SECTION_HEADER));
		PIMAGE_SECTION_HEADER pNextSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + (i+1) * sizeof(IMAGE_SECTION_HEADER));
		if (i == NumberOfSection - 1)
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		else if (RVA > pSectionHeader->VirtualAddress && RVA<pNextSectionHeader->VirtualAddress)
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	return 0;


}
