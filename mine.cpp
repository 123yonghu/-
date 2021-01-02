
#include<Windows.h>
#include <stdio.h>

/*
* �������ܣ������ļ�
* ����˵����filename���ļ���
* ����ֵ��ͨ��malloc������ڴ�Ĵ�С�����޷������򷵻�0
* ʹ�øú�������Ҫ����free���������ͷŶѿռ�
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
	* �������ܣ���ӡPEͷ��Ϣ
	* ����˵����filename���ļ���
	* ����ֵ����
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
	//�ж��Ƿ�ΪMZ
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	printf("***********DOS Header**********\n");
	printf("pDosHeader->e_magic	MZ ��־:%x\n", pDosHeader->e_magic);
	printf("pDosHeader->e_lfanew	PE ƫ��:%x\n", pDosHeader->e_lfanew);
	//�ж�PEƫ���Ƿ���Ч
	if (*(PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־");
		free(pFileBuffer);
		return;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	printf("*********NT Header**************\n");
	printf("pNtHeaders->Signature	PE ��־ :%x\n", pNtHeaders->Signature);
	puts("*********PE Header**************");
	printf("FileHeader.Machine		CPUƽ̨:%x\n", pNtHeaders->FileHeader.Machine);
	printf("pNtHeaders->FileHeader.NumberOfSections	PE�ļ�����������:%x\n", pNtHeaders->FileHeader.NumberOfSections);
	printf("pNtHeaders->FileHeader.Characteristics		(�����ļ����ԣ�:%x\n", pNtHeaders->FileHeader.Characteristics);
	puts("*********Optional PE Header**************");
	printf("pNtHeaders->OptionalHeader.Magic	��ѡPEͷ������%x\n", pNtHeaders->OptionalHeader.Magic);
	printf("pNtHeaders->OptionalHeader.AddressOfEntryPoint		:OEP������ڵ� %x\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("ImageBase      	:%x\n", pNtHeaders->OptionalHeader.ImageBase);






	free(pFileBuffer);

	return;
}
/*
	* �������ܣ���ӡ���н���Ϣ
	* ����˵����filename���ļ���
	* ����ֵ����
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
		printf("���Ǳ�׼��PE�ļ�");
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
	* �������ܣ�Ѱ��DOSͷ
	* ����˵����pFileBuffer���ļ�����ָ��
	* ����ֵ��DOSͷָ��
	*ע�⣺��
	*/
PIMAGE_DOS_HEADER FileToDosHeader(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (pFileBuffer == NULL)
	{
		printf("������NULL");
		return NULL;
	}
	//���MZͷ
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("���Ǳ�׼MZͷ��");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}



/*
�������ܣ������ļ�������ָ�룬����NTͷָ��
�������ļ�������ָ��
����ֵ�������������ϱ�׼PE�ļ�������NTͷ�����򷵻�NULL
ע�⣺��
*/
PIMAGE_NT_HEADERS FileToNtHeader(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	if (pFileBuffer == NULL)
	{
		printf("FileToNtHeader����������NULL");
		return NULL;
	}
	//���MZͷ
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("���Ǳ�׼MZͷ��");
		return NULL;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)pFileBuffer;
	//���PEǩ��
	if (*(DWORD*)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer) != IMAGE_NT_SIGNATURE)
	{
		printf("���Ǳ�׼NTͷ��");
		return NULL;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	return pNtHeaders;
}
/*
�������ܣ������ļ�������ָ�룬���ص�һ���ڱ�ĵ�ַ
�������ļ�������ָ��
����ֵ�������������ϱ�׼PE�ļ������ص�һ���ڱ�ĵ�ַ�����򷵻�NULL
ע�⣺��
*/
PIMAGE_SECTION_HEADER LocateSectionBase(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	if (pFileBuffer == NULL)
	{
		printf("������NULL");
		return NULL;
	}
	//���MZͷ
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("���Ǳ�׼MZͷ��");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//���PEǩ��
	if (*(DWORD*)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer) != IMAGE_NT_SIGNATURE)
	{
		printf("���Ǳ�׼NTͷ��");
		return NULL;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	pSectionHeaderBase = (PIMAGE_SECTION_HEADER)((BYTE*)pFileBuffer+pDosHeader->e_lfanew+sizeof(DWORD)\
		+sizeof(IMAGE_FILE_HEADER)+pNtHeaders->FileHeader.SizeOfOptionalHeader);
	return pSectionHeaderBase;
}





/*
 �������ܣ�FileBufferToImageBuffer
����˵����pFileBuffer���ļ�����ָ��
����ֵ���ڴ�ӳ��ָ��
ע�⣺��
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
		printf("NTͷΪ�գ�\n");
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
�������ܣ�ImageBufferToFileBuffer
����˵����pImageBuffer���ڴ�ӳ��ָ��,FileSize��ԭFileBuffer��С
����ֵ��pFileBuffer
ע�⣺��
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
�������ܣ���pFilBufferָ��ĵ�ַ��ʼ��FileSize��С�����ݱ�����strָ���ľ��Ե�ַ��
�������ļ�����ָ�룬�������ļ��ľ��Ե�ַ���ļ���С
����ֵ����
ע�⣺��
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
�������ܣ�ת��RVAΪFOA������֮
������RVA���ڴ�ӳ��ָ��
����ֵ��FOA��ת��ʧ���򷵻�-1
ע�⣺��
*/
DWORD RVAtoFOA(DWORD RVA,LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	PIMAGE_SECTION_HEADER SectionBase = LocateSectionBase(pImageBuffer);
	WORD NumberOfSection = 0;
	if (pNtHeaders == NULL||SectionBase==NULL)
	{
		printf("�޷��ҵ�ָ��ָ���NTͷ��ڱ��ַ");
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
