#include<Windows.h>
#include <stdio.h>
DWORD LoadFile(const char* fileName, LPVOID* ppfBuffer);//�����ļ�
void showPEheader(const char* fileName);//show PEͷ
void showSection(const char* fileName);//show ��
PIMAGE_NT_HEADERS FileToNtHeader(LPVOID pFileBuffer);//��λNTͷ
LPVOID ImageBufferToFileBuffer(LPVOID pImageBuffer, DWORD FileSize);//��ImageBufferתΪFileBuffer
LPVOID FileBufferToImageBuffer(LPVOID pFileBuffer);//��FileBufferתΪImageBuffer
PIMAGE_SECTION_HEADER LocateSectionBase(LPVOID pFileBuffer);//��λ��һ���ڵĵ�ַ
void SaveFile(LPVOID pFileBuffer, const char* str, DWORD FileSize);//�����ļ�
DWORD RVAtoFOA(DWORD RVA, LPVOID pImageBuffer);//RVA to FOA
