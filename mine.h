#include<Windows.h>
#include <stdio.h>
DWORD LoadFile(const char* fileName, LPVOID* ppfBuffer);//加载文件
void showPEheader(const char* fileName);//show PE头
void showSection(const char* fileName);//show 节
PIMAGE_NT_HEADERS FileToNtHeader(LPVOID pFileBuffer);//定位NT头
LPVOID ImageBufferToFileBuffer(LPVOID pImageBuffer, DWORD FileSize);//从ImageBuffer转为FileBuffer
LPVOID FileBufferToImageBuffer(LPVOID pFileBuffer);//从FileBuffer转为ImageBuffer
PIMAGE_SECTION_HEADER LocateSectionBase(LPVOID pFileBuffer);//定位第一个节的地址
void SaveFile(LPVOID pFileBuffer, const char* str, DWORD FileSize);//保存文件
DWORD RVAtoFOA(DWORD RVA, LPVOID pImageBuffer);//RVA to FOA
