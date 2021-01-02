/*


#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#define notepadLocation "C:\\Users\\86156\\Desktop\\notepad.exe"
int main()
{

    FILE* fp,*to_write;
    char* buffer;
    size_t byte_count;
    char a;

    fopen_s(&fp, notepadLocation, "rb");
    fopen_s(&to_write, "C:\\Users\\86156\\Desktop\\newNotepad.exe", "wb");
    if (fp == NULL||to_write==NULL)
    {
        printf("error in opening %s or %s ", notepadLocation, "C:\\Users\\86156\\Desktop\\newNotepad");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    byte_count = ftell(fp);

    fseek(fp, 0, SEEK_SET);

    buffer = (char*)malloc(byte_count);
    if (buffer == NULL)
    {
        puts("cannot malloc");
        exit(EXIT_FAILURE);
    }
    memset(buffer, 0, byte_count );

    fread(buffer, 1, byte_count, fp);
    if (ferror(fp))
         exit(EXIT_FAILURE);
    fwrite(buffer, 1, byte_count, to_write);



    free(buffer);
    if (fclose(fp) && fclose(to_write))
    {
        printf("error in close file");
        exit(EXIT_FAILURE);
    }
    printf("WELL DONE  byte_count=%d ",byte_count);





    return  0;
}


*/