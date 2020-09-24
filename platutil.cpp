
#include <string>
#include <string.h>

#include <stdio.h>
#include <io.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include "log.h"
#include "platutil.h"

////////////////////////////////////////////////////////////////////////////////
//
// Name : CopyFile
//
// Description: Provide a routine to copy a file from one spot to another
// instead of shelling out to use 'cp'.
//
////////////////////////////////////////////////////////////////////////////////
bool CopyFile(const char *src, const char *dst, int dst_mode, off_t offset)
{
    char cmd[100] = {0};
    sprintf(cmd, "cp %s %s", src, dst);
    char result[1025];
    ExecuteCMD(cmd, result);
    return true;
}

string GetFileNameFromPath(string path)
{

    int pos = path.find_last_of('/');
    if (pos <= 0)
    {
        return "";
    }
    return path.substr(pos + 1);
}
string GetFileSuffixFromPath(string path){
        int pos = path.find_last_of('.');
    if (pos ==string::npos)
    {
        return "";
    }
    return path.substr(pos+1);
}
void ExecuteCMD(const char *cmd, char *result)
{
    const int BUF_SIZE = 2048;
    char buf_ps[BUF_SIZE + 1] = {0};
    char ps[BUF_SIZE + 1] = {0};

    FILE *ptr;
    strncpy(ps, cmd, BUF_SIZE);
    if ((ptr = popen(ps, "r")) != NULL)
    {
        while (fgets(buf_ps, BUF_SIZE, ptr) != NULL)
        {
            strcat(result, buf_ps);
            if (strlen(result) > BUF_SIZE)
                break;
        }
        pclose(ptr);
        ptr = NULL;
    }
    else
    {
        printf("popen %s error\n", ps);
    }
}
