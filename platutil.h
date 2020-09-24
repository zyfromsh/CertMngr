#ifndef _platutil_include
#define  _platutil_include
#include <string>
using namespace std;
bool CopyFile(const char *src, const char *dst, int dst_mode, off_t offset);
string GetFileNameFromPath(string path);
string GetFileSuffixFromPath(string path);
void ExecuteCMD(const char *cmd, char *result);
#endif