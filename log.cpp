#include <stdarg.h>
#include <iostream>
using namespace std;
 
void EventLog(int pr,const char *fmt, ...) 
{
   va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "Info: ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    return;   
}
