#ifndef _dump_include
#define _dump_include

#include "stdafx.h"
#include "Windows.h"
#include "DbgHelp.h"

int GenerateMiniDump(PEXCEPTION_POINTERS pExceptionPointers);
LONG WINAPI ExceptionFilter(LPEXCEPTION_POINTERS lpExceptionInfo);

#endif