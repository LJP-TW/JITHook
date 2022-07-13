#include <stdio.h>
#include <stdarg.h>

#include "args.h"

int logPrintf(int level, const char *format, ...)
{
    if (level > argVerboseLevel) {
        return 0;
    }

    va_list args;
    int ret;

    va_start(args, format);

    ret = vprintf(format, args);

    va_end(args);

    return ret;
}