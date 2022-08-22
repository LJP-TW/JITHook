#include <Windows.h>

#include <stdio.h>
#include <stdarg.h>

#include "args.h"
#include "log.h"

#define COLOR_ERR BACKGROUND_RED
#define COLOR_WARNING FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN
#define COLOR_INFO FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE
#define COLOR_DEBUG BACKGROUND_INTENSITY

int logPrintf(int level, const char *format, ...)
{
    va_list args;
    int ret;
    HANDLE hConsole;
    int color = 0;

    if (level > argVerboseLevel) {
        return 0;
    }

    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (level == LOG_LEVEL_ERR) {
        color = COLOR_ERR;
    } else if (level == LOG_LEVEL_WARNING) {
        color = COLOR_WARNING;
    } else if (level == LOG_LEVEL_INFO) {
        color = COLOR_INFO;
    } else {
        color = COLOR_DEBUG;
    }

    SetConsoleTextAttribute(hConsole, color);

    va_start(args, format);

    ret = vprintf(format, args);

    va_end(args);

    SetConsoleTextAttribute(hConsole, COLOR_INFO);

    return ret;
}