#pragma once

enum LOG_LEVEL
{
	LOG_LEVEL_ERR		= 0,
	LOG_LEVEL_WARNING	= 1,
	LOG_LEVEL_INFO		= 2,
	LOG_LEVEL_DEBUG		= 3,
};

int logPrintf(int level, const char *format, ...);