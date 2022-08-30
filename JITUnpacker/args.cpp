#include <iostream>
#include <vector>
#include <string>

#include "log.h"

// Default target dotnet exe
#define PACKED_ASSEMBLY_NAME "JIThook.exe"
#define UNPACKED_ASSEMBLY_NAME "output.exe_"

// Arguments
int argVerboseLevel = LOG_LEVEL_INFO;
std::string argFilename;
std::string argOutputFilename;

void parseArg(int argc, char *argv[])
{
    if (argc <= 1)
        return;

    std::vector<std::string> args(&argv[1], &argv[argc]);

    for (auto arg = args.begin(); arg != args.end(); arg++) {
        if (*arg == "-v") {
            arg++;
            argVerboseLevel = stoi(*arg);
        } else if (*arg == "-o") {
            arg++;
            argOutputFilename = *arg;
        } else {
            argFilename = *arg;
        }
    }

    if (argFilename.empty()) {
        argFilename = PACKED_ASSEMBLY_NAME;
    }

    if (argOutputFilename.empty()) {
        argOutputFilename = UNPACKED_ASSEMBLY_NAME;
    }
}