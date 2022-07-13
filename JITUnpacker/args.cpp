#include <iostream>
#include <vector>
#include <string>

// Default target dotnet exe
#define PACKED_ASSEMBLY_NAME "JIThook.exe"

// Arguments
int argVerboseLevel;
std::string argFilename;

void parseArg(int argc, char *argv[])
{
    if (argc <= 1)
        return;

    std::vector<std::string> args(&argv[1], &argv[argc]);

    for (auto arg = args.begin(); arg != args.end(); arg++) {
        if (*arg == "-v") {
            arg++;
            argVerboseLevel = stoi(*arg);
        }
        else {
            argFilename = *arg;
        }
    }

    if (argFilename.empty()) {
        argFilename = PACKED_ASSEMBLY_NAME;
    }
}