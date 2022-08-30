#pragma once
#include <string>

// Arguments
extern int argVerboseLevel;
extern std::string argFilename;
extern std::string argOutputFilename;

void parseArg(int argc, char *argv[]);