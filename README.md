# JITHOOK
The goal of this repository is to show you techniques for packing/unpacking .NET assemblies (programs) by abusing .NET's JIT mechanism.

# Build
1. Clone this project
    ```
    git clone --recursive https://github.com/LJP-TW/JITHook.git
    ```
2. Install [lief-project/LIEF](https://github.com/lief-project/LIEF).
    * Download [LIEF-0.12.1-win64.zip](https://github.com/lief-project/LIEF/releases/tag/0.12.1)
    * Decompress it to `JITHook/Lib`. The following is the expected directory structure:
        ```
        JITHook/
        |- JITDemo
        |- JITPacker
        |- JITUnpacker
        |- ...
        |- Lib
           |- dnlib
           |- LIEF-0.12.1-win64
              |- include
              |- lib
        ```
        * (You can remove folders `bin` and `share` in the LIEF folder)
        * (See [LIEF Documentation](https://lief-project.github.io/doc/latest/installation.html#visual-studio-integration) for troubleshooting)
3. Open `JIT_Hook.sln` with Visual Studio Community 2022, configure project with release x64, press ctrl+shift+b to build the whole solution.
4. Check `JITHook/Release` to see result

# Usage
## JITDemo
```
JITDemo.exe
```

It's just a demo of patching method IL.

You can try to reverse-engineer it :)

## JITPacker
```
JITPacker.exe [OPTION] <program path>
```

`JITPacker.exe` will pack the program.

OPTION:
* `-o <PATH>`: Set output file path. Default path is `testprog_packed.exe`.

Default program path is `testprog.exe`.

## JITUnpacker
```
JITUnpacker.exe [OPTION] <packed program path>
```

**WARNING**: Please run `JITUnpacker.exe` in an isolated environment as **it will execute the packed program**.

`JITUnpacker.exe` will try to unpack the packed program.

OPTION:
* `-v <LEVEL>`: Set verbose level, LEVEL can be 0 ~ 3. Default value is 2. Set LEVEL to a higher value to see more information.
* `-o <PATH>`: Set output file path. Default path is `output.exe_`.

Default packed program path is `JIThook.exe`.

## testprog
A test program with different functions:
* Tiny format function
* Tiny format function that throw exception
* Fat format function with large size of IL code
* Fat format function with local variables
* Fat format function with exception handler
