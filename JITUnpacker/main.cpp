#define _CRT_SECURE_NO_WARNINGS

#pragma warning( disable : 6031)

#include <Windows.h>
#include <comdef.h>

// C-related
#include <stdio.h>

// C++-related
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

// mscorlib-related
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

// others
#include "args.h"
#include "corjit.h"
#include "log.h"

#define PAUSE() do { logPrintf(0, "PAUSE\n"); scanf("%*c"); } while(0)

// auto_rename: https://stackoverflow.com/questions/55117881/load-c-sharp-assembly-in-c-c-mscoree-tlh-errors
#import "C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorlib.tlb" raw_interfaces_only auto_rename

#define ALIGN(num, base) (((UINT64)num + base - 1) & ~(base - 1))

typedef void *func(void);

void **CorJitCompiler;
compileMethodFunc *originCompileMethod;
void *newCompileMethod;

struct PEStruct_t {
    BYTE        *PEFile;
    UINT         PEFileLength;
    UINT         sectionCnt;
    UINT         sectionHdrOffset;
    UINT         sectionRawAlignment;
    UINT         sectionVAAlignment;
    UINT         newSectionRaw;
    UINT         newSectionVA;
};
PEStruct_t PEStruct;

UINT newMethodOffset;

struct methodDefInfo {
    UINT *pRVA;
    std::string methodName;
    BYTE *methodHeader;
    BYTE *methodILCode;
    UINT methodILCodeSize;
};
std::unordered_map<int, methodDefInfo> methodMap;

struct PESection_t {
    BYTE       name[8];
    UINT       VASize;
    UINT       VA;
    UINT       rawSize;
    UINT       raw;
    UINT       ptrReloc;
    UINT       ptrLN;
    USHORT     nReloc;
    USHORT     nLN;
    UINT       characteristics;
};

/*
 * Parse Method table stream of "#~" Stream
 */
void assemblyAnalyze(void);

/*
 * Create a section with size 0x1000
 */
void createNewSection(void)
{
    UINT newSectionSize = ALIGN(0x1000, PEStruct.sectionRawAlignment);
    UINT newRaw = ALIGN(PEStruct.PEFileLength, PEStruct.sectionRawAlignment);
    UINT newPEFileLength = newRaw + newSectionSize;
    BYTE *newPEFile = new BYTE[newPEFileLength];
    BYTE *sectionHdr, *sectionCur;
    PESection_t *newSection;
    UINT newSectionVA = 0;

    memcpy(newPEFile, PEStruct.PEFile, PEStruct.PEFileLength);

    BYTE *ntHdr = newPEFile + *(UINT *)(newPEFile + 0x3c);
    USHORT *sectionCnt = (USHORT *)(ntHdr + 0x6);

    *sectionCnt = *sectionCnt + 1;

    sectionHdr = newPEFile + PEStruct.sectionHdrOffset;

    sectionCur = sectionHdr;
    for (int i = 0; i < PEStruct.sectionCnt; ++i) {
        UINT va = *(UINT *)(sectionCur + 0xc);
        UINT vasize = *(UINT *)(sectionCur + 0x8);
        UINT nextVA = ALIGN(va + vasize, PEStruct.sectionVAAlignment);

        if (nextVA > newSectionVA) {
            newSectionVA = nextVA;
        }

        sectionCur += 0x28;
    }

    // TODO: There may not be enough space to create a new section header
    newSection = (PESection_t *)sectionCur;
    memcpy(newSection->name, ".ljp", 5);
    newSection->ptrReloc = NULL;
    newSection->ptrLN = NULL;
    newSection->nReloc = 0;
    newSection->nLN = 0;
    newSection->VA = newSectionVA;
    newSection->VASize = 0x1000;
    newSection->raw = newRaw;
    newSection->rawSize = 0x1000;

    delete[] PEStruct.PEFile;
    PEStruct.PEFile = newPEFile;
    PEStruct.PEFileLength = newPEFileLength;

    // Redo analyze
    methodMap.clear();
    assemblyAnalyze();

    PEStruct.newSectionRaw = newRaw;
    PEStruct.newSectionVA  = newSectionVA;
}

/*
 * Return RVA of new method
 * 
 * [*] Only support CorILMethod_TinyFormat for now
 */
INT createNewMethodBody(uint8_t *ILCode, UINT32 ILCodeSize)
{
    UINT pos;
    UINT rva;
    BYTE header[12];

    if (ILCodeSize >= 1 << 6) {
        logPrintf(0, "[!] Only support CorILMethod_TinyFormat for now\n");
        return -1;
    }

    rva = PEStruct.newSectionVA + newMethodOffset;

    // CorILMethod_TinyFormat
    header[0] = (ILCodeSize << 2) | 0x02;
    
    // Copy header & ILCode
    pos = PEStruct.newSectionRaw + newMethodOffset;
    
    memcpy(PEStruct.PEFile + pos, header, 1);
    memcpy(PEStruct.PEFile + pos + 1, ILCode, ILCodeSize);

    // Done
    newMethodOffset = newMethodOffset + 1 + ILCodeSize;

    return rva;
}

void openPackedFile(const char *filename)
{
    std::ifstream target(filename, std::ios::in | std::ios::binary | std::ios::ate);

    if (!target.is_open()) {
        exit(1);
    }

    PEStruct.PEFileLength = target.tellg();

    PEStruct.PEFile = new BYTE[PEStruct.PEFileLength];
    target.seekg(0, std::ios::beg);
    target.read((char *)PEStruct.PEFile, PEStruct.PEFileLength);

    target.close();

    logPrintf(1, "[*] file: %s\n", filename);
    logPrintf(1, "[*] file length: %d\n", PEStruct.PEFileLength);
}

void saveFile(void)
{
    std::ofstream target("output.exe_", std::ofstream::binary);

    target.write((char *)PEStruct.PEFile, PEStruct.PEFileLength);
    target.close();

    logPrintf(0, "[*] Checkout output.exe_\n");
}

int clrHost(ICorRuntimeHost **pRuntimeHost)
{
    HRESULT hr;
    ICLRMetaHost *pMetaHost = NULL;
    ICLRRuntimeInfo *pRuntimeInfo = NULL;
    BOOL bLoadable;

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
        (LPVOID *)&pMetaHost);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] CLRCreateInstance(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] CLRCreateInstance(...) succeeded\n");

    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (VOID **)&pRuntimeInfo);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pMetaHost->GetRuntime(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] pMetaHost->GetRuntime(...) succeeded\n");

    hr = pRuntimeInfo->IsLoadable(&bLoadable);

    if (FAILED(hr) || !bLoadable)
    {
        logPrintf(0, "[!] pRuntimeInfo->IsLoadable(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] pRuntimeInfo->IsLoadable(...) succeeded\n");

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID **)pRuntimeHost);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pRuntimeInfo->GetInterface(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] pRuntimeInfo->GetInterface(...) succeeded\n");

    hr = (*pRuntimeHost)->Start();

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pRuntimeHost->Start() failed\n");
        return -1;
    }
    logPrintf(1, "[+] pRuntimeHost->Start() succeeded\n");
}

int assemblyLoad(ICorRuntimeHost *pRuntimeHost,
                  mscorlib::_AssemblyPtr *pAssembly,
                  char *fileData,
                  int fileLength)
{
    HRESULT hr;
    IUnknownPtr pAppDomainThunk = NULL;
    mscorlib::_AppDomainPtr pDefaultAppDomain = NULL;
    SAFEARRAYBOUND rgsabound[1];
    SAFEARRAY *pSafeArray = NULL;
    void *pvData = NULL;

    hr = pRuntimeHost->GetDefaultDomain(&pAppDomainThunk);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pRuntimeHost->GetDefaultDomain(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] pRuntimeHost->GetDefaultDomain(...) succeeded\n");

    hr = pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (VOID **)&pDefaultAppDomain);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pAppDomainThunk->QueryInterface(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] pAppDomainThunk->QueryInterface(...) succeeded\n");

    rgsabound[0].cElements = fileLength;
    rgsabound[0].lLbound = 0;

    pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

    hr = SafeArrayAccessData(pSafeArray, &pvData);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] SafeArrayAccessData(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] SafeArrayAccessData(...) succeeded\n");

    memcpy(pvData, fileData, fileLength);

    hr = SafeArrayUnaccessData(pSafeArray);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] SafeArrayUnaccessData(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] SafeArrayUnaccessData(...) succeeded\n");

    hr = pDefaultAppDomain->Load_3(pSafeArray, &(*pAssembly));

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pDefaultAppDomain->Load_3(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] pDefaultAppDomain->Load_3(...) succeeded\n");
}

int assemblyRun(mscorlib::_AssemblyPtr pAssembly, int argc, char *argv[])
{
    HRESULT hr;
    mscorlib::_MethodInfoPtr pMethodInfo = NULL;
    VARIANT retVal;
    VARIANT obj;
    VARIANT args;
    SAFEARRAYBOUND argsBound[1];
    long idx[1];
    SAFEARRAY *params = NULL;
    SAFEARRAYBOUND paramsBound[1];

    hr = pAssembly->get_EntryPoint(&pMethodInfo);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pAssembly->get_EntryPoint(...) failed\n");
        return -1;
    }
    logPrintf(1, "[+] pAssembly->get_EntryPoint(...) succeeded\n");

    ZeroMemory(&retVal, sizeof(VARIANT));
    ZeroMemory(&obj, sizeof(VARIANT));
    obj.vt = VT_NULL;

    args.vt = VT_ARRAY | VT_BSTR;
    argsBound[0].lLbound = 0;
    argsBound[0].cElements = argc;
    args.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
    for (int i = 0; i < argc; i++)
    {
        std::wstring wc(strlen(argv[i]), L'#');
        mbstowcs(&wc[0], argv[i], strlen(argv[i]));
        idx[0] = i;
        SafeArrayPutElement(args.parray, idx, SysAllocString(wc.c_str()));
    }
    paramsBound[0].lLbound = 0;
    paramsBound[0].cElements = 1;
    params = SafeArrayCreate(VT_VARIANT, 1, paramsBound);
    idx[0] = 0;
    SafeArrayPutElement(params, idx, &args);

    PAUSE();

    // hr = 8002000E: https://github.com/etormadiv/HostingCLR/issues/4
    hr = pMethodInfo->Invoke_3(obj, params, &retVal);

    if (FAILED(hr))
    {
        logPrintf(0, "[!] pMethodInfo->Invoke_3(...) failed, hr = %X\n", hr);
        return -1;
    }
    logPrintf(1, "[+] pMethodInfo->Invoke_3(...) succeeded\n");
}

void reportNative(uint8_t **nativeEntry, uint32_t *nativeSizeOfCode)
{
    logPrintf(1, "\t[*] Native entry: %p\n", *nativeEntry);
    logPrintf(1, "\t[*] Native size of code: %x\n", *nativeSizeOfCode);
}

// Ref: https://github.com/dotnet/runtime/blob/4ed596ef63e60ce54cfb41d55928f0fe45f65cf3/src/coreclr/inc/corjit.h#L192
CorJitResult compileMethodHook(
    void                            *thisptr,
    ICorJitInfo                     *comp,               /* IN */
    struct CORINFO_METHOD_INFO      *info,               /* IN */
    unsigned /* code:CorJitFlag */   flags,              /* IN */
    uint8_t                        **nativeEntry,        /* OUT */
    uint32_t                        *nativeSizeOfCode    /* OUT */
)
{
    int token;
    methodDefInfo method;
    CorJitResult ret;

    logPrintf(1, "[*] hooking!\n");

    // Check whether the hook has been edited
    if (CorJitCompiler[0] != newCompileMethod) {
        logPrintf(0, "[*] Hook has been edited!\n");
    }

    // Get the info of module
    token = (0x06000000 + *(USHORT *)info->ftn);

    if (!methodMap.count(token)) {
        goto HookEnd;
    }

    method = methodMap[token];

    logPrintf(1, "\t[*] Token: %x\n", token);
    logPrintf(1, "\t[*] Name: %s\n", method.methodName.c_str());

    // Check whether the IL has been edited
    if (info->ILCodeSize == method.methodILCodeSize) {
        int i = 0;
        
        for (; i < method.methodILCodeSize; ++i) {
            if (info->ILCode[i] != method.methodILCode[i]) {
                break;
            }
        }

        if (i == method.methodILCodeSize) {
            goto HookEnd;
        }
    }

    // IL has been edited, update it
    logPrintf(0, "\t[!] IL has been edited!\n");

    if (info->ILCodeSize > method.methodILCodeSize) {
        INT ILAddr;
        logPrintf(0, "\t[!] TODO: new IL is larger than origin IL and may not have space to store it\n");

        // Add new section
        if (!PEStruct.newSectionVA) {
            createNewSection();
        }

        // Make the IL live in the new section
        ILAddr = createNewMethodBody(info->ILCode, info->ILCodeSize);

        if (ILAddr < 0) {
            goto HookEnd;
        }

        // Re-find method
        method = methodMap[token];

        // Modify RVA of MethodDef entry
        *method.pRVA = ILAddr;
    }
    else {
        // Modify origin IL
        memcpy(method.methodILCode, info->ILCode, info->ILCodeSize);
    }

HookEnd:
    ret = originCompileMethod(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);

    reportNative(nativeEntry, nativeSizeOfCode);

    return ret;
}

int jitHook(void)
{
    HMODULE clrjit;
    func *getjit;
    DWORD old;
    UINT64 iaddr, compileMethodHookIAddr;
    BYTE *addr;
    BYTE trampoline[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
                          0xff, 0xe0,                                                 // jmp rax
                        };
    
    // Preloading clrjit.dll
    AddDllDirectory(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\");
    clrjit = LoadLibraryExA("clrjit.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (clrjit == NULL) {
        logPrintf(0, "[x] Failed to load clrjit.dll\n");
        exit(1);
    }
    logPrintf(1, "[*] Load clrjit.dll\n");

    // Write trampoline
    addr = (BYTE *)clrjit + 0x40;
    logPrintf(1, "[*] Write trampoline to address %p\n", addr);

    compileMethodHookIAddr = (UINT64)compileMethodHook;
    for (int i = 0; i < 8; ++i) {
        trampoline[2 + i] = (compileMethodHookIAddr >> (i * 8)) & 0xff;
    }

    VirtualProtect(addr, sizeof(trampoline), PAGE_EXECUTE_READWRITE, &old);

    for (int i = 0; i < sizeof(trampoline); ++i) {
        addr[i] = trampoline[i];
    }

    newCompileMethod = addr;

    // Hook
    getjit = (func *)GetProcAddress(clrjit, "getJit");
    CorJitCompiler = *(void ***)getjit();
    originCompileMethod = (compileMethodFunc *)CorJitCompiler[0];
    
    VirtualProtect(&CorJitCompiler[0], 0x8, PAGE_EXECUTE_READWRITE, &old);
    CorJitCompiler[0] = newCompileMethod;
    VirtualProtect(&CorJitCompiler[0], 0x8, old, &old);

    logPrintf(1, "[*] Hook compileMethod\n");
    logPrintf(1, "[*] originCompileMethod: %p\n", originCompileMethod);
}

void assemblyAnalyze(void)
{
    logPrintf(2, "[*] Analyze assembly\n");

    BYTE *baseaddr = PEStruct.PEFile;
    BYTE *ntHdr = baseaddr + *(UINT *)(baseaddr + 0x3c);
    USHORT sectionCnt = *(USHORT *)(ntHdr + 0x6);
    UINT optionalHdrSize = *(USHORT *)(ntHdr + 0x14);
    BYTE *optionalHdr = ntHdr + 0x18;
    USHORT magic = *(USHORT *)optionalHdr;

    if (magic != 0x20b) {
        logPrintf(0, "[!] Only support 64-bit program\n");
        exit(1);
    }

    BYTE *sectionHdr = optionalHdr + optionalHdrSize;
    INT offset = 0;
    UINT imageCor20HdrRva = *(UINT *)(optionalHdr + 0xe0);

    PEStruct.sectionCnt = sectionCnt;
    PEStruct.sectionHdrOffset = sectionHdr - baseaddr;
    PEStruct.sectionRawAlignment = *(UINT *)(optionalHdr + 0x24);
    PEStruct.sectionVAAlignment  = *(UINT *)(optionalHdr + 0x20);

    // Find raw addr of imageCor20Hdr
    BYTE *section_cur = sectionHdr;
    while (sectionCnt--) {
        UINT va = *(UINT *)(section_cur + 0xc);
        UINT vasize = *(UINT *)(section_cur + 0x8);

        if (va <= imageCor20HdrRva && imageCor20HdrRva < va + vasize) {
            UINT ra = *(UINT *)(section_cur + 0x14);
            offset = ra - va;
            break;
        }

        section_cur += 0x28;
    }

    BYTE *imageCor20Hdr = baseaddr + imageCor20HdrRva + offset;
    UINT metadataRva = *(UINT *)(imageCor20Hdr + 8);
    BYTE *metadataRoot = baseaddr + metadataRva + offset;
    UINT versionLen = *(UINT *)(metadataRoot + 0xc);
    UINT paddedVersionLen = (UINT)((versionLen + 3) & (~0x03));
    UINT numOfStreams = *(USHORT *)(metadataRoot + 0x12 + paddedVersionLen);
    BYTE *streamHdr = metadataRoot + 0x14 + paddedVersionLen;
    BYTE *tildeStreamHdr = NULL;
    BYTE *stringsStreamHdr = NULL;

    for (UINT i = 0; i < numOfStreams; ++i)
    {
        std::string rcName((char *)(streamHdr + 8));

        if (rcName == "#~")
        {
            tildeStreamHdr = streamHdr;
        }
        else if (rcName == "#Strings")
        {
            stringsStreamHdr = streamHdr;
        }
        streamHdr += 0x8 + ((rcName.length() + 4) & (~0x03));
    }

    UINT tildeIOffset = *(UINT *)tildeStreamHdr;
    UINT tildeISize = *(UINT *)(tildeStreamHdr + 4);

    UINT stringsIOffset = *(UINT *)stringsStreamHdr;
    UINT stringsISize = *(UINT *)(stringsStreamHdr + 4);

    BYTE *stringsStream = metadataRoot + stringsIOffset;

    // ECMA-335 6th II.24.2.6
    BYTE *tableStream = metadataRoot + tildeIOffset;
    
    ULONGLONG maskvalid = *(ULONGLONG *)(tableStream + 8);
    ULONGLONG masksorted = *(ULONGLONG *)(tableStream + 0x10);

    UINT *metadataTableNums = new UINT[0x40];
    BYTE *rows = tableStream + 0x18;

    for (ULONGLONG i = 0, lMaskvalid = maskvalid; lMaskvalid != 0; lMaskvalid >>= 1, i++)
    {
        if ((lMaskvalid & 1) == 1)
        {
            metadataTableNums[i] = *(UINT *)rows;
            rows += 4;
        }
        else
        {
            metadataTableNums[i] = 0;
        }
    }

    UINT metadataTableSizes[] = {
        0xa, // module_size
        0x6, // typeref_size
        0xe, // typedef_size
        0,
        0x6, // field_size
        0,
        0xe, // methoddef_size 
    };

    BYTE **tables = new BYTE * [7];

    tables[0] = rows;

    for (ULONG i = 1; i < 7; ++i)
    {
        tables[i] = tables[i - 1] + metadataTableNums[i - 1] * metadataTableSizes[i - 1];
    }

    BYTE *methodTable = tables[6];

    for (UINT i = 0; i < metadataTableNums[6]; ++i, methodTable += 0xe)
    {
        BYTE *code;
        UINT codesize;
        int format;
        // ECMA-335 6th II.22.26
        BYTE *header;
        UINT *prva = (UINT *)methodTable;
        USHORT nameIdx = *(USHORT *)(methodTable + 0x8);
        std::string name((char *)(stringsStream + nameIdx));
        UINT token = 0x06000000 + i + 1;

        logPrintf(2, "\t[*] Method: %s\n", name.c_str());
        logPrintf(2, "\t\t[*] token: %x\n", token);

        if (!*prva) {
            continue;
        }

        header = baseaddr + *prva + offset;

        format = *header & 1;

        if (format == 1)
        {
            // CorILMethod_FatFormat
            codesize = *(UINT *)(header + 4);
            code = header + 12;
        }
        else
        {
            // CorILMethod_TinyFormat
            codesize = *header >> 2;
            code = header + 1;
        }

        logPrintf(2, "\t\t[*] rva: %x\n", *prva);
        logPrintf(2, "\t\t[*] IL code size: %#x\n", codesize);
        logPrintf(2, "\t\t[*] IL code: %p\n", code);

        methodMap[token] = { prva, name, header, code, codesize };
    }
}

int main(int argc, char *argv[])
{
    ICorRuntimeHost *pRuntimeHost = NULL; // Alternative: ICLRRuntimeHost
    mscorlib::_AssemblyPtr pAssembly = NULL;

    parseArg(argc, argv);

    openPackedFile(argFilename.c_str());

    if (clrHost(&pRuntimeHost) < 0) {
        exit(1);
    }

    jitHook();

    assemblyAnalyze();

    if (assemblyLoad(pRuntimeHost,
                     (mscorlib::_AssemblyPtr *)&pAssembly,
                     (char *)PEStruct.PEFile,
                     PEStruct.PEFileLength) < 0) {
        exit(1);
    }

    if (assemblyRun(pAssembly, argc, argv) < 0) {
        exit(1);
    }

    saveFile();

    logPrintf(0, "[*] CLRHosting Terminated\n");

    return 0;
}