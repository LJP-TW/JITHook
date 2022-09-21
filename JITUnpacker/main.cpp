#define _CRT_SECURE_NO_WARNINGS

#pragma warning(disable : 4146)
#pragma warning(disable : 6031)

// LIEF
#include <LIEF/LIEF.hpp>

// Windows
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
#include <set>
#include <cstdio>

// mscorlib-related
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

// others
#include "args.h"
#include "corjit.h"
#include "log.h"

#define PAUSE() do { logPrintf(LOG_LEVEL_INFO, "[*] PAUSE\n"); scanf("%*c"); } while(0)

// auto_rename: https://stackoverflow.com/questions/55117881/load-c-sharp-assembly-in-c-c-mscoree-tlh-errors
#import "mscorlib.tlb" auto_rename

#define ALIGN(num, base) (((UINT64)num + base - 1) & ~(base - 1))

typedef void *func(void);

void **CorJitCompiler;
compileMethodFunc *originCompileMethod;
getEHinfoFunc *getEHinfo;
void *newCompileMethod;
int localVarSigTokOffset;

struct PEStruct_t
{
    BYTE        *PEFile;
    UINT         PEFileLength;
    UINT         newSectionRaw;
    UINT         newSectionVA;
};
PEStruct_t PEStruct;

UINT newMethodOffset;

struct methodDefInfo
{
    UINT *pRVA;
    std::string methodName;
    BYTE *methodHeader;
    BYTE *methodILCode;
    UINT methodILCodeSize;
    BOOL rvaDuplicated;
};
std::unordered_map<int, methodDefInfo> methodMap;

struct PESection_t
{
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

void openPackedFile(const char *filename);

void init(void)
{
    NTSTATUS(WINAPI *RtlGetVersion)(LPOSVERSIONINFOEXW);
    OSVERSIONINFOEXW osInfo;

    *(FARPROC *)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

    if (RtlGetVersion == NULL) {
        logPrintf(LOG_LEVEL_ERR, "[!] RtlGetVersion not found\n");
        exit(1);
    }

    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    RtlGetVersion(&osInfo);

    logPrintf(LOG_LEVEL_DEBUG, "[*] Windows version:\n");
    logPrintf(LOG_LEVEL_DEBUG, "[*] Major: %d\n", osInfo.dwMajorVersion);
    logPrintf(LOG_LEVEL_DEBUG, "[*] Minor: %d\n", osInfo.dwMinorVersion);
    logPrintf(LOG_LEVEL_DEBUG, "[*] Build: %d\n", osInfo.dwBuildNumber);

    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber == 19043) {
        localVarSigTokOffset = 0x520;
    } else if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber == 19044) {
        // TODO: Check if localVarSigTokOffset can be adjusted according to OS version
        // localVarSigTokOffset = 0x508;
        localVarSigTokOffset = 0x4d8;
    } else {
        // localVarSigTokOffset = 0x508;
        localVarSigTokOffset = 0x4d8;
        logPrintf(LOG_LEVEL_ERR, "[!] OS version is not currently supported and may have bugs\n");
    }
}

/*
 * Parse Method table stream of "#~" Stream
 */
void assemblyAnalyze(void);

void _createNewSection(void)
{
    std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("ljp.tmp");
    LIEF::PE::Section section;

    std::vector<uint8_t> content(0x1000, 0);

    section.name(".ljp");
    section.content(content);

    pe->add_section(section, LIEF::PE::PE_SECTION_TYPES::TEXT);
    pe->write("ljp.tmp");

    delete[] PEStruct.PEFile;
    openPackedFile("ljp.tmp");

    std::remove("ljp.tmp");
}

/*
 * Create a section with size 0x1000
 */
void createNewSection(void)
{
    // Save file
    std::ofstream target("ljp.tmp", std::ofstream::binary);

    target.write((char *)PEStruct.PEFile, PEStruct.PEFileLength);
    target.close();

    // Create new seciton
    _createNewSection();

    // Redo analyze
    methodMap.clear();
    assemblyAnalyze();

    // Set PEStruct.newSectionRaw & PEStruct.newSectionVA
    BYTE *baseaddr = PEStruct.PEFile;
    BYTE *ntHdr = baseaddr + *(UINT *)(baseaddr + 0x3c);
    USHORT sectionCnt = *(USHORT *)(ntHdr + 0x6);

    UINT optionalHdrSize = *(USHORT *)(ntHdr + 0x14);
    BYTE *optionalHdr = ntHdr + 0x18;

    BYTE *sectionHdr = optionalHdr + optionalHdrSize;
    INT offset = 0;

    for (int i = 0; i < sectionCnt; ++i) {
        if (!strcmp((char *)sectionHdr, ".ljp")) {
            PEStruct.newSectionRaw = *(UINT *)(sectionHdr + 0x14);
            PEStruct.newSectionVA = *(UINT *)(sectionHdr + 0xc);
            break;
        }

        sectionHdr += 0x28;
    }
}

static INT createNewMethodBodyTiny(uint8_t *ILCode, UINT ILCodeSize)
{
    UINT pos;
    UINT rva;
    BYTE header[12];
    UINT hdrSize = 1;

    rva = PEStruct.newSectionVA + newMethodOffset;

    // CorILMethod_TinyFormat
    header[0] = (ILCodeSize << 2) | 0x02;

    // Copy header & ILCode
    pos = PEStruct.newSectionRaw + newMethodOffset;

    memcpy(PEStruct.PEFile + pos, header, hdrSize);
    memcpy(PEStruct.PEFile + pos + hdrSize, ILCode, ILCodeSize);

    // Done
    newMethodOffset = newMethodOffset + hdrSize + ILCodeSize;

    return rva;
}

static INT createNewMethodBodyFat(uint8_t *ILCode, UINT ILCodeSize,
                                  CORINFO_METHOD_INFO *info,
                                  UINT localVarSigTok, CORINFO_EH_CLAUSE *clause)
{
    UINT base;
    UINT offset;
    UINT rva;
    CorILMethod_FatFormat header;
    CorILMethod_Sect_EHTable EHTable;
    UINT hdrSize = 12;
    UINT clauseSize;
    CORINFO_EH_CLAUSE_TINY *tinyclause = nullptr;
    int padding = 0;

    rva = PEStruct.newSectionVA + newMethodOffset;

    // CorILMethod_FatFormat
    header.flags = 0x03 | 0x10 | 0x3000;
    header.maxStack = info->maxStack;
    header.codeSize = ILCodeSize;
    header.localVarSigTok = localVarSigTok;

    if (info->EHcount) {
        header.flags |= 0x08;

        clauseSize = info->EHcount * 12;

        EHTable.kind = 1;
        EHTable.dataSize = 4 + clauseSize;
        EHTable.reserved = 0;

        tinyclause = new CORINFO_EH_CLAUSE_TINY[info->EHcount];

        for (int i = 0; i < info->EHcount; ++i) {
            tinyclause[i].Flags = clause[i].Flags;
            tinyclause[i].TryOffset = clause[i].TryOffset;
            tinyclause[i].TryLength = clause[i].TryLength;
            tinyclause[i].HandlerOffset = clause[i].HandlerOffset;
            tinyclause[i].HandlerLength = clause[i].HandlerLength;
            tinyclause[i].ClassToken = clause[i].ClassToken;
        }

        delete[] clause;
    }

    base = PEStruct.newSectionRaw + newMethodOffset;
    offset = 0;

    // Align 4-byte
    if (newMethodOffset % 4) {
        padding = 4 - newMethodOffset % 4;
    }

    memset(PEStruct.PEFile + base, 0, padding);
    offset += padding;
    rva += padding;

    // Copy header & ILCode
    memcpy(PEStruct.PEFile + base + offset, &header, hdrSize);
    offset += hdrSize;

    memcpy(PEStruct.PEFile + base + offset, ILCode, ILCodeSize);
    offset += ILCodeSize;

    if (info->EHcount) {
        // Align 4-byte
        padding = 0;

        if (ILCodeSize % 4) {
            padding = 4 - ILCodeSize % 4;
        }

        memset(PEStruct.PEFile + base + offset, 0, padding);
        offset += padding;

        memcpy(PEStruct.PEFile + base + offset, &EHTable, 4);
        offset += 4;

        memcpy(PEStruct.PEFile + base + offset, tinyclause, clauseSize);
        offset += clauseSize;

        delete[] tinyclause;
    }

    // Done
    newMethodOffset = newMethodOffset + offset;

    return rva;
}

/*
 * Return RVA of new method
 */
INT createNewMethodBody(ICorJitInfo *pCorJitInfo, struct CORINFO_METHOD_INFO *info)
{
    uint8_t *ILCode;
    UINT ILCodeSize;
    UINT localVarSigTok;
    CORINFO_EH_CLAUSE *clause = nullptr;
    int validLocalVarSigTok = 0;
    int fat = 0;

    ILCode = info->ILCode;
    ILCodeSize = info->ILCodeSize;
    localVarSigTok = *(DWORD *)(((BYTE *)info) + localVarSigTokOffset);

    logPrintf(LOG_LEVEL_DEBUG, "[*] info: %p\n", info);
    logPrintf(LOG_LEVEL_DEBUG, "[*] localVarSigTok: %#x\n", localVarSigTok);

    if (((localVarSigTok >> 24) & 0xff) == 0x11) {
        // There are local variables
        fat = 1;
        validLocalVarSigTok = 1;
    } else if (ILCodeSize >= 1 << 6) {
        // The method is too large to encode the size (i.e., at least 64 bytes)
        fat = 1;
    }

    if (info->EHcount) {
        // There are extra data sections 
        // Because there are exception handlers, so a extra CorILMethod_Sect_EHTable is needed
        fat = 1;

        if (!validLocalVarSigTok) {
            localVarSigTok = 0;
        }

        logPrintf(LOG_LEVEL_DEBUG, "[*] EHcount: %d\n", info->EHcount);

        clause = new CORINFO_EH_CLAUSE[info->EHcount];

        for (int i = 0; i < info->EHcount; ++i) {
            getEHinfo(pCorJitInfo, info->ftn, i, &clause[i]);

            logPrintf(LOG_LEVEL_DEBUG, "[*] CORINFO_EH_CLAUSE:\n");
            logPrintf(LOG_LEVEL_DEBUG, "[*] Flags     : %#x\n", clause[i].Flags);
            logPrintf(LOG_LEVEL_DEBUG, "[*] TryOffset : %#x\n", clause[i].TryOffset);
            logPrintf(LOG_LEVEL_DEBUG, "[*] TryLength : %#x\n", clause[i].TryLength);
            logPrintf(LOG_LEVEL_DEBUG, "[*] HdlOffset : %#x\n", clause[i].HandlerOffset);
            logPrintf(LOG_LEVEL_DEBUG, "[*] HdlLength : %#x\n", clause[i].HandlerLength);
            logPrintf(LOG_LEVEL_DEBUG, "[*] Token     : %#x\n", clause[i].ClassToken);
        }
    }

    if (fat) {
        // Fat format
        return createNewMethodBodyFat(ILCode, ILCodeSize, info, localVarSigTok, clause);
    }

    // Tiny format
    return createNewMethodBodyTiny(ILCode, ILCodeSize);
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

    logPrintf(LOG_LEVEL_DEBUG, "[*] file: %s\n", filename);
    logPrintf(LOG_LEVEL_DEBUG, "[*] file length: %d\n", PEStruct.PEFileLength);
}

void saveFile(const char *filename)
{
    std::ofstream target(filename, std::ofstream::binary);

    target.write((char *)PEStruct.PEFile, PEStruct.PEFileLength);
    target.close();

    logPrintf(LOG_LEVEL_INFO, "[*] Checkout %s\n", filename);
}

int clrHost(ICorRuntimeHost **pRuntimeHost)
{
    HRESULT hr;
    ICLRMetaHost *pMetaHost = NULL;
    ICLRRuntimeInfo *pRuntimeInfo = NULL;
    BOOL bLoadable;

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
                           (LPVOID *)&pMetaHost);

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] CLRCreateInstance(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] CLRCreateInstance(...) succeeded\n");

    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (VOID **)&pRuntimeInfo);

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pMetaHost->GetRuntime(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pMetaHost->GetRuntime(...) succeeded\n");

    hr = pRuntimeInfo->IsLoadable(&bLoadable);

    if (FAILED(hr) || !bLoadable) {
        logPrintf(LOG_LEVEL_ERR, "[!] pRuntimeInfo->IsLoadable(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pRuntimeInfo->IsLoadable(...) succeeded\n");

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID **)pRuntimeHost);

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pRuntimeInfo->GetInterface(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pRuntimeInfo->GetInterface(...) succeeded\n");

    hr = (*pRuntimeHost)->Start();

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pRuntimeHost->Start() failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pRuntimeHost->Start() succeeded\n");
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

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pRuntimeHost->GetDefaultDomain(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pRuntimeHost->GetDefaultDomain(...) succeeded\n");

    hr = pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (VOID **)&pDefaultAppDomain);

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pAppDomainThunk->QueryInterface(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pAppDomainThunk->QueryInterface(...) succeeded\n");

    rgsabound[0].cElements = fileLength;
    rgsabound[0].lLbound = 0;

    pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

    hr = SafeArrayAccessData(pSafeArray, &pvData);

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] SafeArrayAccessData(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] SafeArrayAccessData(...) succeeded\n");

    memcpy(pvData, fileData, fileLength);

    hr = SafeArrayUnaccessData(pSafeArray);

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] SafeArrayUnaccessData(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] SafeArrayUnaccessData(...) succeeded\n");

    hr = pDefaultAppDomain->raw_Load_3(pSafeArray, &(*pAssembly));

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pDefaultAppDomain->Load_3(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pDefaultAppDomain->Load_3(...) succeeded\n");
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

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pAssembly->get_EntryPoint(...) failed\n");
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pAssembly->get_EntryPoint(...) succeeded\n");

    ZeroMemory(&retVal, sizeof(VARIANT));
    ZeroMemory(&obj, sizeof(VARIANT));
    obj.vt = VT_NULL;

    args.vt = VT_ARRAY | VT_BSTR;
    argsBound[0].lLbound = 0;
    argsBound[0].cElements = argc;
    args.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
    for (int i = 0; i < argc; i++) {
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

    logPrintf(LOG_LEVEL_INFO, "[*] Press any key to run .NET assembly\n");
    PAUSE();

    // hr = 8002000E: https://github.com/etormadiv/HostingCLR/issues/4
    hr = pMethodInfo->raw_Invoke_3(obj, params, &retVal);

    if (FAILED(hr)) {
        logPrintf(LOG_LEVEL_ERR, "[!] pMethodInfo->Invoke_3(...) failed, hr = %X\n", hr);
        return -1;
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] pMethodInfo->Invoke_3(...) succeeded\n");
}

void reportNative(uint8_t **nativeEntry, uint32_t *nativeSizeOfCode)
{
    logPrintf(LOG_LEVEL_DEBUG, "\t[*] Native entry: %p\n", *nativeEntry);
    logPrintf(LOG_LEVEL_DEBUG, "\t[*] Native size of code: %x\n", *nativeSizeOfCode);
}

static void initGetEHinfo(void **ICorJitInfo)
{
    /*
     * Ref:
     * - https://www.52pojie.cn/thread-1005018-1-1.html#27331457_jitunpacker
     *
     * Compiler::fgFindBasicBlocks
     *      mov     rdi, [rsi+1AB8h]; this->info (ICorJitInfo *)
     *      mov     rax, [rdi]      ; ICorJitInfo
     *      mov     rbx, [rax+40h]  ; ICorJitInfo[8] (CEEJitInfo::getEHinfo)
     *      mov     rcx, rbx
     *      call    cs:__guard_check_icall_fptr ; JitExpandArray<ValueNumStore::VNDefFunc2Arg>::~JitExpandArray<ValueNumStore::VNDefFunc2Arg>(void)
     *      mov     rdx, [rsi+1AD0h]
     *      lea     r9, [rbp+clause]
     *      mov     r8d, r12d
     *      mov     rcx, rdi
     *      call    rbx             ; CEEJitInfo::getEHinfo
     */

    getEHinfo = (getEHinfoFunc*)ICorJitInfo[8];
    logPrintf(LOG_LEVEL_DEBUG, "[*] getEHinfo: %p\n", getEHinfo);
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

    logPrintf(LOG_LEVEL_INFO, "[*] hooking!\n");

    if (!getEHinfo) {
        initGetEHinfo(*((void ***)comp));
    }

    // Check whether the hook has been edited
    if (CorJitCompiler[0] != newCompileMethod) {
        logPrintf(LOG_LEVEL_WARNING, "[+] Hook has been edited!\n");
    }

    // Get the info of module
    token = (0x06000000 + *(USHORT *)info->ftn);

    if (!methodMap.count(token)) {
        goto HookEnd;
    }

    method = methodMap[token];

    logPrintf(LOG_LEVEL_INFO, "\t[*] Token: %x\n", token);
    logPrintf(LOG_LEVEL_INFO, "\t[*] Name: %s\n", method.methodName.c_str());

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
    logPrintf(LOG_LEVEL_WARNING, "\t[+] IL has been edited!\n");

    if (info->ILCodeSize > method.methodILCodeSize || method.rvaDuplicated) {
        INT ILAddr;

        // Add new section
        if (!PEStruct.newSectionVA) {
            createNewSection();
        }

        // Make the IL live in the new section
        ILAddr = createNewMethodBody(comp, info);

        if (ILAddr < 0) {
            goto HookEnd;
        }

        // Re-find method
        method = methodMap[token];

        // Modify RVA of MethodDef entry
        *method.pRVA = ILAddr;
    } else {
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
        logPrintf(LOG_LEVEL_ERR, "[!] Failed to load clrjit.dll\n");
        exit(1);
    }
    logPrintf(LOG_LEVEL_DEBUG, "[*] Load clrjit.dll\n");

    // Write trampoline
    addr = (BYTE *)clrjit + 0x40;
    logPrintf(LOG_LEVEL_DEBUG, "[*] Write trampoline to address %p\n", addr);

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

    logPrintf(LOG_LEVEL_DEBUG, "[*] Hook compileMethod\n");
    logPrintf(LOG_LEVEL_DEBUG, "[*] originCompileMethod: %p\n", originCompileMethod);
}

void assemblyAnalyze(void)
{
    logPrintf(LOG_LEVEL_DEBUG, "[*] Analyze assembly\n");

    BYTE *baseaddr = PEStruct.PEFile;
    BYTE *ntHdr = baseaddr + *(UINT *)(baseaddr + 0x3c);
    USHORT sectionCnt = *(USHORT *)(ntHdr + 0x6);
    UINT optionalHdrSize = *(USHORT *)(ntHdr + 0x14);
    BYTE *optionalHdr = ntHdr + 0x18;
    USHORT magic = *(USHORT *)optionalHdr;
    UINT imageCor20HdrOffset = 0;

    if (magic == 0x20b) {
        logPrintf(LOG_LEVEL_DEBUG, "[!] 64-bit program\n");
        imageCor20HdrOffset = 0xe0;
    } else if (magic == 0x10b) {
        logPrintf(LOG_LEVEL_DEBUG, "[!] 32-bit program\n");
        imageCor20HdrOffset = 0xd0;
    } else {
        logPrintf(LOG_LEVEL_ERR, "[!] Error: weird magic of optional header\n");
        exit(1);
    }

    BYTE *sectionHdr = optionalHdr + optionalHdrSize;
    INT offset = 0;
    UINT imageCor20HdrRva = *(UINT *)(optionalHdr + imageCor20HdrOffset);

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

    for (UINT i = 0; i < numOfStreams; ++i) {
        std::string rcName((char *)(streamHdr + 8));

        if (rcName == "#~") {
            tildeStreamHdr = streamHdr;
        } else if (rcName == "#Strings") {
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

    for (ULONGLONG i = 0, lMaskvalid = maskvalid; lMaskvalid != 0; lMaskvalid >>= 1, i++) {
        if ((lMaskvalid & 1) == 1) {
            metadataTableNums[i] = *(UINT *)rows;
            rows += 4;
        } else {
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

    for (ULONG i = 1; i < 7; ++i) {
        tables[i] = tables[i - 1] + metadataTableNums[i - 1] * metadataTableSizes[i - 1];
    }

    BYTE *methodTable = tables[6];
    std::set<UINT> rvas;

    for (UINT i = 0; i < metadataTableNums[6]; ++i, methodTable += 0xe) {
        BYTE *code;
        UINT codesize;
        int format;
        // ECMA-335 6th II.22.26
        BYTE *header;
        UINT *prva = (UINT *)methodTable;
        USHORT nameIdx = *(USHORT *)(methodTable + 0x8);
        std::string name((char *)(stringsStream + nameIdx));
        UINT token = 0x06000000 + i + 1;

        logPrintf(LOG_LEVEL_DEBUG, "\t[*] Method: %s\n", name.c_str());
        logPrintf(LOG_LEVEL_DEBUG, "\t\t[*] token: %x\n", token);

        if (!*prva) {
            continue;
        }

        header = baseaddr + *prva + offset;

        format = *header & 1;

        if (format == 1) {
            // CorILMethod_FatFormat
            codesize = *(UINT *)(header + 4);
            code = header + 12;
        } else {
            // CorILMethod_TinyFormat
            codesize = *header >> 2;
            code = header + 1;
        }

        logPrintf(LOG_LEVEL_DEBUG, "\t\t[*] rva: %x\n", *prva);
        logPrintf(LOG_LEVEL_DEBUG, "\t\t[*] IL code size: %#x\n", codesize);
        logPrintf(LOG_LEVEL_DEBUG, "\t\t[*] IL code: %p\n", code);

        methodMap[token] = { prva, name, header, code, codesize, rvas.find(*prva) != rvas.end() };

        rvas.insert(*prva);
    }
}

int main(int argc, char *argv[])
{
    ICorRuntimeHost *pRuntimeHost = NULL; // Alternative: ICLRRuntimeHost
    mscorlib::_AssemblyPtr pAssembly = NULL;

    parseArg(argc, argv);

    init();

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

    saveFile(argOutputFilename.c_str());

    logPrintf(LOG_LEVEL_INFO, "[*] CLRHosting Terminated\n");

    return 0;
}
