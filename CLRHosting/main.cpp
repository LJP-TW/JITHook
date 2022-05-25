#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <comdef.h>

// C-related
#include <stdio.h>

// C++-related
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>

// mscorlib-related
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

// others
#include "corjit.h"

#define PAUSE() do { printf("PAUSE\n"); scanf("%*c"); } while(0)

// auto_rename: https://stackoverflow.com/questions/55117881/load-c-sharp-assembly-in-c-c-mscoree-tlh-errors
#import "C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorlib.tlb" raw_interfaces_only auto_rename

// target dotnet exe
#define PACKED_ASSEMBLY_NAME "JIThook.exe"

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
        printf("[!] Only support CorILMethod_TinyFormat for now\n");
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

    printf("[*] file: %s\n", filename);
    printf("[*] file length: %d\n", PEStruct.PEFileLength);
}

void saveFile(void)
{
    std::ofstream target("output.exe_", std::ofstream::binary);

    target.write((char *)PEStruct.PEFile, PEStruct.PEFileLength);
    target.close();

    printf("[*] Checkout output.exe_\n");
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
        printf("[!] CLRCreateInstance(...) failed\n");
        return -1;
    }
    printf("[+] CLRCreateInstance(...) succeeded\n");

    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (VOID **)&pRuntimeInfo);

    if (FAILED(hr))
    {
        printf("[!] pMetaHost->GetRuntime(...) failed\n");
        return -1;
    }
    printf("[+] pMetaHost->GetRuntime(...) succeeded\n");

    hr = pRuntimeInfo->IsLoadable(&bLoadable);

    if (FAILED(hr) || !bLoadable)
    {
        printf("[!] pRuntimeInfo->IsLoadable(...) failed\n");
        return -1;
    }
    printf("[+] pRuntimeInfo->IsLoadable(...) succeeded\n");

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID **)pRuntimeHost);

    if (FAILED(hr))
    {
        printf("[!] pRuntimeInfo->GetInterface(...) failed\n");
        return -1;
    }
    printf("[+] pRuntimeInfo->GetInterface(...) succeeded\n");

    hr = (*pRuntimeHost)->Start();

    if (FAILED(hr))
    {
        printf("[!] pRuntimeHost->Start() failed\n");
        return -1;
    }
    printf("[+] pRuntimeHost->Start() succeeded\n");
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
        printf("[!] pRuntimeHost->GetDefaultDomain(...) failed\n");
        return -1;
    }
    printf("[+] pRuntimeHost->GetDefaultDomain(...) succeeded\n");

    hr = pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (VOID **)&pDefaultAppDomain);

    if (FAILED(hr))
    {
        printf("[!] pAppDomainThunk->QueryInterface(...) failed\n");
        return -1;
    }
    printf("[+] pAppDomainThunk->QueryInterface(...) succeeded\n");

    rgsabound[0].cElements = fileLength;
    rgsabound[0].lLbound = 0;

    pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

    hr = SafeArrayAccessData(pSafeArray, &pvData);

    if (FAILED(hr))
    {
        printf("[!] SafeArrayAccessData(...) failed\n");
        return -1;
    }
    printf("[+] SafeArrayAccessData(...) succeeded\n");

    memcpy(pvData, fileData, fileLength);

    hr = SafeArrayUnaccessData(pSafeArray);

    if (FAILED(hr))
    {
        printf("[!] SafeArrayUnaccessData(...) failed\n");
        return -1;
    }
    printf("[+] SafeArrayUnaccessData(...) succeeded\n");

    hr = pDefaultAppDomain->Load_3(pSafeArray, &(*pAssembly));

    if (FAILED(hr))
    {
        printf("[!] pDefaultAppDomain->Load_3(...) failed\n");
        return -1;
    }
    printf("[+] pDefaultAppDomain->Load_3(...) succeeded\n");
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
        printf("[!] pAssembly->get_EntryPoint(...) failed\n");
        return -1;
    }
    printf("[+] pAssembly->get_EntryPoint(...) succeeded\n");

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
        printf("[!] pMethodInfo->Invoke_3(...) failed, hr = %X\n", hr);
        return -1;
    }
    printf("[+] pMethodInfo->Invoke_3(...) succeeded\n");
}

void reportNative(uint8_t **nativeEntry, uint32_t *nativeSizeOfCode)
{
    printf("\t[*] Native entry: %p\n", *nativeEntry);
    printf("\t[*] Native size of code: %x\n", *nativeSizeOfCode);
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

    printf("[*] hooking!\n");

    // Check whether the hook has been edited
    if (CorJitCompiler[0] != newCompileMethod) {
        printf("[*] Hook has been edited!\n");
    }

    // Get the info of module
    token = (0x06000000 + *(USHORT *)info->ftn);

    if (!methodMap.count(token)) {
        goto HookEnd;
    }

    method = methodMap[token];

    printf("\t[*] Token: %x\n", token);
    printf("\t[*] Name: %s\n", method.methodName.c_str());

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
    printf("\t[!] IL has been edited!\n");

    if (info->ILCodeSize > method.methodILCodeSize) {
        INT ILAddr;
        printf("\t[!] TODO: new IL is larger than origin IL and may not have space to store it\n");

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
        printf("[x] Failed to load clrjit.dll\n");
        exit(1);
    }
    printf("[*] Load clrjit.dll\n");

    // Write trampoline
    addr = (BYTE *)clrjit + 0x40;
    printf("[*] Write trampoline to address %p\n", addr);

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

    printf("[*] Hook compileMethod\n");
    printf("[*] originCompileMethod: %p\n", originCompileMethod);
}

void assemblyAnalyze(void)
{
    printf("[*] Analyze assembly\n");

    BYTE *baseaddr = PEStruct.PEFile;
    BYTE *nt_hdr = baseaddr + *(UINT *)(baseaddr + 0x3c);
    USHORT section_cnt = *(USHORT *)(nt_hdr + 0x6);
    UINT optional_hdr_size = *(USHORT *)(nt_hdr + 0x14);
    BYTE *optional_hdr = nt_hdr + 0x18;
    USHORT magic = *(USHORT *)optional_hdr;

    if (magic != 0x20b) {
        printf("[!] Only support 64-bit program\n");
        exit(1);
    }

    BYTE *section_hdr = optional_hdr + optional_hdr_size;
    INT offset = 0;
    UINT image_cor20_hdr_rva = *(UINT *)(optional_hdr + 0xe0);

    PEStruct.sectionCnt = section_cnt;
    PEStruct.sectionHdrOffset = section_hdr - baseaddr;
    PEStruct.sectionRawAlignment = *(UINT *)(optional_hdr + 0x24);
    PEStruct.sectionVAAlignment  = *(UINT *)(optional_hdr + 0x20);

    // Find raw addr of image_cor20_hdr
    BYTE *section_cur = section_hdr;
    while (section_cnt--) {
        UINT va = *(UINT *)(section_cur + 0xc);
        UINT vasize = *(UINT *)(section_cur + 0x8);

        if (va <= image_cor20_hdr_rva && image_cor20_hdr_rva < va + vasize) {
            UINT ra = *(UINT *)(section_cur + 0x14);
            offset = ra - va;
            break;
        }

        section_cur += 0x28;
    }

    BYTE *image_cor20_hdr = baseaddr + image_cor20_hdr_rva + offset;
    UINT metadata_rva = *(UINT *)(image_cor20_hdr + 8);
    BYTE *metadata_root = baseaddr + metadata_rva + offset;
    UINT version_len = *(UINT *)(metadata_root + 0xc);
    UINT padded_version_len = (UINT)((version_len + 3) & (~0x03));
    UINT num_of_streams = *(USHORT *)(metadata_root + 0x12 + padded_version_len);
    BYTE *stream_hdr = metadata_root + 0x14 + padded_version_len;
    BYTE *tilde_stream_hdr = NULL;
    BYTE *strings_stream_hdr = NULL;

    for (UINT i = 0; i < num_of_streams; ++i)
    {
        std::string rcName((char *)(stream_hdr + 8));

        if (rcName == "#~")
        {
            tilde_stream_hdr = stream_hdr;
        }
        else if (rcName == "#Strings")
        {
            strings_stream_hdr = stream_hdr;
        }
        stream_hdr += 0x8 + ((rcName.length() + 4) & (~0x03));
    }

    UINT tilde_iOffset = *(UINT *)tilde_stream_hdr;
    UINT tilde_iSize = *(UINT *)(tilde_stream_hdr + 4);

    UINT strings_iOffset = *(UINT *)strings_stream_hdr;
    UINT strings_iSize = *(UINT *)(strings_stream_hdr + 4);

    BYTE *strings_stream = metadata_root + strings_iOffset;

    // ECMA-335 6th II.24.2.6
    BYTE *table_stream = metadata_root + tilde_iOffset;
    
    ULONGLONG maskvalid = *(ULONGLONG *)(table_stream + 8);
    ULONGLONG masksorted = *(ULONGLONG *)(table_stream + 0x10);

    UINT *metadata_table_nums = new UINT[0x40];
    BYTE *rows = table_stream + 0x18;

    for (ULONGLONG i = 0, l_maskvalid = maskvalid; l_maskvalid != 0; l_maskvalid >>= 1, i++)
    {
        if ((l_maskvalid & 1) == 1)
        {
            metadata_table_nums[i] = *(UINT *)rows;
            rows += 4;
        }
        else
        {
            metadata_table_nums[i] = 0;
        }
    }

    UINT metadata_table_sizes[] = {
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
        tables[i] = tables[i - 1] + metadata_table_nums[i - 1] * metadata_table_sizes[i - 1];
    }

    BYTE *method_table = tables[6];

    for (UINT i = 0; i < metadata_table_nums[6]; ++i, method_table += 0xe)
    {
        BYTE *code;
        UINT codesize;
        int format;
        // ECMA-335 6th II.22.26
        BYTE *header;
        UINT *prva = (UINT *)method_table;
        USHORT name_idx = *(USHORT *)(method_table + 0x8);
        std::string name((char *)(strings_stream + name_idx));
        UINT token = 0x06000000 + i + 1;

        printf("\t[*] Method: %s\n", name.c_str());
        printf("\t\t[*] token: %x\n", token);

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

        printf("\t\t[*] rva: %x\n", *prva);
        printf("\t\t[*] IL code size: %#x\n", codesize);
        printf("\t\t[*] IL code: %p\n", code);

        methodMap[token] = { prva, name, header, code, codesize };
    }
}

int main(int argc, char *argv[])
{
    ICorRuntimeHost *pRuntimeHost = NULL; // Alternative: ICLRRuntimeHost
    mscorlib::_AssemblyPtr pAssembly = NULL;

    if (argc > 1) {
        openPackedFile(argv[1]);
    }
    else {
        openPackedFile(PACKED_ASSEMBLY_NAME);
    }

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

    printf("[*] CLRHosting Terminated\n");

    return 0;
}
