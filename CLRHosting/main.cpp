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

typedef void *func(void);

void **CorJitCompiler;
compileMethodFunc *originCompileMethod;

struct methodDefInfo {
    std::string name;
    BYTE *header;
    BYTE *code;
    UINT codesize;
};
std::unordered_map<int, methodDefInfo> methodMap;

void openPackedFile(const char *filename, char **fileData, int *fileLength)
{
    std::ifstream target(filename, std::ios::in | std::ios::binary | std::ios::ate);

    if (!target.is_open()) {
        exit(1);
    }

    *fileLength = target.tellg();

    *fileData = new char[*fileLength];
    target.seekg(0, std::ios::beg);
    target.read(*fileData, *fileLength);

    target.close();

    printf("[*] file: %s\n", filename);
    printf("[*] file length: %d\n", *fileLength);
}

void saveFile(char *fileData, int fileLength)
{
    std::ofstream target("output.exe_", std::ofstream::binary);

    target.write(fileData, fileLength);
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

    printf("[*] hooking!\n");

    // Check whether the hook has been edited
    if (CorJitCompiler[0] != compileMethodHook) {
        printf("[*] Hook has been edited!\n");
    }

    // Get the info of module
    token = (0x06000000 + *(USHORT *)info->ftn);

    if (!methodMap.count(token)) {
        goto HookEnd;
    }

    method = methodMap[token];

    printf("\t[*] Token: %x\n", token);
    printf("\t[*] Name: %s\n", method.name.c_str());

    // Check whether the IL has been edited
    if (info->ILCodeSize == method.codesize) {
        int i = 0;
        
        for (; i < method.codesize; ++i) {
            if (info->ILCode[i] != method.code[i]) {
                break;
            }
        }

        if (i == method.codesize) {
            goto HookEnd;
        }
    }

    // IL has been edited, update it
    printf("\t[!] IL has been edited!\n");

    if (info->ILCodeSize > method.codesize) {
        printf("\t[!] TODO: new IL is larger than origin IL and may not have space to store it\n");
        goto HookEnd;
    }

    // Modify origin IL
    memcpy(method.code, info->ILCode, info->ILCodeSize);

HookEnd:
    return originCompileMethod(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);
}

int jitHook(void)
{
    HMODULE clrjit;
    func *getjit;
    DWORD old;
    
    // Preloading clrjit.dll
    AddDllDirectory(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\");
    clrjit = LoadLibraryExA("clrjit.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (clrjit == NULL) {
        printf("[x] Failed to load clrjit.dll\n");
        exit(1);
    }
    printf("[*] Load clrjit.dll\n");

    // Hook
    getjit = (func *)GetProcAddress(clrjit, "getJit");
    CorJitCompiler = *(void ***)getjit();
    originCompileMethod = (compileMethodFunc *)CorJitCompiler[0];
    
    VirtualProtect(&CorJitCompiler[0], 0x8, PAGE_EXECUTE_READWRITE, &old);
    CorJitCompiler[0] = compileMethodHook;
    VirtualProtect(&CorJitCompiler[0], 0x8, old, &old);

    printf("[*] Hook compileMethod\n");
    printf("[*] originCompileMethod: %p\n", originCompileMethod);
}

/*
 * Parse Method table stream of "#~" Stream
 */
void assemblyAnalyze(char *baseaddr)
{
    printf("[*] Analyze assembly\n");

    BYTE *nt_hdr = (BYTE *)baseaddr + *(UINT *)(baseaddr + 0x3c);
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

    BYTE *image_cor20_hdr = (BYTE *)baseaddr + image_cor20_hdr_rva + offset;
    UINT metadata_rva = *(UINT *)(image_cor20_hdr + 8);
    BYTE *metadata_root = (BYTE *)baseaddr + metadata_rva + offset;
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
        UINT rva = *(UINT *)method_table;
        USHORT name_idx = *(USHORT *)(method_table + 0x8);
        std::string name((char *)(strings_stream + name_idx));
        UINT token = 0x06000000 + i + 1;

        printf("\t[*] Method: %s\n", name.c_str());
        printf("\t\t[*] token: %x\n", token);

        if (!rva) {
            continue;
        }

        header = (BYTE *)baseaddr + rva + offset;

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

        printf("\t\t[*] rva: %x\n", rva);
        printf("\t\t[*] IL code size: %#x\n", codesize);
        printf("\t\t[*] IL code: %p\n", code);

        methodMap[token] = { name, header, code, codesize };
    }
}

int main(int argc, char *argv[])
{
    ICorRuntimeHost *pRuntimeHost = NULL; // Alternative: ICLRRuntimeHost
    mscorlib::_AssemblyPtr pAssembly = NULL;
    char *fileData;
    int fileLength;

    if (argc > 1) {
        openPackedFile(argv[1], &fileData, &fileLength);
    }
    else {
        openPackedFile(PACKED_ASSEMBLY_NAME, &fileData, &fileLength);
    }

    if (clrHost(&pRuntimeHost) < 0) {
        exit(1);
    }

    jitHook();

    assemblyAnalyze(fileData);

    if (assemblyLoad(pRuntimeHost, (mscorlib::_AssemblyPtr *)&pAssembly, fileData, fileLength) < 0) {
        exit(1);
    }

    if (assemblyRun(pAssembly, argc, argv) < 0) {
        exit(1);
    }

    saveFile(fileData, fileLength);

    printf("[*] CLRHosting Terminated\n");

    return 0;
}
