#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <comdef.h>

// C-related
#include <stdio.h>

// C++-related
#include <iostream>
#include <fstream>
#include <string>

// mscorlib-related
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

// others
#include "corjit.h"

// auto_rename: https://stackoverflow.com/questions/55117881/load-c-sharp-assembly-in-c-c-mscoree-tlh-errors
#import "C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorlib.tlb" raw_interfaces_only auto_rename

// target dotnet exe
#define PACKED_ASSEMBLY_NAME "JIThook.exe"

typedef void *func(void);

void **CorJitCompiler;
compileMethodFunc *originCompileMethod;

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
    printf("[*] file length: %d\n", fileLength);
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

    printf("PAUSE\n");
    scanf("%*c");

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
    printf("[*] hooking!\n");

    // Check whether the hook has been edited
    if (CorJitCompiler[0] != compileMethodHook) {
        printf("[*] Hook has been edited!\n");
    }

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

int main(int argc, char *argv[])
{
    ICorRuntimeHost *pRuntimeHost = NULL; // Alternative: ICLRRuntimeHost
    mscorlib::_AssemblyPtr pAssembly = NULL;    
    char *fileData;
    int fileLength;

    openPackedFile(PACKED_ASSEMBLY_NAME, &fileData, &fileLength);

    if (clrHost(&pRuntimeHost) < 0) {
        exit(1);
    }

    jitHook();

    if (assemblyLoad(pRuntimeHost, (mscorlib::_AssemblyPtr *)&pAssembly, fileData, fileLength) < 0) {
        exit(1);
    }

    if (assemblyRun(pAssembly, argc, argv) < 0) {
        exit(1);
    }

    return 0;
}
