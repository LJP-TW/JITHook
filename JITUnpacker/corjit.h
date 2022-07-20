#pragma once
// Ref: 
// - https://github.com/dotnet/runtime/blob/62eb291312749c52507309d50051dd61538cc62d/src/coreclr/inc/corjit.h
// - https://github.com/dotnet/runtime/blob/62eb291312749c52507309d50051dd61538cc62d/src/coreclr/inc/corinfo.h 
#include <Windows.h>
#include <dmerror.h>
#include <comdef.h>

#define NO_ERROR 0L

/*****************************************************************************/
    // These are error codes returned by CompileMethod
enum CorJitResult
{
    // Note that I dont use FACILITY_NULL for the facility number,
    // we may want to get a 'real' facility number
    CORJIT_OK               = NO_ERROR,
    CORJIT_BADCODE          = MAKE_HRESULT(SEVERITY_ERROR, FACILITY_NULL, 1),
    CORJIT_OUTOFMEM         = MAKE_HRESULT(SEVERITY_ERROR, FACILITY_NULL, 2),
    CORJIT_INTERNALERROR    = MAKE_HRESULT(SEVERITY_ERROR, FACILITY_NULL, 3),
    CORJIT_SKIPPED          = MAKE_HRESULT(SEVERITY_ERROR, FACILITY_NULL, 4),
    CORJIT_RECOVERABLEERROR = MAKE_HRESULT(SEVERITY_ERROR, FACILITY_NULL, 5),
    CORJIT_IMPLLIMITATION   = MAKE_HRESULT(SEVERITY_ERROR, FACILITY_NULL, 6),
};

class ICorJitInfo;

typedef void *CORINFO_METHOD_HANDLE;
typedef void *CORINFO_MODULE_HANDLE;
typedef void *CORINFO_SIG_INFO;

// These are returned from getMethodOptions
enum CorInfoOptions
{
    CORINFO_OPT_INIT_LOCALS                 = 0x00000010, // zero initialize all variables

    CORINFO_GENERICS_CTXT_FROM_THIS         = 0x00000020, // is this shared generic code that access the generic context from the this pointer?  If so, then if the method has SEH then the 'this' pointer must always be reported and kept alive.
    CORINFO_GENERICS_CTXT_FROM_METHODDESC   = 0x00000040, // is this shared generic code that access the generic context from the ParamTypeArg(that is a MethodDesc)?  If so, then if the method has SEH then the 'ParamTypeArg' must always be reported and kept alive. Same as CORINFO_CALLCONV_PARAMTYPE
    CORINFO_GENERICS_CTXT_FROM_METHODTABLE  = 0x00000080, // is this shared generic code that access the generic context from the ParamTypeArg(that is a MethodTable)?  If so, then if the method has SEH then the 'ParamTypeArg' must always be reported and kept alive. Same as CORINFO_CALLCONV_PARAMTYPE
    CORINFO_GENERICS_CTXT_MASK              = CORINFO_GENERICS_CTXT_FROM_THIS | CORINFO_GENERICS_CTXT_FROM_METHODDESC | CORINFO_GENERICS_CTXT_FROM_METHODTABLE,
    CORINFO_GENERICS_CTXT_KEEP_ALIVE        = 0x00000100, // Keep the generics context alive throughout the method even if there is no explicit use, and report its location to the CLR

};

//
// what type of code region we are in
//
enum CorInfoRegionKind
{
    CORINFO_REGION_NONE,
    CORINFO_REGION_HOT,
    CORINFO_REGION_COLD,
    CORINFO_REGION_JIT,
};

struct CORINFO_METHOD_INFO
{
    CORINFO_METHOD_HANDLE       ftn;
    CORINFO_MODULE_HANDLE       scope;
    uint8_t                    *ILCode;
    unsigned                    ILCodeSize;
    unsigned                    maxStack;
    unsigned                    EHcount;
    CorInfoOptions              options;
    CorInfoRegionKind           regionKind;
    CORINFO_SIG_INFO            args;
    CORINFO_SIG_INFO            locals;
};

typedef CorJitResult(compileMethodFunc)(
    void                            *thisptr,
    ICorJitInfo                     *comp,               /* IN */
    struct CORINFO_METHOD_INFO      *info,               /* IN */
    unsigned /* code:CorJitFlag */   flags,              /* IN */
    uint8_t                        **nativeEntry,        /* OUT */
    uint32_t                        *nativeSizeOfCode    /* OUT */
    );

// These are the flags set on an CORINFO_EH_CLAUSE
enum CORINFO_EH_CLAUSE_FLAGS
{
    CORINFO_EH_CLAUSE_NONE      = 0,
    CORINFO_EH_CLAUSE_FILTER    = 0x0001,      // If this bit is on, then this EH entry is for a filter
    CORINFO_EH_CLAUSE_FINALLY   = 0x0002,     // This clause is a finally clause
    CORINFO_EH_CLAUSE_FAULT     = 0x0004,       // This clause is a fault clause
    CORINFO_EH_CLAUSE_DUPLICATE = 0x0008,   // Duplicated clause. This clause was duplicated to a funclet which was pulled out of line
    CORINFO_EH_CLAUSE_SAMETRY   = 0x0010,     // This clause covers same try block as the previous one. (Used by NativeAOT ABI.)
};

struct CORINFO_EH_CLAUSE
{
    CORINFO_EH_CLAUSE_FLAGS     Flags;
    uint32_t                    TryOffset;
    uint32_t                    TryLength;
    uint32_t                    HandlerOffset;
    uint32_t                    HandlerLength;
    union
    {
        uint32_t                ClassToken;       // use for type-based exception handlers
        uint32_t                FilterOffset;     // use for filter-based exception handlers (COR_ILEXCEPTION_FILTER is set)
    };
};

typedef void (getEHinfoFunc)(
    ICorJitInfo            *thisptr,
    CORINFO_METHOD_HANDLE   ftn,              /* IN */
    unsigned                EHnumber,         /* IN */
    CORINFO_EH_CLAUSE      *clause            /* OUT */
    );

struct CorILMethod_FatFormat
{
    USHORT  flags; // and size
    USHORT  maxStack;
    UINT    codeSize;
    UINT    localVarSigTok;
};

struct CorILMethod_Sect_EHTable
{
    BYTE                        kind;
    BYTE                        dataSize;
    USHORT                      reserved;
    struct CORINFO_EH_CLAUSE    clauses[0];
};