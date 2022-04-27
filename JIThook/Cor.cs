using System;
using System.Runtime.InteropServices;

namespace JIThook
{
    public sealed class Cor
    {
        public enum CorJitFlag
        {
            CORJIT_FLG_SPEED_OPT = 0x00000001,
            CORJIT_FLG_SIZE_OPT = 0x00000002,
            CORJIT_FLG_DEBUG_CODE = 0x00000004,
            CORJIT_FLG_DEBUG_EnC = 0x00000008,
            CORJIT_FLG_DEBUG_INFO = 0x00000010,
            CORJIT_FLG_LOOSE_EXCEPT_ORDER = 0x00000020,
            CORJIT_FLG_TARGET_PENTIUM = 0x00000100,
            CORJIT_FLG_TARGET_PPRO = 0x00000200,
            CORJIT_FLG_TARGET_P4 = 0x00000400,
            CORJIT_FLG_TARGET_BANIAS = 0x00000800,
            CORJIT_FLG_USE_FCOMI = 0x00001000,
            CORJIT_FLG_USE_CMOV = 0x00002000,
            CORJIT_FLG_USE_SSE2 = 0x00004000,
            CORJIT_FLG_PROF_CALLRET = 0x00010000,
            CORJIT_FLG_PROF_ENTERLEAVE = 0x00020000,
            CORJIT_FLG_PROF_INPROC_ACTIVE_DEPRECATED = 0x00040000,
            CORJIT_FLG_PROF_NO_PINVOKE_INLINE = 0x00080000,
            CORJIT_FLG_SKIP_VERIFICATION = 0x00100000,
            CORJIT_FLG_PREJIT = 0x00200000,
            CORJIT_FLG_RELOC = 0x00400000,
            CORJIT_FLG_IMPORT_ONLY = 0x00800000,
            CORJIT_FLG_IL_STUB = 0x01000000,
            CORJIT_FLG_PROCSPLIT = 0x02000000,
            CORJIT_FLG_BBINSTR = 0x04000000,
            CORJIT_FLG_BBOPT = 0x08000000,
            CORJIT_FLG_FRAMED = 0x10000000,
            CORJIT_FLG_ALIGN_LOOPS = 0x20000000,
            CORJIT_FLG_PUBLISH_SECRET_PARAM = 0x40000000,
        }

        public enum CorInfoCallConv
        {
            C = 1,
            DEFAULT = 0,
            EXPLICITTHIS = 64,
            FASTCALL = 4,
            FIELD = 6,
            GENERIC = 16,
            HASTHIS = 32,
            LOCAL_SIG = 7,
            MASK = 15,
            NATIVEVARARG = 11,
            PARAMTYPE = 128,
            PROPERTY = 8,
            STDCALL = 2,
            THISCALL = 3,
            VARARG = 5
        }
        public enum CorInfoType : byte
        {
            BOOL = 2,
            BYREF = 18,
            BYTE = 4,
            CHAR = 3,
            CLASS = 20,
            COUNT = 23,
            DOUBLE = 15,
            FLOAT = 14,
            INT = 8,
            LONG = 10,
            NATIVEINT = 12,
            NATIVEUINT = 13,
            PTR = 17,
            REFANY = 21,
            SHORT = 6,
            STRING = 16,
            UBYTE = 5,
            UINT = 9,
            ULONG = 11,
            UNDEF = 0,
            USHORT = 7,
            VALUECLASS = 19,
            VAR = 22,
            VOID = 1
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CorinfoSigInst
        {
            public uint classInstCount;
            public unsafe IntPtr* classInst;
            public uint methInstCount;
            public unsafe IntPtr* methInst;
        }
        public enum CorInfoOptions : ushort
        {
            CORINFO_OPT_INIT_LOCALS = 0x00000010,
            CORINFO_GENERICS_CTXT_FROM_THIS = 0x00000020,
            CORINFO_GENERICS_CTXT_FROM_METHODDESC = 0x00000040,
            CORINFO_GENERICS_CTXT_FROM_METHODTABLE = 0x00000080,

            CORINFO_GENERICS_CTXT_MASK = (CORINFO_GENERICS_CTXT_FROM_THIS |
                                                       CORINFO_GENERICS_CTXT_FROM_METHODDESC |
                                                       CORINFO_GENERICS_CTXT_FROM_METHODTABLE),

            CORINFO_GENERICS_CTXT_KEEP_ALIVE = 0x00000100
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CorinfoSigInfo
        {
            public CorInfoCallConv callConv;
            public IntPtr retTypeClass;
            public IntPtr retTypeSigClass;
            public CorInfoType retType;
            public byte flags;
            public ushort numArgs;
            public CorinfoSigInst sigInst;
            public IntPtr args;
            public uint token;
            public IntPtr sig;
            public IntPtr scope;
        }
        public unsafe interface ICorMethodInfo
        {
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct CorMethodInfo64 : ICorMethodInfo
        {
            // CORINFO_METHOD_HANDLE
            public IntPtr ftn;

            // CORINFO_MODULE_HANDLE
            public IntPtr scope;

            public byte* ilCode;
            public UInt32 ilCodeSize;
            public UInt32 maxStack;
            public UInt32 EHCount;
            public CorInfoOptions options;
            public int regionKind;
            public CorinfoSigInfo args;
            public CorinfoSigInfo locals;
        }
    }
}
