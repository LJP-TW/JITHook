﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// dnlib
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnlib.IO;
using dnlib.PE;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using MethodImplAttributes = dnlib.DotNet.MethodImplAttributes;

// Ref:
// - https://github.com/0xd4d/dnlib/blob/master/Examples/
// - https://stackoverflow.com/questions/54441057/inject-a-class-with-a-method-using-dnlib

namespace Packer
{
    class packer
    {
        // NativeAPI
        internal enum Protection
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
           Protection flNewProtect, out uint lpflOldProtect);

        // Cor
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

        // Clrjit
        [DllImport("Clrjit.dll", CallingConvention = System.Runtime.InteropServices.CallingConvention.StdCall, 
            PreserveSig = true)]
        private static extern IntPtr getJit();

        [UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.StdCall, 
            SetLastError = true)]
        public unsafe delegate int CompileMethodDel64(
            IntPtr thisPtr, [In] IntPtr corJitInfo, [In] CorMethodInfo64* methodInfo, CorJitFlag flags,
            [Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode);

        [UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.ThisCall)]
        public delegate uint GetMethodDefFromMethodDel(IntPtr thisPtr, IntPtr ftn);

        public static IntPtr VTableAddr
        {
            get
            {
                IntPtr pVTable = getJit();
                if (pVTable == IntPtr.Zero)
                    throw new Exception("Could not retrieve address for getJit");
                return pVTable;
            }
        }

        // Unpacker
        private const int GET_METHOD_DEF_FROM_METHOD_SLOT_INDEX = 105;
        public static CompileMethodDel64 OriginalCompileMethod { [MethodImpl(MethodImplOptions.NoInlining)] get; private set; }
        public static CompileMethodDel64 NewCompileMethod { [MethodImpl(MethodImplOptions.NoInlining)] get; set; }

        private static IntPtr pCompileMethod;

        private static Dictionary<IntPtr, Module> interceptorModules = new Dictionary<IntPtr, Module>();

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static unsafe int MyCompileMethod(IntPtr thisPtr, [In] IntPtr corJitInfo,
               [In] CorMethodInfo64* methodInfo, CorJitFlag flags,
               [Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode)
        {
            Console.WriteLine("[J] JIT hook");

            string methodToken = (0x06000000 + *(ushort*)methodInfo->ftn).ToString("x8");
            Console.WriteLine("[J] methodToken: {0}", methodToken);

            Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
            System.IO.Stream stream = assembly.GetManifestResourceStream(methodToken);
            if (stream == null)
            {
                Console.WriteLine("[J] JIT hook end: methodToken not found");
                return OriginalCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
            }

            byte[] newil = new byte[stream.Length];
            stream.Read(newil, 0, newil.Length);

            Console.WriteLine("[J] new IL: {0}", BitConverter.ToString(newil));

            IntPtr ilCodeHandle = Marshal.AllocHGlobal(newil.Length);
            Marshal.Copy(newil, 0, ilCodeHandle, newil.Length);

            // Patch
            methodInfo->ilCode = (byte*)ilCodeHandle.ToPointer();
            methodInfo->ilCodeSize = (uint)newil.Length;

            Console.WriteLine("[J] Patch!");

            Console.WriteLine("[J] JIT hook end");
            return OriginalCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
        }

        public static unsafe void Hook()
        {
            uint old;
            
            NewCompileMethod = MyCompileMethod;

            Console.WriteLine("[*] Init Hook");

            pCompileMethod = Marshal.ReadIntPtr(VTableAddr);

            OriginalCompileMethod = (CompileMethodDel64)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(pCompileMethod), 
                typeof(CompileMethodDel64));
            
            RuntimeHelpers.PrepareDelegate(OriginalCompileMethod);
            RuntimeHelpers.PrepareDelegate(NewCompileMethod);

            // RuntimeHelpers.PrepareMethod(typeof(packer).GetMethod("callentry", BindingFlags.Static | BindingFlags.NonPublic).MethodHandle);
            RuntimeHelpers.PrepareMethod(typeof(Console).GetMethod("WriteLine", new[] { typeof(string) }).MethodHandle);
            RuntimeHelpers.PrepareMethod(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly").MethodHandle);
            RuntimeHelpers.PrepareMethod(typeof(System.Reflection.Assembly).GetMethod("GetManifestResourceStream", new[] { typeof(string) }).MethodHandle);
            // RuntimeHelpers.PrepareMethod(typeof(System.IO.Stream).GetMethod("Read").MethodHandle);
            RuntimeHelpers.PrepareMethod(typeof(Marshal).GetMethod("AllocHGlobal", new[] { typeof(int) }).MethodHandle);
            RuntimeHelpers.PrepareMethod(typeof(Marshal).GetMethod("Copy", new[] { typeof(byte[]), typeof(int), typeof(IntPtr), typeof(int) }).MethodHandle);

            // Console.WriteLine("[*] Prepare {0}", typeof(packer).GetMethod("callentry", BindingFlags.Static | BindingFlags.NonPublic).Name);
            Console.WriteLine("[*] Prepare {0}", typeof(Console).GetMethod("WriteLine", new[] { typeof(string) }).Name);
            Console.WriteLine("[*] Prepare {0}", typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly").Name);
            Console.WriteLine("[*] Prepare {0}", typeof(System.Reflection.Assembly).GetMethod("GetManifestResourceStream", new[] { typeof(string) }).Name);
            // Console.WriteLine("[*] Prepare {0}", typeof(System.IO.Stream).GetMethod("Read").Name);
            Console.WriteLine("[*] Prepare {0}", typeof(Marshal).GetMethod("AllocHGlobal", new[] { typeof(int) }).Name);
            Console.WriteLine("[*] Prepare {0}", typeof(Marshal).GetMethod("Copy", new[] { typeof(byte[]), typeof(int), typeof(IntPtr), typeof(int) }).Name);

            if (!VirtualProtect(pCompileMethod, (uint)IntPtr.Size, Protection.PAGE_EXECUTE_READWRITE, out old))
                throw new Exception("[!] Cannot change memory protection flags.");
            
            Marshal.WriteIntPtr(pCompileMethod, Marshal.GetFunctionPointerForDelegate(NewCompileMethod));
            
            VirtualProtect(pCompileMethod, (uint)IntPtr.Size, (Protection)old, out old);
        }
        public static void entry()
        {
            Console.WriteLine("[*] packer entry");

            Hook();

            Console.WriteLine("[*] hook installed!");
        }
    }
    class Program
    {
        static ModuleContext modCtx;
        static ModuleDefMD module;
        static IPEImage PEImage;
        static DataReader reader;

        static string argOutputFile;
        static string argInputFile;

        static void packMethod(TypeDef type, MethodDef method)
        {
            uint offset = ((uint)PEImage.ToFileOffset(method.RVA)) + method.Body.HeaderSize;
            int codesize = 0;

            // Calc codesize
            foreach (Instruction ins in method.Body.Instructions)
            {
                codesize += ins.GetSize();
            }

            // Read origin IL
            reader.Position = offset;

            byte[] originILbytes = reader.ReadBytes(codesize);
            
            // Save origin IL to resources
            module.Resources.Add(new EmbeddedResource(method.MDToken.ToString().ToLower(), originILbytes,
                ManifestResourceAttributes.Private));

            // Patch IL
            HashSet<uint> tryStart = new HashSet<uint>();
            HashSet<uint> handlerStart = new HashSet<uint>();
            HashSet<uint> handlerEnd = new HashSet<uint>();
            HashSet<string> brTarget = new HashSet<string>();

            method.Body.KeepOldMaxStack = true;

            foreach (ExceptionHandler ex in method.Body.ExceptionHandlers)
            {
                tryStart.Add(ex.TryStart.Offset);
                handlerStart.Add(ex.HandlerStart.Offset);
                handlerEnd.Add(ex.HandlerEnd.Offset);
            }

            for (int i = 0; i < method.Body.Instructions.Count - 1; i++)
            {
                if (method.Body.Instructions[i].IsLeave() ||
                    method.Body.Instructions[i].IsBr() ||
                    method.Body.Instructions[i].IsConditionalBranch())
                {
                    brTarget.Add(method.Body.Instructions[i].ToString().Split()[2]);
                }
            }

            for (int i = 0; i < method.Body.Instructions.Count - 1; i++)
            {
                int inssize = method.Body.Instructions[i].GetSize();
                string IL = method.Body.Instructions[i].ToString().Split(':')[0];

                if (brTarget.Contains(IL) ||
                    tryStart.Contains(method.Body.Instructions[i].Offset) ||
                    handlerStart.Contains(method.Body.Instructions[i].Offset) ||
                    handlerEnd.Contains(method.Body.Instructions[i].Offset + ((uint)inssize)))
                {
                    continue;
                }

                method.Body.Instructions[i] = OpCodes.Conv_Ovf_U2_Un.ToInstruction();
                for (int _ = 0; _ < inssize - 1; ++_)
                {
                    method.Body.Instructions.Insert(i, OpCodes.Conv_Ovf_U2_Un.ToInstruction());
                }
            }
        }
        static void pack()
        {
            // List types
            foreach (TypeDef type in module.GetTypes())
            {
                if (type.FullName == "<Module>" ||
                    type.FullName == "Packer.packer" || type.FullName.StartsWith("Packer.packer/"))
                {
                    continue;
                }

                Console.WriteLine("[*] Packing Type: {0}", type.FullName);

                // List methods
                foreach (MethodDef method in type.Methods)
                {
                    Console.WriteLine("\t[*] Packing Method: {0} ({1})", method.FullName, method.MDToken);
                    
                    if (method.FullName == module.EntryPoint.FullName)
                    {
                        Console.WriteLine("\t\t[!] Skip entry point");
                        continue;
                    }

                    packMethod(type, method);
                }
            }
        }
        static void Main(string[] args)
        {
            argInputFile = "./testprog.exe";
            argOutputFile = "./testprog_packed.exe";

            for (int i = 0; i < args.Length; ++i)
            {
                if (args[i] == "-o")
                {
                    ++i;
                    argOutputFile = args[i];
                } else
                {
                    argInputFile = args[i];
                }
            }

            // Get target module
            modCtx = ModuleDef.CreateModuleContext();
            module = ModuleDefMD.Load(@argInputFile, modCtx);
            PEImage = module.Metadata.PEImage;
            reader = module.Metadata.PEImage.DataReaderFactory.CreateReader();

            // Get packer module
            ModuleContext packerModCtx = ModuleDef.CreateModuleContext();
            ModuleDefMD packerModule = ModuleDefMD.Load(@Environment.GetCommandLineArgs()[0], packerModCtx);

            // Get Packer.packer type of packer module
            TypeDef packerType = null;

            Console.WriteLine("[*] Search for type Packer.packer...");
            foreach (var _type in packerModule.GetTypes())
            {
                Console.WriteLine("\t[*] Type name: {0}", _type.FullName);
                if (_type.FullName == "Packer.packer")
                {
                    packerType = _type;
                    break;
                }
            }

            if (packerType == null)
            {
                Console.WriteLine("[!] packer type not found");
                return;
            }

            // Get <Module> type of target module
            TypeDef moduleType = null;

            Console.WriteLine("[*] Search for type <Module>...");
            foreach (var _type in module.GetTypes())
            {
                Console.WriteLine("\t[*] Type name: {0}", _type.FullName);
                if (_type.FullName == "<Module>")
                {
                    moduleType = _type;
                    break;
                }
            }

            if (moduleType == null)
            {
                Console.WriteLine("[!] module type not found");
                return;
            }

            // Add Packer.packer type
            packerModule.Types.Remove(packerType);
            module.Types.Add(packerType);

            // Create module initializer
            MethodDef cctor = new MethodDefUser(".cctor",
                MethodSig.CreateStatic(module.CorLibTypes.Void));
            cctor.Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | 
                MethodAttributes.RTSpecialName | MethodAttributes.Static;
            cctor.ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed;
            moduleType.Methods.Add(cctor);

            MethodDef packerEntry = packerType.FindMethod("entry");

            var cctorILbody = new CilBody();
            cctor.Body = cctorILbody;
            cctorILbody.Instructions.Add(OpCodes.Call.ToInstruction(packerEntry));
            cctorILbody.Instructions.Add(OpCodes.Ret.ToInstruction());

            using (MemoryStream stream = new MemoryStream())
            {
                // Save to memory stream
                module.Write(stream);

                // Reload
                modCtx = ModuleDef.CreateModuleContext();
                module = ModuleDefMD.Load(stream, modCtx);
                PEImage = module.Metadata.PEImage;
                reader = module.Metadata.PEImage.DataReaderFactory.CreateReader();

                // Pack
                pack();

                // Save file
                ModuleWriterOptions opts = new ModuleWriterOptions(module);
                opts.MetadataOptions.Flags = MetadataFlags.PreserveAll;

                module.Write(@argOutputFile, opts);
            }
        }
    }
}
