using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JIThook
{
    public static class HelperDef
    {
        private const int GET_METHOD_DEF_FROM_METHOD_SLOT_INDEX = 105;
        public static Clrjit.CompileMethodDel64 OriginalCompileMethod { [MethodImpl(MethodImplOptions.NoInlining)] get; private set; }
        public static Clrjit.CompileMethodDel64 NewCompileMethod { [MethodImpl(MethodImplOptions.NoInlining)] get; set; }

        private static IntPtr pCompileMethod;

        private static Dictionary<IntPtr, Module> interceptorModules = new Dictionary<IntPtr, Module>();

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static unsafe int MyCompileMethod(IntPtr thisPtr, [In] IntPtr corJitInfo,
               [In] Cor.CorMethodInfo64* methodInfo, Cor.CorJitFlag flags,
               [Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode)
        {
            Console.WriteLine("[JIT hook] --------------------");

            var module = FindModule(methodInfo->scope);

            if (module == null)
            {
                Console.WriteLine("[JIT hook end] ----------------");
                return OriginalCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
            }

            int token = (0x06000000 + *(ushort*)methodInfo->ftn);

            byte[] il = new byte[methodInfo->ilCodeSize];
            Marshal.Copy((IntPtr)methodInfo->ilCode, il, 0, (int)methodInfo->ilCodeSize);

            Console.WriteLine("Method Name: " + module.ResolveMethod(token).Name);
            Console.WriteLine("    IL legnth: " + methodInfo->ilCodeSize);
            Console.WriteLine("    IL b64: " + Convert.ToBase64String(il));

            // Just ret
            // string newil_b64 = "Kg==";

            // Print "Hello!" (not work)
            // string newil_b64 = "ctcBAHAoGAAACio=";

            // Return a1 + a2
            string newil_b64 = "AgNYKg==";

            byte[] newil = Convert.FromBase64String(newil_b64);

            var ilCodeHandle = Marshal.AllocHGlobal(newil.Length);
            Marshal.Copy(newil, 0, ilCodeHandle, newil.Length);

            // Patch
            methodInfo->ilCode = (byte*)ilCodeHandle.ToPointer();
            methodInfo->ilCodeSize = (uint)newil.Length;

            Console.WriteLine("    Patch!");

            Console.WriteLine("[JIT hook end] ----------------");
            return OriginalCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
        }

        private static Module FindModule(IntPtr modulePtr)
        {
            if (interceptorModules.ContainsKey(modulePtr))
                return interceptorModules[modulePtr];
            return null;
        }

        public static void RegisterModule(this AppDomain domain, Module module)
        {
            // TODO: Docs?
            var mPtr = module.ModuleHandle.GetType().GetField("m_ptr", BindingFlags.NonPublic | BindingFlags.Instance);
            var mPtrValue = mPtr.GetValue(module.ModuleHandle);
            var mpData = mPtrValue.GetType().GetField("m_pData", BindingFlags.NonPublic | BindingFlags.Instance);
            var mpDataValue = (IntPtr)mpData.GetValue(mPtrValue);

            if (!interceptorModules.ContainsKey(mpDataValue))
                interceptorModules[mpDataValue] = module;
        }

        public static unsafe void Hook(this AppDomain domain)
        {
            uint old;

            NewCompileMethod = MyCompileMethod;

            Console.WriteLine("Init Hook");

            pCompileMethod = Marshal.ReadIntPtr(Clrjit.VTableAddr);

            OriginalCompileMethod = (Clrjit.CompileMethodDel64) Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(pCompileMethod), 
                                                                                                        typeof(Clrjit.CompileMethodDel64));

            RuntimeHelpers.PrepareDelegate(OriginalCompileMethod);
            RuntimeHelpers.PrepareDelegate(NewCompileMethod);
            RuntimeHelpers.PrepareMethod(typeof(HelperDef).GetMethod("FindModule", BindingFlags.Static | BindingFlags.NonPublic).MethodHandle);

            if (!NativeAPI.VirtualProtect(pCompileMethod, (uint)IntPtr.Size, NativeAPI.Protection.PAGE_EXECUTE_READWRITE, out old))
                throw new Exception("Cannot change memory protection flags.");

            Marshal.WriteIntPtr(pCompileMethod, Marshal.GetFunctionPointerForDelegate(NewCompileMethod));

            NativeAPI.VirtualProtect(pCompileMethod, (uint)IntPtr.Size, (NativeAPI.Protection)old, out old);
        }
    }
    class Program
    {
        static int Hello(int a1, int a2)
        {
            Console.WriteLine("Hello!");

            return 0;
        }
        static void Main(string[] args)
        {
            AppDomain.CurrentDomain.RegisterModule(typeof(Program).Module);
            AppDomain.CurrentDomain.Hook();

            int i = Hello(1, 5);
            Console.WriteLine(i);
        }
    }
}
