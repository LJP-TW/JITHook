using System;
using System.Runtime.InteropServices;

namespace JIThook
{
    public sealed class Clrjit
    {
        [DllImport("Clrjit.dll", CallingConvention = CallingConvention.StdCall, PreserveSig = true)]
        private static extern IntPtr getJit();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public unsafe delegate int CompileMethodDel64(
            IntPtr thisPtr, [In] IntPtr corJitInfo, [In] Cor.CorMethodInfo64* methodInfo, Cor.CorJitFlag flags,
            [Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
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
    }
}
