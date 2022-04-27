using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// dnlib
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Packer
{
    class Program
    {
        static void Main(string[] args)
        {
            // Get module
            ModuleContext modCtx = ModuleDef.CreateModuleContext();
            ModuleDefMD module = ModuleDefMD.Load(@"./JITHook.exe", modCtx);

            // Get assembly
            AssemblyDef asm = module.Assembly;
            Console.WriteLine("Assembly: {0}", asm);

            foreach (var type in module.GetTypes())
            {
                Console.WriteLine("Type: {0}", type.FullName);
                Console.WriteLine("  Methods: {0}", type.Methods.Count);

                if (type.FullName == "JIThook.Program") { 
                    foreach (var method in type.Methods)
                    {
                        Console.WriteLine("    Method: {0}", method.FullName);
                        // TODO: Get method IL and patch it
                    }
                }
            }
            
            module.Write(@"./JITHook_packed.exe");
        }
    }
}
