using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// dnlib
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;
using dnlib.PE;

// Ref:
// - https://github.com/0xd4d/dnlib/blob/master/Examples/
// - https://stackoverflow.com/questions/54441057/inject-a-class-with-a-method-using-dnlib

namespace Packer
{
    class packer
    {
        static void entry()
        {
            Console.WriteLine("ljpacker entry");
        }
    }
    class Program
    {
        static ModuleContext modCtx;
        static ModuleDefMD module;
        static IPEImage PEImage;
        static DataReader reader;

        static void packMethod(TypeDef type, MethodDef method)
        {
            int codesize = 0;

            foreach (Instruction ins in method.Body.Instructions)
            {
                uint offset = ((uint)PEImage.ToFileOffset(method.RVA)) + method.Body.HeaderSize + ins.Offset;

                codesize += ins.GetSize();

                reader.Position = offset;
                                
                Console.WriteLine("0x{0:x} : {1} | {2}", offset, ins, 
                    BitConverter.ToString(reader.ReadBytes(ins.GetSize())));
            }

            Console.WriteLine("RVA {0:x}: codesize: {1:x}", method.RVA, codesize);

            // Add resource
            byte[] resourceData = Encoding.UTF8.GetBytes("Hello, world!");
            module.Resources.Add(new EmbeddedResource("HelloWorld", resourceData,
                ManifestResourceAttributes.Private));
        }
        static void pack()
        {
            // List types
            foreach (TypeDef type in module.GetTypes())
            {
                Console.WriteLine("Packing Type: {0}", type.FullName);
                // List methods
                foreach (MethodDef method in type.Methods)
                {
                    Console.WriteLine("Packing Method: {0}", method.FullName);
                    packMethod(type, method);
                }
            }
        }
        static void Main(string[] args)
        {
            // Get module
            modCtx = ModuleDef.CreateModuleContext();
            module = ModuleDefMD.Load(@"./testprog.exe", modCtx);
            PEImage = module.Metadata.PEImage;
            reader = module.Metadata.PEImage.DataReaderFactory.CreateReader();

            // Get assembly
            AssemblyDef asm = module.Assembly;
            Console.WriteLine("Assembly: {0}", asm);

            pack();

            // Get entrypoint
            // MethodDef entry = module.EntryPoint;
            // TypeDef entryType = entry.DeclaringType;
            // Console.WriteLine("Entry Point Method: {0}", entry.FullName);
            // Console.WriteLine("Type of Entry Point Method: {0}", entryType.FullName);

            // Create a method ref to 'System.Void System.Console::WriteLine(System.String)'
            // TypeRef consoleRef = new TypeRefUser(module, "System", "Console", module.CorLibTypes.AssemblyRef);
            // MemberRef consoleWrite1 = new MemberRefUser(module, "WriteLine",
            //             MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String),
            //             consoleRef);

            // Create test function
            // MethodDef testfunc = new MethodDefUser("packer_func",
            //     MethodSig.CreateStatic(module.CorLibTypes.Void));
            // testfunc.Attributes = MethodAttributes.Private | MethodAttributes.Static |
            //     MethodAttributes.HideBySig | MethodAttributes.ReuseSlot;
            // testfunc.ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed;
            // entryType.Methods.Add(testfunc);
            // 
            // var ilbody = new CilBody();
            // testfunc.Body = ilbody;
            // ilbody.Instructions.Add(OpCodes.Ldstr.ToInstruction("Hello World!"));
            // ilbody.Instructions.Add(OpCodes.Call.ToInstruction(consoleWrite1));
            // ilbody.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            // ilbody.Instructions.Add(OpCodes.Ret.ToInstruction());

            // Get packer module
            ModuleContext packerModCtx = ModuleDef.CreateModuleContext();
            ModuleDefMD packerModule = ModuleDefMD.Load(@"./packer.exe", packerModCtx);

            // Get assembly
            AssemblyDef packerAsm = module.Assembly;
            Console.WriteLine("Packer Assembly: {0}", packerAsm);

            // Get type
            TypeDef packerType = null;
            
            foreach (var _type in packerModule.GetTypes())
            {
                Console.WriteLine("Type name: {0}", _type.FullName);
                if (_type.FullName == "Packer.packer")
                {
                    packerType = _type;
                    break;
                }
            }

            if (packerType == null)
            {
                return;
            }

            // Add Packer.packer type
            packerModule.Types.Remove(packerType);
            module.Types.Add(packerType);

            // Set entrypoint
            MethodDef packerEntry = packerType.FindMethod("entry");
            module.EntryPoint = packerEntry;

            module.Write(@"./testprog_packed_ljp.exe");
        }
    }
}
