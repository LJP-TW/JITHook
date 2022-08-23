using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
            Console.WriteLine("packer entry");
        }
    }
    class Program
    {
        static ModuleContext modCtx;
        static ModuleDefMD module;
        static IPEImage PEImage;
        static DataReader reader;
        static OpCode nonsense;

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
            module.Resources.Add(new EmbeddedResource(method.MDToken.ToString(), originILbytes,
                ManifestResourceAttributes.Private));

            // Patch IL
            var newILbody = new CilBody();
            newILbody.Instructions.Add(nonsense.ToInstruction());

            method.Body = newILbody;
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
                    Console.WriteLine("Packing Method: {0} ({1})", method.FullName, method.MDToken);
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

            // Create new opcode
            nonsense = new OpCode(
                "nonsense", 0xf1, 0x87, OperandType.InlineNone, FlowControl.Next, StackBehaviour.Push0, StackBehaviour.Pop0);

            modCtx.RegisterExperimentalOpCode(nonsense);

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
