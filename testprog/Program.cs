using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace testprog
{
    class Program
    {
        static int ga, gb;
        /*
         * Tiny format:
         * - No local variables are allowed 
         * - No exceptions 
         * - No extra data sections
         * - The operand stack shall be no bigger than 8 entries
         */
        static void tinyFunc()
        {
            ga = ga + gb;
        }

        // The method is too large to encode the size (i.e., at least 64 bytes)
        static int fatFunc1(int a, int b)
        {
            return a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b;
        }

        // There are local variables 
        static int fatFunc2(int a, int b)
        {
            int ret;

            ret = a + b;

            return ret;
        }

        // Same as fatFunc2 but with different variable names
        static int fatFunc3(int c, int d)
        {
            int ret;

            ret = c + d;

            return ret;
        }

        // There are exceptions
        static int fatFunc4(int a)
        {
            if (a == 0)
            {
                throw new Exception("a = 0");
            }
            return a + 1;
        }

        // There are exceptions
        static int fatFunc5(int a)
        {
            try
            {
                return fatFunc4(a) + 1;
            }
            catch
            {
                throw;
            }
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Test program, press any key to continue");
            Console.ReadLine();

            int ret;

            ga = 1;
            gb = 2;

            Console.WriteLine("Test tiny function");
            tinyFunc();
            ret = ga;
            // 3
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fat function1 (The method is too large to encode the size)");
            ret = fatFunc1(3, 4);
            // 140
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fat function2 (There are local variables)");
            ret = fatFunc2(5, 6);
            // 11
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fat function3 (There are local variables with different name)");
            ret = fatFunc3(7, 8);
            // 15
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fat function2 again");
            ret = fatFunc2(5, 6);
            // 11
            Console.WriteLine("ret: " + ret.ToString());

            try
            {
                Console.WriteLine("Test fat function4 (There are exceptions)");
                ret = fatFunc4(0);
                Console.WriteLine("ret: " + ret.ToString());
            } catch (Exception ex)
            {
                Console.WriteLine("Function4 exception: " + ex.Message);
            }

            try
            {
                Console.WriteLine("Test fat function5 (There are exceptions)");
                ret = fatFunc5(0);
                Console.WriteLine("ret: " + ret.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("Function5 exception: " + ex.Message);
            }
        }
    }
}
