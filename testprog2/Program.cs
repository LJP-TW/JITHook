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
        static void tinyFunc1()
        {
            ga = ga + gb;
        }

        // The "No exceptions" condition actually means "No exception handlers"
        static void tinyFunc2()
        {
            throw new Exception("tinyFunc2");
        }
        static void tinyFunc3()
        {
            ga = ga * gb;
        }
        static void tinyFunc4()
        {
            ga = ga - gb;
        }

        // The method is too large to encode the size (i.e., at least 64 bytes)
        static int fatFunc1(int a, int b)
        {
            return a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b;
        }

        // The method is too large to encode the size (i.e., at least 64 bytes)
        static int fatFunc1_1(int a, int b)
        {
            return b + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b;
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

        // There are extra data sections 
        // Because there are exception handlers, so a extra CorILMethod_Sect_EHTable is needed
        static int fatFunc4(int a)
        {
            try
            {
                tinyFunc2();
                return a;
            }
            catch
            {
                throw;
            }
        }

        // There are extra data sections 
        // Because there are exception handlers, so a extra CorILMethod_Sect_EHTable is needed
        static int fatFunc5(int a)
        {
            try
            {
                return fatFunc4(a) + 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine("In fatFunc5: " + ex.Message);
                throw;
            }
        }

        // There are extra data sections 
        // Because there are exception handlers, so a extra CorILMethod_Sect_EHTable is needed
        static void fatFunc6()
        {
            try
            {
                ga = ga / gb;
            }
            catch
            {
                ga = ga + gb;
            }
        }

        static int fatFunc7(int a, int b, int c)
        {
            try
            {
                try
                {
                    a = b / c;
                }
                catch
                {
                    Console.WriteLine("In fatFunc7: c == 0");
                    return a;
                }

                a = c / b;
                return a;
            }
            catch
            {
                Console.WriteLine("In fatFunc7: b == 0");
            }

            return a;
        }

        static int fatFunc8(int a)
        {
            int ret;

            if (a == 0)
            {
                tinyFunc3();
                ret = 3;
            }
            else
            {
                tinyFunc4();
                ret = 4;
            }

            return ret;
        }

        static void Main()
        {
            Console.WriteLine("Test program");

            int ret;

            ga = 1;
            gb = 2;

            Console.WriteLine("Test tinyFunc1");
            tinyFunc1();
            ret = ga;
            // 3
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fatFunc1 (The method is too large to encode the size)");
            ret = fatFunc1(3, 4);
            // 140
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fatFunc2 (There are local variables)");
            ret = fatFunc2(5, 6);
            // 11
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fatFunc3 (There are local variables with different name)");
            ret = fatFunc3(7, 8);
            // 15
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fatFunc2 again");
            ret = fatFunc2(5, 6);
            // 11
            Console.WriteLine("ret: " + ret.ToString());

            try
            {
                Console.WriteLine("Test tinyFunc2 (Throw a exception)");
                tinyFunc2();
            } catch (Exception ex)
            {
                Console.WriteLine("tinyFunc2 exception: " + ex.Message);
            }

            try
            {
                Console.WriteLine("Test fatFunc4 (There are exception handlers)");
                ret = fatFunc4(0);
                Console.WriteLine("ret: " + ret.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("fatFunc4 exception: " + ex.Message);
            }

            try
            {
                Console.WriteLine("Test fatFunc5 (There are exception handlers)");
                ret = fatFunc5(0);
                Console.WriteLine("ret: " + ret.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("fatFunc5 exception: " + ex.Message);
            }

            try
            {
                Console.WriteLine("Test fatFunc6");
                fatFunc6();
            }
            catch (Exception ex)
            {
                Console.WriteLine("fatFunc6 exception: " + ex.Message);
            }

            Console.WriteLine("Test fatFunc7");
            ret = fatFunc7(4, 0, 2);
            // 0
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fatFunc8");
            ret = fatFunc8(0);
            // 3
            Console.WriteLine("ret: " + ret.ToString());

            Console.WriteLine("Test fatFunc1_1");
            ret = fatFunc1_1(1, 2);
            // 61
            Console.WriteLine("ret: " + ret.ToString());
        }
    }
}
