using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FeistelCipher
{
    internal static class Program
    {
        private static void Main()
        {
            while (true)
            {
                Run();
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                Console.Clear();
            }
        }

        static void Run()
        {
            const byte rounds = 16;
            var key64 = RandomKey();
            Console.WriteLine($"Key(64bit): {key64:X}");
            var iv = RandomKey();
            Console.WriteLine($"IV: {iv:X}");
            Console.Write("Enter message: ");
            var message = Padding(Console.ReadLine());
            var mesgC = ToBlocks(message);
            Console.WriteLine("Encrypting...");
            for (var i = 0; i < mesgC.Length; i++)
            {
                mesgC[i] = Encrypt(i == 0 ? mesgC[i] ^ iv : mesgC[i] ^ mesgC[i - 1], key64, rounds);
                Console.WriteLine("{0:X}", mesgC[i]);
            }
            message = MessageToHex(mesgC);
            Console.WriteLine($"ENCRYPTED MESSAGE: {message}");

            var mesgP = new ulong[mesgC.Length];
            mesgC.CopyTo(mesgP, 0);
            Console.WriteLine("Decrypting...");
            for (var i = 0; i < mesgP.Length; i++)
            {
                mesgP[i] = i == 0 ? iv ^ Decrypt(mesgP[i], key64, rounds) : mesgC[i - 1] ^ Decrypt(mesgP[i], key64, rounds);
                Console.WriteLine($"{mesgP[i]:X}");
            }
            message = MessageToString(mesgP);
            Console.WriteLine($"DECRYPTED MESSAGE: {message}");
        }

        private static string Padding(string input)
        {
            var n = input.Length*16%64;
            if (n == 0)
            {
                return input;
            }
            var sb = new StringBuilder(input);
            var k = (64 - n)/16;
            sb.Append(new char(), k);
            return sb.ToString();
        }

        private static ulong[] ToBlocks(string input)
        {
            var result = new ulong[input.Length/4];
            var temp = new uint[2];
            for (int i = 0, j = 0; i < input.Length; i += 4, j++)
            {
                temp[0] = (uint) input[i] << 2 * 8 | input[i + 1];
                temp[1] = (uint) input[i + 2] << 2 * 8 | input[i + 3];

                result[j] = (ulong) temp[0] << 4 * 8 | temp[1];
            }
            return result;
        }

        private static ulong RandomKey()
        {
            var rand = new Random((int) (DateTime.Now.Ticks & 0xFFFFFFFF));
            var buffer = new byte[sizeof(ulong)];
            rand.NextBytes(buffer);
            ulong res = 0;
            for (var i = 0; i < sizeof(ulong); i++)
            {
                ulong temp = buffer[i];
                temp = temp << 8 * (7 - i);
                res = res | temp;
            }
            return res;
        }

        private static ulong Encrypt(ulong msg, ulong key64, uint rounds)
        {
            var right = (uint) (msg << 4 * 8 >> 4 * 8); // 0-31 bytes
            var left = (uint) (msg >> 4 * 8); // 32-63 bytes
            uint[] key32I = new uint[rounds];
            for (var i = 0; i < rounds; i++)
            {
                key32I[i] = KeyGenerator(i, key64);
            }
            for (var i = 0; i < rounds; i++)
            {
                var function = F(left, key32I[i]);
                var tmp = left;
                left = right ^ function;
                right = tmp;
            }
            var tmp1 = (ulong) left << 4 * 8;
            var tmp2 = (ulong) right;
            return tmp1 | tmp2;
        }

        private static string MessageToHex(IEnumerable<ulong> msg)
        {
            var result = string.Empty;
            var tmp = new ushort[4];
            foreach (var item in msg)
            {
                tmp[0] = (ushort) (item >> 6 * 8); // 6-7 bytes
                tmp[1] = (ushort) (item >> 4 * 8 << 6 * 8 >> 6 * 8); // 4-5 bytes
                tmp[2] = (ushort) (item << 4 * 8 >> 6 * 8); // 2-3 bytes
                tmp[3] = (ushort) (item << 6 * 8 >> 6 * 8); // 0-1 bytes
                result = tmp.Aggregate(result, (current, t) => current + t.ToString("X"));
            }
            byte[] res = Encoding.Default.GetBytes(result);
            var hex = BitConverter.ToString(res);
            hex = hex.Replace("-", "");
            return result;
        }

        private static string MessageToString(IEnumerable<ulong> msg)
        {
            var result = string.Empty;
            var tmp = new ushort[4];
            foreach (var item in msg)
            {
                tmp[0] = (ushort) (item >> 6*8); // 6-7 bytes
                tmp[1] = (ushort) (item >> 4*8 << 6*8 >> 6*8); // 4-5 bytes
                tmp[2] = (ushort) (item << 4*8 >> 6*8); // 2-3 bytes
                tmp[3] = (ushort) (item << 6*8 >> 6*8); // 0-1 bytes
                result = tmp.Aggregate(result, (current, t) => current + Convert.ToChar(t));
            }
            return result;
        }

        #region cycleMove

        private static ulong CycleMoveRight(ulong number, byte offset) => number >> offset | number << 64 - offset;

        private static uint CycleMoveLeft(uint number, byte offset) => number << offset | number >> 32 - offset;

        #endregion

        private static uint F(uint left, uint key)
            => (GetEven(left) ^ key << 0 >> 16) | GetOdd(~CycleMoveLeft(left, 11) + key);

        private static uint KeyGenerator(int round, ulong key64)
            => (uint) (CycleMoveRight(key64, (byte) (round * 7)) << 0 >> 32);

        private static ulong Decrypt(ulong msg, ulong key64, int iteration)
        {
            var right = (uint) (msg << 4 * 8 >> 4 * 8);
            var left = (uint) (msg >> 4 * 8);
            uint[] key32I = new uint[iteration];
            for (var i = iteration - 1; i >= 0; i--)
            {
                key32I[i] = KeyGenerator(i, key64);
            }
            for (var i = iteration - 1; i >= 0; i--)
            {
                var function = F(right, key32I[i]);
                var tmp = right;
                right = left ^ function;
                left = tmp;
            }
            var tmp1 = (ulong) left << 4 * 8;
            var tmp2 = (ulong) right;
            return tmp1 | tmp2;
        }

        private static uint GetOdd(uint x)
        {
            uint result = 0;
            for (int i = 0, j = 0; i < 16; i += 2, j++)
            {
                var y = (x >> i) & 1;
                result = result | (y << j);
            }
            return result;
        }

        private static uint GetEven(uint x)
        {
            uint result = 0;
            for (int i = 1, j = 0; i < 16; i += 2, j++)
            {
                var y = (x >> i) & 1;
                result = result | (y << j);
            }
            return result;
        }
    }
}