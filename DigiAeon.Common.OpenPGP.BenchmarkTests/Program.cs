using BenchmarkDotNet.Running;
using DigiAeon.Common.OpenPGP.BenchmarkTests.Tests;

namespace DigiAeon.Common.OpenPGP.BenchmarkTests
{
    internal class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<DecryptLargeFileTests>();
        }
    }
}