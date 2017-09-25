using System;

namespace TokenBinding
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }

    public class TokenBindingHandler
    {
        public SecurityStatus GenerateBinding(string KeyType, string target, TokenBindingType tokenBindingType, byte[] uniqueData, byte[] extensionData, out TokenBinding tokenBinding)
        {
            tokenBinding = null;
            return SecurityStatus.Success;
        }
    }

    public enum SecurityStatus
    {
        Success,
        Failure
    }

    public enum TokenBindingType
    {
        Provided,
        Referred
    }
}
