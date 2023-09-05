namespace DigiAeon.Common.OpenPGP.Shared
{
    public static class ValidationHelper
    {
        public static void ValidateForRequiredArgument(string value, string argumentName)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException($"{argumentName} is required.", argumentName);
            }
        }

        public static void ValidateForRequiredArgument(byte[]? value, string argumentName)
        {
            if (value == null || value.Length <= 0)
            {
                throw new ArgumentException($"{argumentName} is required.", argumentName);
            }
        }

        public static void ValidateIfFileExists(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found.", filePath);
            }
        }
    }
}
