namespace DigiAeon.Common.OpenPGP.Exceptions
{
    public class PGPOperationException : Exception
    {
        public string OperationName { get; } = string.Empty;

        public PGPOperationException(string? message) : base(message)
        {
        }

        public PGPOperationException(string operationName, Exception innerException) : base($"Operation ({operationName}) failed. For more details see inner exception.", innerException)
        {
            OperationName = operationName;
        }
    }
}
