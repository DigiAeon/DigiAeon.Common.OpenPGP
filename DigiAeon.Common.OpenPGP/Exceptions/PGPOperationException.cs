namespace DigiAeon.Common.OpenPGP.Exceptions
{
    public class PGPOperationException : Exception
    {
        public string OperationName { get; }

        public PGPOperationException() : base()
        {
        }

        public PGPOperationException(string message) : base(message)
        {
        }

        public PGPOperationException(string operationName, Exception innerException) : base($"Operation ({operationName}) failed. For more details see inner exception.", innerException)
        {
            OperationName = operationName;
        }
    }
}
