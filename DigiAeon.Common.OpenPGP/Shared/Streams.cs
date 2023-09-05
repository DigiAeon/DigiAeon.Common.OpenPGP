namespace DigiAeon.Common.OpenPGP.Shared
{
    internal sealed class Streams
    {
        private const int BufferSize = 512;

        public static void PipeAll(Stream inStr, Stream outStr)
        {
            byte[] bs = new byte[BufferSize];
            int numRead;
            while ((numRead = inStr.Read(bs, 0, bs.Length)) > 0)
            {
                outStr.Write(bs, 0, numRead);
            }
        }

        public static async Task PipeAllAsync(Stream inStr, Stream outStr)
        {
            byte[] bs = new byte[BufferSize];
            int numRead;
            while ((numRead = await inStr.ReadAsync(bs, 0, bs.Length)) > 0)
            {
                await outStr.WriteAsync(bs, 0, numRead);
            }
        }
    }
}
