using System.Text;

namespace DigiAeon.Common.OpenPGP.UnitTests.Shared
{
    public static class FileHelper
    {
        /// <summary>
        /// Generate unique file name
        /// </summary>
        /// <param name="extension">Extension name with dot(.)</param>
        /// <returns>file name</returns>
        public static string GenerateUniqueFileName(string extension)
        {
            return Guid.NewGuid().ToString().Replace("-", string.Empty) + extension;
        }
    }
}
