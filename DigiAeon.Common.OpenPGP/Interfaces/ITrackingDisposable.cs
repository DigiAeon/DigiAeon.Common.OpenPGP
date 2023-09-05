using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigiAeon.Common.OpenPGP.Interfaces
{
    public interface ITrackingDisposable : IDisposable
    {
        //The implementation of the actual disposings
        Task FinishDisposeAsync();
    }
}
