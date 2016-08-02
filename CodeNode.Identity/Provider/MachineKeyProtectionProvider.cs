using Microsoft.Owin.Security.DataProtection;

namespace CodeNode.Identity.Provider
{
    internal class MachineKeyProtectionProvider : IDataProtectionProvider
    {
        public IDataProtector Create(params string[] purposes)
        {
            return new MachineKeyDataProtector(purposes);
        }
    }
}