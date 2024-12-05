using SharePointPnP.IdentityModel.Extensions.S2S.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace OfficeDevPnP.Core.Utilities
{
    public class SymmetricKeyIssuerNameRegistryExtended : SymmetricKeyIssuerNameRegistry
    {
        private readonly Dictionary<string, string> _issuerList = new Dictionary<string, string>();
        public void AddTrustedIssuer(X509Certificate2 cert, string issuerName)
        {
            _issuerList.Add(cert.Thumbprint, issuerName);
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            var value = base.GetIssuerName(securityToken);

            if (value == null
                && securityToken != null
                && securityToken is X509SecurityToken x509SecurityToken)
            {
                _issuerList.TryGetValue(x509SecurityToken.Certificate.Thumbprint, out value);
            }

            return value;
        }
    }
}
