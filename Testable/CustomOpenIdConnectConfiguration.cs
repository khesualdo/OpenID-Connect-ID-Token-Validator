using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

/// <summary>
/// Creates a wrapper for the SigningKeys getter.
/// Used for mocking the SigningKeys getter of the OpenIdConnectConfiguration class.
/// </summary>
public class CustomOpenIdConnectConfiguration : IOpenIdConnectConfiguration
{
    private OpenIdConnectConfiguration _discoveryDocument;

    public CustomOpenIdConnectConfiguration(OpenIdConnectConfiguration discoveryDocument)
    {
        _discoveryDocument = discoveryDocument;
    }

    /// <summary>
    /// Defines a getter for a collection of SecurityKey(s)
    /// </summary>
    public ICollection<SecurityKey> SigningKeys
    {
        get
        {
            return _discoveryDocument.SigningKeys;
        }
    }
}