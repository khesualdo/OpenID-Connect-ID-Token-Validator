using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

/// <summary>
/// OpenIdConnectConfiguration interface.
/// Used for mocking the SigningKeys getter of the OpenIdConnectConfiguration class.
/// </summary>
public interface IOpenIdConnectConfiguration
{
    /// <summary>
    /// A signature of a getter for a collection of SecurityKey(s)
    /// </summary>
    ICollection<SecurityKey> SigningKeys { get; }
}
