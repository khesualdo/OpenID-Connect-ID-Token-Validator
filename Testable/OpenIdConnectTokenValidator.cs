using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Used for validating an OpenID Connect JWT.
/// </summary>
public class OpenIdConnectTokenValidator
{

    /// <summary>
    /// Wrapper for ValidateOpenIdConnectJSONWebToken()
    /// </summary>
    /// <param name="token">OpenID Connect JWT</param>
    /// <param name="issuer">identifies the principal that issued the JWT</param>
    /// <param name="audience">identifies the recipients that the JWT is intended for</param>
    /// <param name="nonce">used to mitigate a token replay attack</param>
    /// <param name="wellKnownURL">identifies the .well-known endpoint</param>
    /// <returns>True if the token is valid, false otherwise</returns>
    public async Task<bool> ValidateOpenIdConnectJSONWebTokenWrapperAsync(string token, string issuer, string audience, string nonce, string wellKnownUrl) 
    {
        if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
        if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));
        if (string.IsNullOrEmpty(audience)) throw new ArgumentNullException(nameof(audience));
        if (string.IsNullOrEmpty(nonce)) throw new ArgumentNullException(nameof(nonce));
        if (string.IsNullOrEmpty(wellKnownUrl)) throw new ArgumentNullException(nameof(wellKnownUrl));
        
        ConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            issuer + wellKnownUrl,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever());

        CancellationToken ct = default(CancellationToken);
        OpenIdConnectConfiguration discoveryDocument = await configurationManager.GetConfigurationAsync(ct);
        CustomOpenIdConnectConfiguration _discoveryDocument = new CustomOpenIdConnectConfiguration(discoveryDocument);

        return this.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument, true);
    }

    /// <summary>
    /// Validates an OpenID Connect JWT.
    /// </summary>
    /// <param name="token">OpenID Connect JWT</param>
    /// <param name="issuer">identifies the principal that issued the JWT</param>
    /// <param name="audience">identifies the recipients that the JWT is intended for</param>
    /// <param name="nonce">used to mitigate a token replay attack</param>
    /// <param name="discoveryDocument">stores the signing keys</param>
    /// <param name="validateLifetime">indicates if token experiation date must be checked</param>
    /// <returns>True if the token is valid, false otherwise</returns>
    public bool ValidateOpenIdConnectJSONWebToken(string token, string issuer, string audience, string nonce,
        IOpenIdConnectConfiguration discoveryDocument, bool validateLifetime)
    {
        // Check if any of the parameters are empty
        if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
        if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));
        if (string.IsNullOrEmpty(audience)) throw new ArgumentNullException(nameof(audience));
        if (string.IsNullOrEmpty(nonce)) throw new ArgumentNullException(nameof(nonce));
        if (discoveryDocument == null) throw new ArgumentNullException(nameof(discoveryDocument));
        if (validateLifetime == null) throw new ArgumentNullException(nameof(validateLifetime));

        ICollection<SecurityKey> signingKeys = discoveryDocument.SigningKeys;

        TokenValidationParameters validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers = new string[] { issuer },
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            ValidateLifetime = validateLifetime,
            // Allow for some drift in server time
            // (a lower value is better, five minutes or less is recommended)
            ClockSkew = TimeSpan.FromMinutes(5),
            ValidateAudience = true,
            ValidAudiences = new string[] { audience }
        };

        try
        {
            // Validate key(s), lifetime, issuer(s), audience(s)
            ClaimsPrincipal principal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out var rawValidatedToken);

            bool nonceMatches = false;

            try
            {
                // Validate nonce
                nonceMatches = ((JwtSecurityToken)rawValidatedToken).Payload.TryGetValue("nonce", out var rawNonce)
                    && rawNonce.ToString() == nonce;
            }
            catch (Exception)
            {
                Console.WriteLine("Error thrown trying to match the nonce");
                return false;
            }

            if (!nonceMatches)
            {
                Console.WriteLine("Invalid nonce");
                return false;
            }

            return true;
        }
        catch (SecurityTokenExpiredException)
        {
            Console.WriteLine("Invalid token - token is expired");
            return false;
        }
        catch (SecurityTokenInvalidIssuerException)
        {
            Console.WriteLine("Invalid token - the issuer(s) are invalid");
            return false;
        }
        catch (SecurityTokenInvalidAudienceException)
        {
            Console.WriteLine("Invalid token - the audiencs(s) are invalid");
            return false;
        }
        catch (SecurityTokenValidationException)
        {
            Console.WriteLine("Invalid token");
            return false;
        }
        catch (ArgumentException)
        {
            Console.WriteLine("Invalid arguments to ValidateToken()");
            return false;
        }
        catch (Exception)
        {
            Console.WriteLine("Error thrown by ValidateToken()");
            return false;
        }
    }
}
