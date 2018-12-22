using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

[TestClass]
public class Test_OpenIdConnectTokenValidator
{
    private Mock<IOpenIdConnectConfiguration> _discoveryDocument;

    private string token;
    private string issuer;
    private string audience;
    private string nonce;

    private string e; // Found in a JWK
    private string n; // Found in a JWK
    private string kid; // Found in a JWK
    
    // JWKs may be found in a JSON object returned by the .well-known/openid-configuration endpoint
    // Check the ID Token to find out which JWK to use 
    // Good read on JWKs - https://auth0.com/docs/jwks
    
    // I didn't have to deal with x5t, x5c, etc..., but as far as I understand Identity Providers are moving away
    // from using these claims ... so any modern Identity Provider should provide the kid claim

    private static byte[] Base64UrlDecoder(string base64Url)
    {
        string padded = base64Url.Length % 4 == 0
            ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
        string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
        return Convert.FromBase64String(base64);
    }

    [TestInitialize]
    public void Initilize()
    {
        _discoveryDocument = new Mock<IOpenIdConnectConfiguration>(MockBehavior.Strict);

        token = ""; // Insert a sample ID Token
        
        // From payload of the ID Token
        issuer = ""; // Insert a value of the iss claim from the sample ID Token above
        audience = ""; // Insert a value of the aud claim from the sample ID Token above
        nonce = ""; // Insert a value of the nonce claim from the sample ID Token above

        // From the header of the ID Token
        kid = ""; // Insert a value of the kid claim from the sample ID Token above
        
        // From JWK associated with kid above
        e = "";
        n = "";
    }

    [TestMethod]
    public async Task InvalidTokenThrowsArgumentException()
    {
        token = "7.7.7";

        // Need the keys array to get passed validationParameters = new TokenValidationParameters() { ... }
        // and execute ValidateToken(token, validationParameters, out rawValidatedToken)
        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is ArgumentException);
        }
    }

    [TestMethod]
    public async Task InvalidAudienceThrowsSecurityTokenInvalidAudienceException()
    {
        audience = "777";

        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is SecurityTokenInvalidAudienceException);
        }
    }

    [TestMethod]
    public async Task InvalidIssuerThrowsSecurityTokenInvalidIssuerException()
    {
        issuer = "777";

        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is SecurityTokenInvalidIssuerException);
        }
    }

    [TestMethod]
    public async Task ExpiredTokenThrowsSecurityTokenExpiredException()
    {
        // This test relies on the fact that the token is a valid, expired token
        
        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, true);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is SecurityTokenExpiredException);
        }
    }

    [TestMethod]
    public async Task InvalidNonceThrowsSecurityTokenValidationException()
    {
        // The real nonce is found in the token, just make this any other value
        nonce = "777";

        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        Assert.AreEqual(false, result);
    }
    
    [TestMethod]
    public async Task NullValidateLifetimeThrowsArgumentNullException()
    {
        var keys = new List<SecurityKey>();
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, null);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is ArgumentNullException);
        }
    }
    
    [TestMethod]
    public async Task NullDiscoveryDocumentThrowsArgumentNullException()
    {
        var keys = new List<SecurityKey>();
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, null, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is ArgumentNullException);
        }
    }

    [TestMethod]
    public async Task EmptyAudienceThrowsArgumentNullException()
    {
        issuer = "";

        var keys = new List<SecurityKey>();
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is ArgumentNullException);
        }
    }

    [TestMethod]
    public async Task EmptyNonceThrowsArgumentNullException()
    {
        nonce = "";

        var keys = new List<SecurityKey>();
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is ArgumentNullException);
        }
    }


    [TestMethod]
    public async Task EmptyIssuerThrowsArgumentNullException()
    {
        string audience = "";

        var keys = new List<SecurityKey>();
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is ArgumentNullException);
        }
    }

    [TestMethod]
    public async Task EmptyTokenThrowsArgumentNullException()
    {
        token = "";

        var keys = new List<SecurityKey>();
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();

        try
        {
            bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);
        }
        catch (Exception exception)
        {
            Assert.IsTrue(exception is ArgumentNullException);
        }
    }

    [TestMethod]
    public async Task ValidKeyReturnsTrue()
    {
        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();
        bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);

        Assert.AreEqual(true, result);
    }

    [TestMethod]
    public async Task InvalidExponentReturnsFalse()
    {
        n = "777";

        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();
        bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);

        Assert.AreEqual(false, result);
    }

    [TestMethod]
    public async Task InvalidModulusReturnsFalse()
    {
        e = "777";

        var keys = new List<SecurityKey>();
        byte[] exponent = Base64UrlDecoder(e);
        byte[] modulus = Base64UrlDecoder(n);
        var rsaParameters = new RSAParameters { Exponent = Base64UrlDecoder(e), Modulus = Base64UrlDecoder(n) };
        var rsaSecurityKey = new RsaSecurityKey(rsaParameters) { KeyId = kid };
        keys.Add(rsaSecurityKey);
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();
        bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);

        Assert.AreEqual(false, result);
    }

    [TestMethod]
    public async Task NoKeysReturnsFalse()
    {
        var keys = new List<SecurityKey>();
        _discoveryDocument.SetupGet(d => d.SigningKeys).Returns(keys);

        var validator = new OpenIdConnectTokenValidator();
        bool result = validator.ValidateOpenIdConnectJSONWebToken(token, issuer, audience, nonce, _discoveryDocument.Object, false);

        Assert.AreEqual(false, result);
    }
}
