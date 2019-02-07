# :crown: :trophy: :moneybag: OpenID-Connect ID-Token Validator

I spent a lot of time searching for a way to validate OpenId-Connect ID Tokens, but I spent even more time searching for a way to make my code testable. I want to share this code with the world, and hopefully someone else finds it useful!

This code provides the basic steps required to locally verify an ID Token signed using asymmetric encryption (eg. RS256). It uses packages from Microsoft for key parsing and token validation. The code is also testable and comes with a suite of unit tests.

P.S. If you want more information about OpenId-Connect, ID Tokens, Authentication vs Authorization, Testable vs Non-Testable Code, Mocking, and this repo in general continue reading after the [How to Run](#how-to-run) section, and of course - 

Please send me your feedback!

# How to Run

> Remember to prefix the .well-known config URL with a `/`

### Packages
```
Install-Package Microsoft.IdentityModel.Protocols.OpenIdConnect -Version 5.3.0
```

### Testable
```C#
string token = "...";
string issuer = "...";
string audience = "...";
string nonce = "...";
string wellKnownURL = "...";

OpenIdConnectTokenValidator oidcTokenValidator = new OpenIdConnectTokenValidator();
bool result = await oidcTokenValidator.ValidateOpenIdConnectJSONWebTokenWrapperAsync(token, issuer, audience, nonce, wellKnownURL);
```

### Non-Testable
```C#
string token = "...";
string issuer = "...";
string audience = "...";
string nonce = "...";
string wellKnownURL = "...";

OpenIdConnectTokenValidator oidcTokenValidator = new OpenIdConnectTokenValidator();
bool result = await oidcTokenValidator.ValidateOpenIdConnectJSONWebTokenAsync(token, issuer, audience, nonce, wellKnownURL);
```

# Authentication vs. Authorization

- Authentication = who you are (eg. username + password)
- Authorization = what you are allowed to do (eg. permissions - read, write, execute)

# Definitions

### What is a `token` and how to get it?

The `token` would be any valid ID Token. Assuming we are using the Authorization Code Flow, to get a valid ID Token:
1. Make a call to the `/auth` endpoint to receive the `authorization code`
2. Make a call to the `/oidc/token` enpoint with the `authorization code` to receive the `token`

OneLogin has a clear explanation of the Authorization Code Flow:
1. https://developers.onelogin.com/openid-connect/api/authorization-code
2. https://developers.onelogin.com/openid-connect/api/authorization-code-grant

An ID Token usually comes in a form of a JSON Web Token (JWT). [Here](https://jwt.io/introduction/) is a good read on JWTs.

Use [this](https://jwt.io/) to parse the ID Token.

### What is an `issuer` and where to find it?

The `issuer` is the issuing authority - whoever gave you the ID Token, usually this will be the Identity Provider (eg. AzureAD, OneLogin), and it is nothing more than the value of the `iss` claim from the ID Token.

### What is an `audience` and where to find it?

The `audience` is the particular audience - the client, usually this will be the same as your `Client ID` issued by the Identity Provider, and it is nothing more than the value of the `aud` claim from the ID Token.

### What is a `nonce` and where to find it?

The `nonce` is a random string that is used by the Identity Provider to protect against replay attacks. When making a call to the `/auth` endpoint you may pass a value for the `nonce` as such - `/auth?nonce=123`. There exists a `nonce` claim in the ID Token whose value matches the value passed in the `/auth` endpoint.

If no `nonce` is passed when making a call to the `/auth` endpoint, the value of the `nonce` claim will be `"undefined"` or `""`.

### What is a `wellKnownURL` and how to get it?

When registering your app with the Identity Provider they will give you the `Client ID`, `Client Secret`, and `.well-known/openid-configuration` endpoint. Usually making a request to the `.well-known/openid-configuration` endpoint returns a JSON object containing information about the Identity Provider (eg. supported scopes and claims, keys used to sign the tokens), the clients may use this information to construct a valid request to the Identity Provider.

### Links
- https://developer.okta.com/authentication-guide/tokens/validating-id-tokens
- https://auth0.com/docs/tokens/id-token

# Testable vs. Non-Testable Code

When writing unit tests, no external activity (eg. HTTP requests) is allowed, each unit test has to be self-contained. This means that all external activity has to be mocked. The [first version](https://github.com/00111000/OpenId-Connect-ID-Token-Validator/tree/master/Non-Testable) of `ValidateOpenIdConnectJSONWebToken()` was non-testable since it was making a request - `await configurationManager.GetConfigurationAsync(ct);` inside of the method.

Therefore, I had to create a [second version](https://github.com/00111000/OpenId-Connect-ID-Token-Validator/tree/master/Testable) of `ValidateOpenIdConnectJSONWebToken()`, where a few extra parameters had to be added to the method signature in order to make the method testable. I guess taking a TDD approach would help to avoid this.

### How mocking works?

For mocking external activity I used the Moq.NET framework.

I have abstracted the contents of this section into a gist.
https://gist.github.com/00111000/590cc386657c88c3ee21831c2d22d71c

# Common Questions

### What is the point for `CustomOpenIdConnectConfiguration.cs` and `IOpenIdConnectConfiguration.cs`?

`SigningKeys` is part of a regular class and it is not a virtual property, therefore it must be declared in an interface or an abstract class. That's why I created a custom interface - needed for mocking and a class that implements it - needed for regular usage.

### Why not pass `SigningKeys` instead of `discoveryDocument`?

`SigningKeys` is only a getter property, so we have to tell the property exactly what to return.

### Why pass `validateLifetime`?

It is possible for an ID Token to expire, and the `ValidateLifetime` property in `validationParameters` checks for that. In order to save time and not having to go through the process of generating a new token every time the unit tests have to be ran, adding an option to avoid checking for token experation allows the same token to be used for testing.

# Kudos
- https://stackoverflow.com/questions/47121732/how-to-properly-consume-openid-connect-jwks-uri-metadata-in-c
- https://stackoverrun.com/ru/q/9483098
- https://developer.okta.com/code/dotnet/jwt-validation
