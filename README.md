# Atlas Auth for Unity

Sign players in with Atlas from a Unity game (2021.3 or newer).

- **System-browser sign-in** (OAuth code + PKCE) on desktop, with a loopback redirect. Passkeys, social and SSO all work because the hosted page does the sign-in.
- **Device flow** for consoles, TVs and handhelds: show a code, the player approves it on a phone.
- **Token storage** behind `ITokenStore` (PlayerPrefs for development; wrap the platform keychain for release).
- Automatic refresh, `GetUserInfoAsync`, `SignOutAsync` (revokes the refresh token).

## Install

Add `net.atlasauth.sdk` from OpenUPM (`openupm add net.atlasauth.sdk`) or by git URL in Package Manager.

## Use

```csharp
var atlas = new AtlasClient(new AtlasOptions {
    Issuer = "https://auth.example.com",
    ClientId = "client_game",
    Transport = new UnityWebRequestTransport(),
    Store = new PlayerPrefsTokenStore(),
});

// Desktop
await AtlasBrowserSignIn.SignInAsync(atlas);

// Console / TV: device flow
var code = await atlas.StartDeviceFlowAsync();
ShowOnScreen(code.UserCode, code.VerificationUri);   // or a QR code of VerificationUriComplete
await atlas.PollDeviceFlowAsync(code);

var token = await atlas.GetAccessTokenAsync();       // refreshes when needed; null when signed out
```

Create the OAuth application in your dashboard as a public client and allow the `http://127.0.0.1:53682/callback` redirect (and your custom scheme on mobile). Send `token` to your game server as `Authorization: Bearer`; verify it there with an Atlas backend SDK.

## Tests

`Tests~/` holds a .NET test project that compiles `Runtime/` without Unity: `dotnet test Tests~`.
