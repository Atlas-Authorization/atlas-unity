using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Atlas;
using Xunit;

public class FakeTransport : IHttpTransport
{
    public readonly List<(string Url, Dictionary<string, string> Form)> Posts = new List<(string, Dictionary<string, string>)>();
    public readonly Queue<HttpResult> Replies = new Queue<HttpResult>();
    public string LastBearer;

    public Task<HttpResult> PostFormAsync(string url, IDictionary<string, string> form, CancellationToken ct)
    {
        Posts.Add((url, new Dictionary<string, string>(form)));
        return Task.FromResult(Replies.Dequeue());
    }

    public Task<HttpResult> GetAsync(string url, string bearer, CancellationToken ct)
    {
        LastBearer = bearer;
        return Task.FromResult(Replies.Dequeue());
    }
}

public class AtlasClientTests
{
    static HttpResult R(int status, string body) => new HttpResult { Status = status, Body = body };

    static (AtlasClient, FakeTransport, MemoryTokenStore, Func<DateTime>[]) Make()
    {
        var t = new FakeTransport();
        var store = new MemoryTokenStore();
        var now = new[] { new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc) };
        Func<DateTime> clock = () => now[0];
        var c = new AtlasClient(new AtlasOptions
        {
            Issuer = "https://auth.example.com/",
            ClientId = "client_game",
            Transport = t,
            Store = store,
            UtcNow = clock,
            Delay = (_, __) => Task.CompletedTask,
        });
        return (c, t, store, new[] { clock });
    }

    [Fact]
    public void AuthorizeUrlCarriesPkceChallengeOfTheVerifier()
    {
        var (c, _, _, _) = Make();
        var (url, verifier, state) = c.BuildAuthorizeUrl("http://127.0.0.1:1/callback");
        Assert.StartsWith("https://auth.example.com/oauth2/authorize?", url);
        Assert.Contains("code_challenge_method=S256", url);
        Assert.Contains("code_challenge=" + Pkce.Challenge(verifier), url);
        Assert.Contains("state=" + state, url);
        Assert.NotEqual(verifier, state);
    }

    [Fact]
    public void PkceMatchesRfc7636Vector()
    {
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    [Fact]
    public async Task DeviceFlowPollsThroughPendingAndSlowDownThenStoresTokens()
    {
        var (c, t, store, _) = Make();
        t.Replies.Enqueue(R(200, "{\"device_code\":\"dc\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://auth.example.com/oauth2/device\",\"expires_in\":600,\"interval\":5}"));
        var code = await c.StartDeviceFlowAsync();
        Assert.Equal("WDJB-MJHT", code.UserCode);

        t.Replies.Enqueue(R(400, "{\"error\":\"authorization_pending\"}"));
        t.Replies.Enqueue(R(400, "{\"error\":\"slow_down\"}"));
        t.Replies.Enqueue(R(200, "{\"access_token\":\"at\",\"refresh_token\":\"rt\",\"expires_in\":3600,\"scope\":\"openid\"}"));
        var tokens = await c.PollDeviceFlowAsync(code);
        Assert.Equal("at", tokens.AccessToken);
        Assert.Equal("rt", AtlasTokens.FromJson(store.Load()).RefreshToken);
        Assert.Equal("urn:ietf:params:oauth:grant-type:device_code", t.Posts[1].Form["grant_type"]);
    }

    [Fact]
    public async Task DeviceFlowSurfacesDenial()
    {
        var (c, t, _, _) = Make();
        t.Replies.Enqueue(R(400, "{\"error\":\"access_denied\",\"error_description\":\"No.\"}"));
        var e = await Assert.ThrowsAsync<AtlasException>(() => c.PollDeviceFlowAsync(new DeviceCode { DeviceCodeValue = "dc", ExpiresIn = 600, Interval = 1 }));
        Assert.Equal("access_denied", e.Code);
    }

    [Fact]
    public async Task AccessTokenIsRefreshedWhenExpiredAndKeepsTheOldRefreshTokenIfNoneIsRotated()
    {
        var (c, t, store, _) = Make();
        var past = new DateTimeOffset(new DateTime(2026, 10, 26, 11, 0, 0, DateTimeKind.Utc)).ToUnixTimeSeconds();
        store.Save(new AtlasTokens { AccessToken = "old", RefreshToken = "rt", ExpiresAt = past }.ToJson());
        t.Replies.Enqueue(R(200, "{\"access_token\":\"new\",\"expires_in\":3600}"));
        Assert.Equal("new", await c.GetAccessTokenAsync());
        Assert.Equal("refresh_token", t.Posts[0].Form["grant_type"]);
        Assert.Equal("rt", AtlasTokens.FromJson(store.Load()).RefreshToken);
    }

    [Fact]
    public async Task RevokedRefreshTokenSignsOut()
    {
        var (c, t, store, _) = Make();
        store.Save(new AtlasTokens { AccessToken = "old", RefreshToken = "rt", ExpiresAt = 1 }.ToJson());
        t.Replies.Enqueue(R(400, "{\"error\":\"invalid_grant\"}"));
        Assert.Null(await c.GetAccessTokenAsync());
        Assert.Null(store.Load());
    }

    [Fact]
    public async Task SignOutClearsLocallyAndRevokes()
    {
        var (c, t, store, _) = Make();
        store.Save(new AtlasTokens { AccessToken = "a", RefreshToken = "rt", ExpiresAt = long.MaxValue }.ToJson());
        t.Replies.Enqueue(R(200, "{}"));
        await c.SignOutAsync();
        Assert.Null(store.Load());
        Assert.EndsWith("/oauth2/revoke", t.Posts[0].Url);
    }

    [Fact]
    public async Task UserInfoSendsBearer()
    {
        var (c, t, store, _) = Make();
        store.Save(new AtlasTokens { AccessToken = "a", ExpiresAt = long.MaxValue }.ToJson());
        t.Replies.Enqueue(R(200, "{\"sub\":\"user_1\",\"email_verified\":true}"));
        var info = await c.GetUserInfoAsync();
        Assert.Equal("user_1", MiniJson.Str(info, "sub"));
        Assert.Equal("a", t.LastBearer);
    }

    [Fact]
    public void MiniJsonHandlesEscapesNestedAndArrays()
    {
        var d = MiniJson.ParseObject("{\"a\":\"x\\\"\\u0041\",\"n\":[1,{\"k\":\"]\"}],\"o\":{\"p\":1},\"z\":null,\"b\":false,\"i\":42}");
        Assert.Equal("x\"A", MiniJson.Str(d, "a"));
        Assert.Equal(42, MiniJson.Int(d, "i"));
        Assert.Throws<FormatException>(() => MiniJson.ParseObject("[1]"));
    }
}

public class GamePlatformTests
{
    [Xunit.Fact]
    public void BodiesAreValidJsonWithBase64Binary()
    {
        var gc = Atlas.MiniJson.ParseObject(Atlas.GamePlatform.GameCenterBody("T:1", "com.x", "https://static.gc.apple.com/k.cer", new byte[] { 1, 2, 3 }, new byte[] { 4, 5 }, 1700000000000, "Ada"));
        Xunit.Assert.Equal("apple_game_center", Atlas.MiniJson.Str(gc, "provider"));
        var inner = (System.Collections.Generic.Dictionary<string, object>)gc["game_center"];
        Xunit.Assert.Equal("AQID", Atlas.MiniJson.Str(inner, "signature"));
        Xunit.Assert.Equal("BAU=", Atlas.MiniJson.Str(inner, "salt"));
    }

    [Xunit.Fact]
    public void PlayGamesBody()
    {
        Xunit.Assert.Equal("4/x", Atlas.MiniJson.Str(Atlas.MiniJson.ParseObject(Atlas.GamePlatform.PlayGamesBody("4/x")), "server_auth_code"));
    }
}
