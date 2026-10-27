using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Atlas
{
    /// <summary>One HTTP exchange. The Unity build uses UnityWebRequest; tests use a fake.</summary>
    public interface IHttpTransport
    {
        Task<HttpResult> PostFormAsync(string url, IDictionary<string, string> form, CancellationToken ct);
        Task<HttpResult> GetAsync(string url, string bearer, CancellationToken ct);
    }

    public sealed class HttpResult
    {
        public int Status;
        public string Body;
    }

    /// <summary>Where tokens live between runs. Keep refresh tokens in secure storage on shipped builds.</summary>
    public interface ITokenStore
    {
        string Load();
        void Save(string json);
        void Clear();
    }

    public sealed class MemoryTokenStore : ITokenStore
    {
        string _v;
        public string Load() => _v;
        public void Save(string json) { _v = json; }
        public void Clear() { _v = null; }
    }

    public sealed class AtlasException : Exception
    {
        public string Code { get; }
        public int Status { get; }
        public AtlasException(string code, string message, int status = 0) : base(message) { Code = code; Status = status; }
    }

    public sealed class AtlasTokens
    {
        public string AccessToken;
        public string RefreshToken;
        public string IdToken;
        public string Scope;
        /// <summary>Unix seconds when the access token expires.</summary>
        public long ExpiresAt;

        public bool IsExpired(long nowUnix, int skewSeconds = 30) => nowUnix + skewSeconds >= ExpiresAt;

        public string ToJson() =>
            "{\"access_token\":" + MiniJson.Quote(AccessToken ?? "") + ",\"refresh_token\":" + MiniJson.Quote(RefreshToken ?? "") +
            ",\"id_token\":" + MiniJson.Quote(IdToken ?? "") + ",\"scope\":" + MiniJson.Quote(Scope ?? "") + ",\"expires_at\":" + ExpiresAt + "}";

        public static AtlasTokens FromJson(string json)
        {
            var d = MiniJson.ParseObject(json);
            return new AtlasTokens
            {
                AccessToken = MiniJson.Str(d, "access_token"),
                RefreshToken = Empty(MiniJson.Str(d, "refresh_token")),
                IdToken = Empty(MiniJson.Str(d, "id_token")),
                Scope = MiniJson.Str(d, "scope"),
                ExpiresAt = MiniJson.Int(d, "expires_at"),
            };
        }

        static string Empty(string s) => string.IsNullOrEmpty(s) ? null : s;
    }

    /// <summary>The code a player types or scans on another device (RFC 8628).</summary>
    public sealed class DeviceCode
    {
        public string DeviceCodeValue;
        public string UserCode;
        public string VerificationUri;
        public string VerificationUriComplete;
        public int ExpiresIn;
        public int Interval;
    }

    public sealed class AtlasOptions
    {
        /// <summary>Your instance's OAuth origin, e.g. https://auth.example.com (no trailing slash needed).</summary>
        public string Issuer;
        public string ClientId;
        public string Scope = "openid profile email offline_access";
        public IHttpTransport Transport;
        public ITokenStore Store = new MemoryTokenStore();
        public Func<DateTime> UtcNow = () => DateTime.UtcNow;
        /// <summary>Sleeps between device polls; tests replace it.</summary>
        public Func<TimeSpan, CancellationToken, Task> Delay = (t, ct) => Task.Delay(t, ct);
    }

    public sealed class AtlasClient
    {
        const string DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
        readonly AtlasOptions _o;
        readonly string _base;

        public AtlasClient(AtlasOptions options)
        {
            if (options == null || string.IsNullOrEmpty(options.Issuer) || string.IsNullOrEmpty(options.ClientId))
                throw new ArgumentException("Issuer and ClientId are required.");
            if (options.Transport == null) throw new ArgumentException("A Transport is required (UnityWebRequestTransport on Unity).");
            _o = options;
            _base = options.Issuer.TrimEnd('/');
        }

        long Now() => new DateTimeOffset(_o.UtcNow()).ToUnixTimeSeconds();

        // ---- PKCE system-browser sign-in ----

        /// <summary>Build the sign-in URL to open in the system browser, plus the verifier to keep for the exchange.</summary>
        public (string Url, string Verifier, string State) BuildAuthorizeUrl(string redirectUri)
        {
            var verifier = Pkce.NewVerifier();
            var state = Pkce.NewVerifier();
            var q = new SortedDictionary<string, string>
            {
                ["response_type"] = "code",
                ["client_id"] = _o.ClientId,
                ["redirect_uri"] = redirectUri,
                ["scope"] = _o.Scope,
                ["state"] = state,
                ["code_challenge"] = Pkce.Challenge(verifier),
                ["code_challenge_method"] = "S256",
            };
            var sb = new StringBuilder(_base + "/oauth2/authorize?");
            bool first = true;
            foreach (var kv in q)
            {
                if (!first) sb.Append('&');
                first = false;
                sb.Append(Uri.EscapeDataString(kv.Key)).Append('=').Append(Uri.EscapeDataString(kv.Value));
            }
            return (sb.ToString(), verifier, state);
        }

        /// <summary>Exchange the authorization code from the redirect. Check that the returned state matches first.</summary>
        public Task<AtlasTokens> ExchangeCodeAsync(string code, string verifier, string redirectUri, CancellationToken ct = default) =>
            TokenAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["code_verifier"] = verifier,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = _o.ClientId,
            }, ct);

        // ---- Device flow ----

        public async Task<DeviceCode> StartDeviceFlowAsync(CancellationToken ct = default)
        {
            var r = await _o.Transport.PostFormAsync(_base + "/oauth2/device_authorization",
                new Dictionary<string, string> { ["client_id"] = _o.ClientId, ["scope"] = _o.Scope }, ct);
            var d = Parse(r);
            if (r.Status >= 400) throw Err(d, r.Status);
            return new DeviceCode
            {
                DeviceCodeValue = MiniJson.Str(d, "device_code"),
                UserCode = MiniJson.Str(d, "user_code"),
                VerificationUri = MiniJson.Str(d, "verification_uri"),
                VerificationUriComplete = MiniJson.Str(d, "verification_uri_complete"),
                ExpiresIn = (int)MiniJson.Int(d, "expires_in", 600),
                Interval = (int)MiniJson.Int(d, "interval", 5),
            };
        }

        /// <summary>Poll until the player approves, denies or the code expires. Honours slow_down.</summary>
        public async Task<AtlasTokens> PollDeviceFlowAsync(DeviceCode code, CancellationToken ct = default)
        {
            int interval = Math.Max(1, code.Interval);
            long deadline = Now() + code.ExpiresIn;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                await _o.Delay(TimeSpan.FromSeconds(interval), ct);
                if (Now() > deadline) throw new AtlasException("expired_token", "The device code expired.");
                var r = await _o.Transport.PostFormAsync(_base + "/oauth2/token", new Dictionary<string, string>
                {
                    ["grant_type"] = DeviceGrant,
                    ["device_code"] = code.DeviceCodeValue,
                    ["client_id"] = _o.ClientId,
                }, ct);
                var d = Parse(r);
                if (r.Status < 400) return Save(d);
                var e = MiniJson.Str(d, "error");
                if (e == "authorization_pending") continue;
                if (e == "slow_down") { interval += 5; continue; }
                throw Err(d, r.Status);
            }
        }

        // ---- Tokens ----

        public AtlasTokens Current()
        {
            var json = _o.Store.Load();
            return string.IsNullOrEmpty(json) ? null : AtlasTokens.FromJson(json);
        }

        /// <summary>A valid access token, refreshing it when it is about to expire. Null when signed out.</summary>
        public async Task<string> GetAccessTokenAsync(CancellationToken ct = default)
        {
            var t = Current();
            if (t == null) return null;
            if (!t.IsExpired(Now())) return t.AccessToken;
            if (t.RefreshToken == null) { _o.Store.Clear(); return null; }
            try
            {
                return (await TokenAsync(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = t.RefreshToken,
                    ["client_id"] = _o.ClientId,
                }, ct)).AccessToken;
            }
            catch (AtlasException e) when (e.Code == "invalid_grant")
            {
                _o.Store.Clear();
                return null;
            }
        }

        /// <summary>The signed-in player's profile claims (sub, name, email, ...).</summary>
        public async Task<Dictionary<string, object>> GetUserInfoAsync(CancellationToken ct = default)
        {
            var token = await GetAccessTokenAsync(ct);
            if (token == null) throw new AtlasException("signed_out", "Not signed in.");
            var r = await _o.Transport.GetAsync(_base + "/oauth2/userinfo", token, ct);
            var d = Parse(r);
            if (r.Status >= 400) throw Err(d, r.Status);
            return d;
        }

        /// <summary>Revoke the refresh token and forget the tokens. Local state is cleared even if the call fails.</summary>
        public async Task SignOutAsync(CancellationToken ct = default)
        {
            var t = Current();
            _o.Store.Clear();
            if (t?.RefreshToken == null) return;
            try
            {
                await _o.Transport.PostFormAsync(_base + "/oauth2/revoke", new Dictionary<string, string>
                {
                    ["token"] = t.RefreshToken,
                    ["token_type_hint"] = "refresh_token",
                    ["client_id"] = _o.ClientId,
                }, ct);
            }
            catch (Exception) { /* best effort */ }
        }

        async Task<AtlasTokens> TokenAsync(IDictionary<string, string> form, CancellationToken ct)
        {
            var r = await _o.Transport.PostFormAsync(_base + "/oauth2/token", form, ct);
            var d = Parse(r);
            if (r.Status >= 400) throw Err(d, r.Status);
            return Save(d);
        }

        AtlasTokens Save(Dictionary<string, object> d)
        {
            var t = new AtlasTokens
            {
                AccessToken = MiniJson.Str(d, "access_token"),
                RefreshToken = MiniJson.Str(d, "refresh_token") ?? Current()?.RefreshToken,
                IdToken = MiniJson.Str(d, "id_token"),
                Scope = MiniJson.Str(d, "scope"),
                ExpiresAt = Now() + MiniJson.Int(d, "expires_in", 3600),
            };
            if (t.AccessToken == null) throw new AtlasException("invalid_response", "The token response had no access_token.");
            _o.Store.Save(t.ToJson());
            return t;
        }

        static Dictionary<string, object> Parse(HttpResult r)
        {
            try { return MiniJson.ParseObject(r.Body ?? "{}"); }
            catch (FormatException) { throw new AtlasException("invalid_response", "The server answered with something that is not JSON.", r.Status); }
        }

        static AtlasException Err(Dictionary<string, object> d, int status) =>
            new AtlasException(MiniJson.Str(d, "error") ?? "error", MiniJson.Str(d, "error_description") ?? "Request failed.", status);
    }

    public static class Pkce
    {
        public static string NewVerifier()
        {
            var b = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return B64Url(b);
        }

        public static string Challenge(string verifier)
        {
            using (var sha = SHA256.Create()) return B64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
        }

        static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
