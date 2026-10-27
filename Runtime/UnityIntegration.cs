#if UNITY_5_3_OR_NEWER
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.Networking;

namespace Atlas
{
    /// <summary>UnityWebRequest transport.</summary>
    public sealed class UnityWebRequestTransport : IHttpTransport
    {
        public Task<HttpResult> PostFormAsync(string url, IDictionary<string, string> form, CancellationToken ct)
        {
            var f = new WWWForm();
            foreach (var kv in form) f.AddField(kv.Key, kv.Value);
            return Send(UnityWebRequest.Post(url, f), null, ct);
        }

        public Task<HttpResult> GetAsync(string url, string bearer, CancellationToken ct) =>
            Send(UnityWebRequest.Get(url), bearer, ct);

        static Task<HttpResult> Send(UnityWebRequest req, string bearer, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<HttpResult>();
            if (bearer != null) req.SetRequestHeader("Authorization", "Bearer " + bearer);
            req.SetRequestHeader("Accept", "application/json");
            var op = req.SendWebRequest();
            op.completed += _ =>
            {
                tcs.TrySetResult(new HttpResult { Status = (int)req.responseCode, Body = req.downloadHandler?.text });
                req.Dispose();
            };
            ct.Register(() => { req.Abort(); tcs.TrySetCanceled(); });
            return tcs.Task;
        }
    }

    /// <summary>Keeps tokens in PlayerPrefs. Fine for development; use a platform keychain wrapper (ITokenStore) for release builds.</summary>
    public sealed class PlayerPrefsTokenStore : ITokenStore
    {
        const string Key = "atlas.tokens";
        public string Load() => PlayerPrefs.HasKey(Key) ? PlayerPrefs.GetString(Key) : null;
        public void Save(string json) { PlayerPrefs.SetString(Key, json); PlayerPrefs.Save(); }
        public void Clear() { PlayerPrefs.DeleteKey(Key); PlayerPrefs.Save(); }
    }

    public static class AtlasBrowserSignIn
    {
        /// <summary>
        /// Sign in through the system browser (passkeys, social and SSO all work on the hosted page) and catch
        /// the redirect on a loopback port. Desktop platforms; on mobile use a custom-scheme redirect and
        /// call ExchangeCodeAsync yourself.
        /// </summary>
        public static async Task<AtlasTokens> SignInAsync(AtlasClient client, int port = 53682, CancellationToken ct = default)
        {
            var redirect = "http://127.0.0.1:" + port + "/callback";
            var (url, verifier, state) = client.BuildAuthorizeUrl(redirect);
            using (var listener = new HttpListener())
            {
                listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
                listener.Start();
                Application.OpenURL(url);
                using (ct.Register(listener.Stop))
                {
                    var ctx = await listener.GetContextAsync();
                    var query = ctx.Request.QueryString;
                    var body = Encoding.UTF8.GetBytes("<html><body>You can close this window and return to the game.</body></html>");
                    ctx.Response.ContentType = "text/html";
                    ctx.Response.OutputStream.Write(body, 0, body.Length);
                    ctx.Response.Close();
                    if (query["state"] != state) throw new AtlasException("state_mismatch", "The sign-in response did not match this request.");
                    if (query["error"] != null) throw new AtlasException(query["error"], query["error_description"] ?? "Sign-in was refused.");
                    return await client.ExchangeCodeAsync(query["code"], verifier, redirect, ct);
                }
            }
        }
    }
}
#endif
