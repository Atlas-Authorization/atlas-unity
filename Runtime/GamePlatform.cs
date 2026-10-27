using System;
using System.Text;

namespace Atlas
{
    /// <summary>
    /// Request bodies for game-platform sign-in (<c>POST {frontend api}/v1/oauth/game_platform</c>, with your
    /// publishable key in <c>x-publishable-key</c>). Gather the proof with the platform plugin
    /// (Apple GameKit's identity verification signature on iOS/tvOS/macOS, or the Play Games server auth code on Android),
    /// build the body here and post it.
    /// </summary>
    public static class GamePlatform
    {
        public static string GameCenterBody(string playerId, string bundleId, string publicKeyUrl, byte[] signature, byte[] salt, long timestampMs, string displayName = null)
        {
            var sb = new StringBuilder("{\"provider\":\"apple_game_center\",\"game_center\":{");
            sb.Append("\"player_id\":").Append(MiniJson.Quote(playerId));
            sb.Append(",\"bundle_id\":").Append(MiniJson.Quote(bundleId));
            sb.Append(",\"public_key_url\":").Append(MiniJson.Quote(publicKeyUrl));
            sb.Append(",\"signature\":").Append(MiniJson.Quote(Convert.ToBase64String(signature)));
            sb.Append(",\"salt\":").Append(MiniJson.Quote(Convert.ToBase64String(salt)));
            sb.Append(",\"timestamp\":").Append(timestampMs);
            if (displayName != null) sb.Append(",\"display_name\":").Append(MiniJson.Quote(displayName));
            return sb.Append("}}").ToString();
        }

        public static string PlayGamesBody(string serverAuthCode) =>
            "{\"provider\":\"google_play_games\",\"server_auth_code\":" + MiniJson.Quote(serverAuthCode) + "}";
    }
}
