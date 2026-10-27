using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Atlas
{
    /// <summary>Tiny JSON reader/writer for the flat objects the OAuth endpoints exchange (no dependency, works in every Unity version).</summary>
    public static class MiniJson
    {
        /// <summary>Parse a JSON object. Nested values are returned as raw JSON strings under their key.</summary>
        public static Dictionary<string, object> ParseObject(string json)
        {
            int i = 0;
            Ws(json, ref i);
            var v = ReadValue(json, ref i);
            var d = v as Dictionary<string, object>;
            if (d == null) throw new FormatException("Expected a JSON object.");
            return d;
        }

        public static string Str(Dictionary<string, object> d, string key) =>
            d.TryGetValue(key, out var v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;

        public static long Int(Dictionary<string, object> d, string key, long fallback = 0) =>
            d.TryGetValue(key, out var v) && v is double n ? (long)n : fallback;

        public static string Quote(string s)
        {
            var sb = new StringBuilder("\"");
            foreach (var c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4")); else sb.Append(c);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }

        static void Ws(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }

        static object ReadValue(string s, ref int i)
        {
            Ws(s, ref i);
            if (i >= s.Length) throw new FormatException("Unexpected end of JSON.");
            char c = s[i];
            if (c == '{')
            {
                var d = new Dictionary<string, object>();
                i++; Ws(s, ref i);
                if (s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws(s, ref i);
                    var k = ReadString(s, ref i);
                    Ws(s, ref i);
                    if (s[i++] != ':') throw new FormatException("Expected ':'.");
                    d[k] = ReadValue(s, ref i);
                    Ws(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == '}') { i++; return d; }
                    throw new FormatException("Expected ',' or '}'.");
                }
            }
            if (c == '[')
            {
                int start = i; Skip(s, ref i);
                return s.Substring(start, i - start);
            }
            if (c == '"') return ReadString(s, ref i);
            if (string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            int j = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (j == i) throw new FormatException("Unexpected JSON token.");
            return double.Parse(s.Substring(j, i - j), CultureInfo.InvariantCulture);
        }

        // Skip a bracketed value (arrays), honouring strings.
        static void Skip(string s, ref int i)
        {
            int depth = 0;
            for (; i < s.Length; i++)
            {
                if (s[i] == '"') { ReadString(s, ref i); i--; }
                else if (s[i] == '[' || s[i] == '{') depth++;
                else if (s[i] == ']' || s[i] == '}') { depth--; if (depth == 0) { i++; return; } }
            }
            throw new FormatException("Unterminated JSON array.");
        }

        static string ReadString(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException("Expected a string.");
            i++;
            var sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u': sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("Unterminated string.");
        }
    }
}
