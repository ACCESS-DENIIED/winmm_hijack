/*
 Logging: Writes to <exe_dir>/SMT/Logs/winmm.log via UtilsLog. Never logs token contents; only
          statuses, lengths, or HTTP codes. Avoids console/OutputDebugString in production.
 Environment:
   - SMT_VPS_BASE_URL (Debug only): override base URL (http/https scheme + host[:port]). Invalid
     values set g_vpsConfigInvalid and abort network calls.
   - CACHE_TTL_SECONDS: TTL for token verification cache (default 600s; max 24h).
 Security/Privacy: Sensitive buffers are zeroed (ZeroString/ZeroWString). Minimum TLS 1.3
                   is enforced for HTTPS.
 Related:
   - inject.cpp: Handles injection flow and uses these utilities.
   - MemoryModule.c: In-memory DLL loader; logs via MM_LogW/MM_LogA.
*/
#include "utils.h"
#include <regex>
#include <string>
#include <windows.h>
#include <winhttp.h>
#include <functional>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <vector>
#include <algorithm>
#include <bcrypt.h>
#include <cstdio>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

// Helpers to securely zero sensitive buffers (avoid optimization away)
static inline void ZeroString(std::string &s) {
    if (!s.empty()) SecureZeroMemory(s.data(), s.size());
}
static inline void ZeroWString(std::wstring &s) {
    if (!s.empty()) SecureZeroMemory(s.data(), s.size() * sizeof(wchar_t));
}

// Resolve VPS endpoint. In Release builds, always use production host over HTTPS 443.
// In Debug builds, allow override via environment variable SMT_VPS_BASE_URL (e.g., http://localhost:5005).
struct VpsEndpoint {
    std::wstring host;      // hostname only (no scheme)
    INTERNET_PORT port;     // port number
    DWORD requestFlags;     // WINHTTP_FLAG_SECURE for HTTPS, 0 for HTTP
};

static VpsEndpoint GetDefaultProdEndpoint() {
    // Production VPS over HTTPS 443
    return VpsEndpoint{L"spider-man.vps.dev", INTERNET_DEFAULT_HTTPS_PORT, WINHTTP_FLAG_SECURE};
}

// Global flag set when SMT_VPS_BASE_URL is provided but invalid. Used to fail fast.
static bool g_vpsConfigInvalid = false;

// JSON string escaper for embedding UTF-8 token safely
static std::string JsonEscape(const std::string& s)
{
    std::string out; out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    return out;
}

static std::wstring FormatWinError(DWORD err)
{
    LPWSTR buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, NULL);
    std::wstring s;
    if (n && buf) { s.assign(buf, n); LocalFree(buf); }
    // Trim CR/LF
    if (!s.empty()) {
        while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n')) s.pop_back();
    }
    return s;
}

/*
 Summary: Determines the VPS target endpoint.
   - Release: always returns the compiled production HTTPS endpoint (443).
   - Debug: allows SMT_VPS_BASE_URL override (http/https; host[:port]).
 Behavior: If SMT_VPS_BASE_URL is present but invalid, sets g_vpsConfigInvalid, logs a diagnostic,
           and returns an empty endpoint to fail fast.
 Returns: VpsEndpoint with host/port/requestFlags; host is empty when invalid override provided.
*/
static VpsEndpoint ResolveVpsEndpoint()
{
    g_vpsConfigInvalid = false;
#if defined(_DEBUG)
    wchar_t buf[2048];
    DWORD n = GetEnvironmentVariableW(L"SMT_VPS_BASE_URL", buf, 2048);
    if (n > 0 && n < 2048)
    {
        std::wstring url(buf, n);
        // Trim whitespace
        url.erase(0, url.find_first_not_of(L" \t\r\n"));
        url.erase(url.find_last_not_of(L" \t\r\n") + 1);

        // Parse scheme
        bool isHttps = false;
        size_t pos = std::wstring::npos;
        if (url.rfind(L"https://", 0) == 0) { isHttps = true; pos = 8; }
        else if (url.rfind(L"http://", 0) == 0) { isHttps = false; pos = 7; }

        if (pos != std::wstring::npos)
        {
            std::wstring rest = url.substr(pos);
            // Cut off path if present
            size_t slash = rest.find(L"/");
            std::wstring hostport = (slash == std::wstring::npos) ? rest : rest.substr(0, slash);
            if (!hostport.empty())
            {
                // Split host:port
                size_t colon = hostport.rfind(L":");
                std::wstring host = hostport;
                INTERNET_PORT port = isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
                if (colon != std::wstring::npos)
                {
                    host = hostport.substr(0, colon);
                    std::wstring portStr = hostport.substr(colon + 1);
                    try {
                        int p = std::stoi(portStr);
                        if (p > 0 && p <= 65535) port = static_cast<INTERNET_PORT>(p);
                    } catch (...) { /* ignore, keep default */ }
                }
                DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
                if (!host.empty()) {
                    return VpsEndpoint{host, port, flags};
                }
            }
        }
        // Env was present but invalid: fail-fast by flagging invalid
        g_vpsConfigInvalid = true;
        UtilsLog(L"Invalid SMT_VPS_BASE_URL; expected http(s)://host[:port]. Aborting network calls.");
        return VpsEndpoint{L"", 0, 0};
    }
    // No env set in Debug: fall through to compiled default
    return GetDefaultProdEndpoint();
#else
    // Release: always use compiled default; ignore any environment override
    return GetDefaultProdEndpoint();
#endif
}

// Local file logger (matches inject.cpp path: <exe_dir>/SMT/Logs/winmm.log)
static std::wofstream g_utilsLog;
static std::wstring GetUtilsLogPath()
{
    auto exePath = GetCurrentDllPath(NULL);
    auto dir = exePath.parent_path() / L"SMT" / L"Logs";
    std::error_code ec; std::filesystem::create_directories(dir, ec);
    return (dir / L"winmm.log").wstring();
}
static void UtilsLog(const std::wstring& msg)
{
    if (!g_utilsLog.is_open())
        g_utilsLog.open(GetUtilsLogPath(), std::ios::out | std::ios::app);
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[64];
    swprintf_s(ts, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    g_utilsLog << L"[" << ts << L"] [UTILS] " << msg << L"\n";
    g_utilsLog.flush();
}
// Usage: Used to construct the log path <exe_dir>/SMT/Logs consistently across modules.
std::filesystem::path GetCurrentDllPath(HMODULE hModule)
{
    TCHAR pathBuffer[MAX_PATH] = { 0 };
	if (NULL == hModule) {
        hModule = GetModuleHandle(NULL);
    }
    if (GetModuleFileName(hModule, pathBuffer, MAX_PATH) == 0) {
        return {};
    }
    return std::filesystem::path(pathBuffer);
}

// Percent-encodes the UTF-8 bytes of a wide string for safe use in URL query parameters.
// Details: Leaves unreserved characters (ALPHA/DIGIT/-/._/~) as-is; encodes others as %HH.
// Reason: Prevents truncation or misinterpretation of special characters.
static std::wstring PercentEncodeUtf8(const std::wstring& input)
{
    // Convert to UTF-8 bytes first
    int len = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 1) return L""; // empty
    std::string utf8(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, utf8.data(), len, NULL, NULL);

    std::wstring out;
    out.reserve(input.size() * 3); // worst-case expansion
    auto isUnreserved = [](unsigned char c) -> bool {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
    };
    const wchar_t hex[] = L"0123456789ABCDEF";
    for (unsigned char b : utf8)
    {
        if (isUnreserved(b))
        {
            out.push_back(static_cast<wchar_t>(b));
        }
        else
        {
            out.push_back(L'%');
            out.push_back(hex[(b >> 4) & 0xF]);
            out.push_back(hex[b & 0xF]);
        }
    }
    return out;
}

// Helpers for UTF-8 conversion (without percent-encoding) and JSON parsing
static std::string WStringToUtf8(const std::wstring& input)
{
    int len = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 1) return std::string();
    std::string utf8(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, utf8.data(), len, NULL, NULL);
    return utf8;
}

static bool ParseValidFromJson(const std::string& body)
{
    // Strict enough for our schema: find "valid" key and ensure boolean true/false
    // Reject if key not found or value not a boolean.
    auto findKey = body.find("\"valid\"");
    if (findKey == std::string::npos) return false;
    auto colon = body.find(':', findKey);
    if (colon == std::string::npos) return false;
    // Skip whitespace
    size_t i = colon + 1;
    while (i < body.size() && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n')) ++i;
    if (i + 3 < body.size() && body.compare(i, 4, "true") == 0) return true;
    if (i + 4 < body.size() && body.compare(i, 5, "false") == 0) return false;
    return false;
}

/*
 Function: Sha256Hex
 Summary: Computes SHA-256 using Windows CNG and returns the lowercase hex string.
*/
static std::string Sha256Hex(const std::string& data)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) return std::string();

    DWORD objLen = 0, cb = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return std::string(); }
    std::vector<BYTE> obj(objLen);

    DWORD hashLen = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return std::string(); }
    std::vector<BYTE> hash(hashLen);

    status = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return std::string(); }
    status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    if (status < 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return std::string(); }
    status = BCryptFinishHash(hHash, hash.data(), hashLen, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status < 0) return std::string();

    static const char* hex = "0123456789abcdef";
    std::string out(hashLen * 2, '\0');
    for (DWORD i = 0; i < hashLen; ++i) {
        out[i*2] = hex[(hash[i] >> 4) & 0xF];
        out[i*2 + 1] = hex[hash[i] & 0xF];
    }
    return out;
}

// Simple cache for token verification results
struct CacheEntry { bool valid; ULONGLONG expiresAt; };
static std::unordered_map<std::string, CacheEntry> g_tokenCache;
static std::mutex g_cacheMutex;

static DWORD GetCacheTtlSeconds()
{
    wchar_t buf[64];
    DWORD n = GetEnvironmentVariableW(L"CACHE_TTL_SECONDS", buf, 64);
    if (n > 0 && n < 64) {
        int v = _wtoi(buf);
        if (v > 0 && v < 24*60*60) return (DWORD)v;
    }
    return 600; // default 600s
}

/*
 Template: MakeHttpRequest<ResultType>
 Summary: Executes an HTTP request against the resolved VPS host using WinHTTP.
 Params:
   - endpoint: relative path (with or without leading '/').
   - method: HTTP method (e.g., L"GET", L"POST").
   - extraHeaders: additional CRLF-separated headers (may be empty).
   - body/bodyLen: optional request body.
   - responseHandler: callback to parse the response and produce ResultType.
 Behavior:
   - Aborts if g_vpsConfigInvalid is set (invalid SMT_VPS_BASE_URL in Debug).
   - Enforces TLS 1.2+ when using HTTPS.
   - Tries a localhost/127.0.0.1 fallback when appropriate.
 Privacy: Does not log request bodies; logs only high-level diagnostics.
*/
template<typename ResultType>
ResultType MakeHttpRequest(
    const std::wstring &endpoint,
    const std::wstring &method,
    const std::wstring &extraHeaders, // CRLF separated, may be empty
    const void* body, DWORD bodyLen,
    std::function<ResultType(HINTERNET, bool)> responseHandler) {
        if (g_vpsConfigInvalid) {
            UtilsLog(L"HTTP aborted: invalid SMT_VPS_BASE_URL detected.");
            return ResultType{};
        }
        std::wstring ep = endpoint;
        if (!ep.empty() && ep[0] != L'/') {
            ep.insert(ep.begin(), L'/');
        }

        VpsEndpoint vps = ResolveVpsEndpoint();
        std::wstring hosts[2] = { vps.host, L"" };
        if (vps.host == L"127.0.0.1") hosts[1] = L"localhost";
        else if (vps.host == L"localhost") hosts[1] = L"127.0.0.1";

        ResultType finalResult{};
        for (int attempt = 0; attempt < 2; ++attempt) {
            std::wstring hostTry = hosts[attempt];
            if (hostTry.empty()) continue;

            try {
                std::wstring hostport = hostTry + L":" + std::to_wstring(vps.port);
                UtilsLog(L"HTTP preparing: host=" + hostport + L" path=" + ep + L" method=" + method);
            }
            catch (...) {}

            HINTERNET hSession = WinHttpOpen(L"SMTLauncher", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) { continue; }

            DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
            if (!WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
                DWORD err = GetLastError();
                UtilsLog(L"WinHttpSetOption SECURE_PROTOCOLS failed. GLE=" + std::to_wstring(err) + L" (" + FormatWinError(err) + L")");
            }
            HINTERNET hConnect = WinHttpConnect(hSession, hostTry.c_str(), vps.port, 0);
            if (!hConnect) { WinHttpCloseHandle(hSession); continue; }
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), ep.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, vps.requestFlags);
            if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); continue; }

            LPCWSTR headers = extraHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extraHeaders.c_str();
            DWORD headersLen = extraHeaders.empty() ? 0 : (DWORD)extraHeaders.size();
            BOOL sendOk = WinHttpSendRequest(hRequest, headers, headersLen, (LPVOID)body, bodyLen, bodyLen, 0);
            if (!sendOk) {
                DWORD err = GetLastError();
                UtilsLog(L"WinHttpSendRequest failed. GLE=" + std::to_wstring(err) + L" (" + FormatWinError(err) + L")");
            }
            BOOL recvOk = FALSE;
            if (sendOk) {
                recvOk = WinHttpReceiveResponse(hRequest, NULL);
                if (!recvOk) {
                    DWORD err = GetLastError();
                    UtilsLog(L"WinHttpReceiveResponse failed. GLE=" + std::to_wstring(err) + L" (" + FormatWinError(err) + L")");
                }
            }
            bool success = sendOk && recvOk;

            ResultType result = responseHandler(hRequest, success);

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            if (success) { finalResult = result; break; }
            else if (attempt == 0 && !hosts[1].empty()) {
                UtilsLog(L"Primary host failed; trying fallback host: " + hosts[1]);
            }
        }
        return finalResult;
}


/*
 Summary: Verifies a Patreon access token via POST /v1/auth/verify (JSON body).
 Caching: SHA-256 of token used as key; results cached for CACHE_TTL_SECONDS.
 Privacy: Never logs token contents; only cache hits and verification status.
 Returns: true if VPS returns valid=true; false otherwise or on error.
*/
bool VerifyToken(const std::wstring &token) {
    // Cache check
    std::string tokenUtf8 = WStringToUtf8(token);
    const std::string key = Sha256Hex(tokenUtf8);
    if (!key.empty()) {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_tokenCache.find(key);
        if (it != g_tokenCache.end()) {
            if (GetTickCount64() < it->second.expiresAt) {
                UtilsLog(L"Verify cache hit");
                return it->second.valid;
            } else {
                g_tokenCache.erase(it);
            }
        }
    }

    // Build JSON body
    std::string bodyJson = std::string("{\"token\":\"") + JsonEscape(tokenUtf8) + "\"}";
    // Headers: Content-Type
    std::wstring headers = L"Content-Type: application/json\r\n";

    bool valid = MakeHttpRequest<bool>(
        L"v1/auth/verify", L"POST", headers,
        bodyJson.data(), (DWORD)bodyJson.size(),
        [](HINTERNET hRequest, bool success) -> bool {
            if (!success) return false;
            DWORD statusCode = 0; DWORD size = sizeof(statusCode);
            if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX))
                return false;
            if (statusCode != 200) {
                UtilsLog(L"Verify unexpected status: " + std::to_wstring(statusCode));
                return false;
            }
            // Read body fully
            std::string body;
            for (;;) {
                DWORD avail = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
                if (avail == 0) break;
                size_t pos = body.size();
                body.resize(pos + avail);
                DWORD read = 0;
                if (!WinHttpReadData(hRequest, &body[pos], avail, &read)) break;
                if (read < avail) body.resize(pos + read);
            }
            bool v = ParseValidFromJson(body);
            if (v) UtilsLog(L"Token verified by VPS");
            else UtilsLog(L"Token verification returned invalid");
            return v;
        }
    );

    // Update cache
    if (!key.empty()) {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        g_tokenCache[key] = CacheEntry{ valid, GetTickCount64() + (ULONGLONG)GetCacheTtlSeconds() * 1000ULL };
    }
    // Security: zero transient sensitive buffers
    ZeroString(bodyJson);
    ZeroString(tokenUtf8);
    return valid;
}

/*
 Returns: Vector of bytes on success, empty vector on failure or unexpected status.
*/
std::vector<BYTE> DownloadMod(const std::wstring &token)
{ 
    // Build Authorization header, do not log token
    std::wstring authHeader = L"Authorization: Bearer ";
    authHeader += std::wstring(token.c_str());
    authHeader += L"\r\n";

    auto bytes = MakeHttpRequest<std::vector<BYTE>>(
        L"v1/mod", L"GET", authHeader, nullptr, 0,
        [](HINTERNET hRequest, bool success) -> std::vector<BYTE> {
            std::vector<BYTE> modBytes;
            if (!success) return modBytes;

            // Check HTTP status first; only proceed on 200 OK
            DWORD statusCode = 0; DWORD size = sizeof(statusCode);
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX)) {
                if (statusCode != 200) {
                    UtilsLog(L"Mod download unexpected status: " + std::to_wstring(statusCode));
                    return modBytes;
                }
            }
            // Log Content-Length if present
            WCHAR clBuf[64] = {0}; DWORD clSize = sizeof(clBuf);
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, clBuf, &clSize, WINHTTP_NO_HEADER_INDEX)) {
                UtilsLog(L"Mod Content-Length: " + std::wstring(clBuf));
            }
            DWORD sizeOfBuffer = 0;
            do {
                if (!WinHttpQueryDataAvailable(hRequest, &sizeOfBuffer) || sizeOfBuffer == 0) break;
                std::vector<BYTE> buffer(sizeOfBuffer);
                DWORD dwDownloaded = 0;
                if (!WinHttpReadData(hRequest, buffer.data(), sizeOfBuffer, &dwDownloaded)) break;
                modBytes.insert(modBytes.end(), buffer.begin(), buffer.begin() + dwDownloaded);
            } while (sizeOfBuffer > 0);
            return modBytes;
        }
    );

    // Security: zero Authorization header buffer after use
    ZeroWString(authHeader);
    return bytes;
}
