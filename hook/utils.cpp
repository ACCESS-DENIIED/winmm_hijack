#include "utils.h"
#include <regex>
#include <string>
#include <windows.h>
#include <winhttp.h>
#include <functional>

#pragma comment(lib, "winhttp.lib")

// TODO: use real url
constexpr const wchar_t* VPSUrl = L"https://spider-mans.vps.dev";

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

template<typename ResultType>
ResultType MakeHttpRequest(
    const std::wstring &endpoint,
    const std::wstring &queryParams,
    std::function<ResultType(HINTERNET, bool)> responseHandler) {
        std::wstring ep = endpoint;
        if (!queryParams.empty()) {
            ep += L"?" + queryParams;
        }

        HINTERNET hSession = WinHttpOpen(L"SMTLauncher", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        HINTERNET hConnect = WinHttpConnect(hSession, VPSUrl, INTERNET_DEFAULT_HTTPS_PORT, 0);
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", ep.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

        if (!hSession) {
            return {};
        }
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return {};
        }
        if (!hRequest) { 
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return {};
        }
        bool success = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(hRequest, NULL);
        
        ResultType result = responseHandler(hRequest, success);
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return result;
    }


bool VerifyToken(const std::wstring &token) {
    return MakeHttpRequest<bool>(
        L"verify", L"token=" + token,
        [](HINTERNET hRequest, bool success) -> bool {
            if (!success) {
                return false;
            }
            DWORD statusCode = 0; 
            DWORD size = sizeof(statusCode);

            // Get HTTP status code
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX)) {
                if (statusCode == 401) {
                    OutputDebugString(L"Unauthorized token");
                } else if (statusCode != 200) {
                    OutputDebugString(L"Failed to verify token");
                }
                return statusCode == 200;
            }
            return false;
        }
    );
    
    // TODO: verify the mod signature/checksum
}

std::vector<BYTE> DownloadMod(const std::wstring &token)
{ 
    return MakeHttpRequest<std::vector<BYTE>>(
        L"mod", L"token=" + token,
        [](HINTERNET hRequest, bool success) -> std::vector<BYTE> {
            std::vector<BYTE> modBytes;
            if (!success) {
                return modBytes;
            }

            DWORD size = 0;
            do {
                if (!WinHttpQueryDataAvailable(hRequest, &size) || size == 0) {
                    break;
                }
                std::vector<BYTE> buffer(size);
                DWORD dwDownloaded = 0;

                // Read data chunk into the buffer
                if (!WinHttpReadData(hRequest, buffer.data(), size, &dwDownloaded)) {
                    break;
                }
                modBytes.insert(modBytes.end(), buffer.begin(), buffer.begin() + dwDownloaded);

            } while (size > 0);
            
            return modBytes;
        }
    );
}
