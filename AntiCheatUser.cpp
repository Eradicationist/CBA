#include <windows.h>
#include <winioctl.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include "AntiCheatCommon.h"

#define NUM_OFFSETS 3
#define SERVER_NAME L"yourserver.com"
#define SERVER_PORT 443
#define INIT_PATH L"/init"
#define VERIFY_PATH L"/verify_offset"
#define API_KEY "your_api_key"

// Simulated offsets and identifiers
struct OffsetEntry {
    const char* id;
    ULONG value;
};
OffsetEntry g_offsets[NUM_OFFSETS] = {
    {"offset_1", 0x1000},
    {"offset_2", 0x2000},
    {"offset_3", 0x3000}
};

// Session key
UCHAR g_sessionKey[32];

NTSTATUS PerformECDH(HINTERNET hSession, UCHAR* sessionKey) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptGenerateKeyPair(hAlg, &hKey, 256, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    UCHAR pubKey[1024];
    ULONG pubKeyLen;
    status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pubKey, sizeof(pubKey), &pubKeyLen, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, SERVER_NAME, SERVER_PORT, 0);
    if (!hConnect) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return STATUS_UNSUCCESSFUL;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", INIT_PATH, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return STATUS_UNSUCCESSFUL;
    }

    std::wstring headers = L"Content-Type: application/octet-stream\r\nX-API-Key: " + std::wstring(API_KEY, API_KEY + strlen(API_KEY));
    BOOL success = WinHttpSendRequest(hRequest, headers.c_str(), -1, pubKey, pubKeyLen, pubKeyLen, 0);
    if (success) success = WinHttpReceiveResponse(hRequest, NULL);

    UCHAR serverPubKey[1024];
    DWORD serverPubKeyLen = 0;
    if (success) {
        WinHttpReadData(hRequest, serverPubKey, sizeof(serverPubKey), &serverPubKeyLen);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);

    if (!success) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return STATUS_UNSUCCESSFUL;
    }

    BCRYPT_KEY_HANDLE hServerKey;
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hServerKey, serverPubKey, serverPubKeyLen, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptDeriveKey(hKey, BCRYPT_KDF_RAW, NULL, sessionKey, 32, &pubKeyLen, 0);
    BCryptDestroyKey(hServerKey);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

NTSTATUS EncryptOffset(ULONG offset, UCHAR* key, UCHAR* ciphertext, ULONG* ciphertextLen, UCHAR* iv, UCHAR* tag) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {0};
    authInfo.cbSize = sizeof(authInfo);
    authInfo.dwInfoVersion = 1;
    authInfo.pbNonce = iv;
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    status = BCryptEncrypt(hKey, (PUCHAR)&offset, sizeof(offset), &authInfo, NULL, 0, ciphertext, 32, ciphertextLen, 0);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

bool SendOffsetToServer(const char* offsetId, ULONG offsetValue) {
    UCHAR iv[12];
    UCHAR ciphertext[32];
    UCHAR tag[16];
    ULONG ciphertextLen;
    BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    NTSTATUS status = EncryptOffset(offsetValue, g_sessionKey, ciphertext, &ciphertextLen, iv, tag);
    if (!NT_SUCCESS(status)) {
        std::cout << "[AntiCheat][C++] Encryption failed: 0x" << std::hex << status << "\n";
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"AntiCheatClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, SERVER_NAME, SERVER_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", VERIFY_PATH, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Get timestamp in Unix epoch ms
    LARGE_INTEGER li;
    GetSystemTimeAsFileTime((FILETIME*)&li);
    LONGLONG timestamp = (li.QuadPart - 116444736000000000LL) / 10000;

    // Secure nonce
    ULONGLONG nonce;
    BCryptGenRandom(NULL, (PUCHAR)&nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Base64 encode
    char b64Cipher[64], b64IV[32], b64Tag[32];
    DWORD b64CipherLen = sizeof(b64Cipher), b64IVLen = sizeof(b64IV), b64TagLen = sizeof(b64Tag);
    CryptBinaryToStringA(ciphertext, ciphertextLen, CRYPT_STRING_BASE64URL, b64Cipher, &b64CipherLen);
    CryptBinaryToStringA(iv, sizeof(iv), CRYPT_STRING_BASE64URL, b64IV, &b64IVLen);
    CryptBinaryToStringA(tag, sizeof(tag), CRYPT_STRING_BASE64URL, b64Tag, &b64TagLen);

    // JSON payload
    char json[256];
    sprintf_s(json, "{\"id\":\"%s\",\"nonce\":%llu,\"timestamp\":%lld\",\"ciphertext\":\"%s\", \"iv\":\"%s\", \"tag\": \"%s\"}",
              offsetId, nonce, timestamp, b64Cipher, b64IV, b64TagList);

    std::wstring headers = L"Content-Type: application/json\r\nX-API-Key: " + std::wstring(API_KEY, API_KEY + strlen(API_KEY)));
    BOOL success = WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    success &= WinHttpSendRequest(hRequest, NULL, NULL, json, strlen(json), strlen(json), 0);
    if (success) success = WinHttpReceiveResponse(hRequest, NULL);
    
    DWORD statusCode = SUCCESS;
    DWORD statusSize = sizeof(statusCode);
    if (success) {
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusSize, NULL);
    }

    if (!success) {
        DWORD error = GetLastError();
        std::cout << "[AntiCheat][C++] WinHTTP error: " << error << "\n";
    }

    WinHttpCloseHandle(hRequest));
    WinHttpCloseHandle(hConnect));
    WinHttpCloseHandle(hSession);

    return success && statusCode == 200);
}

int main() {
    std::cout << "[AntiCheat][C++] Starting anti-cheat...\n";

    // Initialize WinHTTP session for ECDH
    HINTERNET hSession = WinHttpOpen(L"AntiCheatClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        std::cout << "[AntiCheat][C++] Failed to initialize WinHTTP\n";
        return 1;
    }

    // Perform ECDH
    if (!NT_SUCCESS(PerformECDH(hSession, g_sessionKey))) {
        std::cout << "[AntiCheat][C++] ECDH initialization failed\n";
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Open driver
    HANDLE hDriver = CreateFileW(L"\\\\\.\\AntiCheatDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cout << "[AntiCheat][C++] Failed to open driver: " << GetLastError() << "\n";
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Main loop with retry limit
    int retries = 0;
    const int maxRetries = 3;
    while (retries < maxRetries) {
        // Trigger driver integrity check
        DWORD bytesReturned;
        DeviceIoControl(hDriver, IOCTL_CHECK_INTEGRITY, NULL, NULL, 0, NULL, 0, &bytesReturned, NULL);

        // Retrieve logs
        char logs[4096];
        DeviceIoControl(hDriver, IOCTL_GET_LOGS, NULL, 0, logs, sizeof(logs), &bytesReturned, NULL);
        if (bytesReturned > 0) {
            std::cout << "[AntiCheat][C++] Driver Logs: " << std::string(logs, bytesReturned) << "\n";
        }

        // Send offsets to server
        bool allSuccess = true;
        for (int i = 0; i < NUM_OFFSETS; ++i) {
            if (SendOffsetToServer(g_offsets[i].id, g_offsets[i].value)) {
                std::cout << "[AntiCheat][C++] Offset " << g_offsets[i].id << " verified.\n";
            } else {
                std::cout << "[AntiCheat][C++] Failed to verify offset " << g_offsets[i].id << ".\n";
                allSuccess = false;
            }
        }

        if (!allSuccess) {
            retries++;
            std::cout << "[AntiCheat][C++] Retry " << retries << " of " << maxRetries << "\n";
            if (retries >= maxRetries) {
                std::cout << "[AntiCheat][C++] Max retries reached, exiting.\n";
                break;
            }
        } else {
            retries = 0;
        }

        Sleep(1000);
    }

    CloseHandle(hDriver);
    WinHttpCloseHandle(hSession);
    return retries >= maxRetries ? 1 : 0;
}