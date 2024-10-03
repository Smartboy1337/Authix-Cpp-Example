#ifndef MAIN_H
#define MAIN_H

#include <Windows.h>
#include <iostream>
#include <format>
#include <random>
#include <sddl.h>
#include <IPTypes.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")


#include "../Auth/Authix.hpp"

char* ConvertToChar(const wchar_t* buffer)
{
    int size = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL);
    char* multiByteString = new char[size];
    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, multiByteString, size, NULL, NULL);

    return multiByteString;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string GetIP() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        // Perform the request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            readBuffer = "";
        }

        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

bool IsUsingVPN(const std::string& ip) {
    std::string url = "https://ipinfo.io/" + ip + "/json?token=YOUR_API_TOKEN";
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return false;
        }

        curl_easy_cleanup(curl);
    }
    else {
        std::cerr << "Failed to initialize curl" << std::endl;
        curl_global_cleanup();
        return false;
    }
    curl_global_cleanup();

    try {
        auto json = nlohmann::json::parse(readBuffer);
        std::string org = json.value("org", "");
        return org.find("VPN") != std::string::npos || org.find("Proxy") != std::string::npos;
    }
    catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return false;
    }
}

char* GrabSID()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) 
    {
        return nullptr;
    }

    DWORD dwLengthNeeded;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) 
    {
        CloseHandle(hToken);
        return nullptr;
    }

    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(new BYTE[dwLengthNeeded]);

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLengthNeeded, &dwLengthNeeded)) 
    {
        CloseHandle(hToken);
        delete[] reinterpret_cast<PBYTE>(pTokenUser);
        return nullptr;
    }

    CloseHandle(hToken);

    LPWSTR pStringSid = nullptr;
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pStringSid)) 
    {
        delete[] reinterpret_cast<PBYTE>(pTokenUser);
        return nullptr;
    }

    char* FinalSid = ConvertToChar(pStringSid);

    return FinalSid;
}

#endif //MAIN_H
