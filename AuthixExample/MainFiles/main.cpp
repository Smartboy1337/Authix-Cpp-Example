#include "main.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <curl/curl.h>

extern std::string webhookUrl; // Declaration
// Function to escape JSON special characters
std::string EscapeJson(const std::string& str) {
    std::string escapedStr;
    for (char c : str) {
        switch (c) {
        case '\"': escapedStr += "\\\""; break;
        case '\\': escapedStr += "\\\\"; break;
        case '/': escapedStr += "\\/"; break;
        case '\b': escapedStr += "\\b"; break;
        case '\f': escapedStr += "\\f"; break;
        case '\n': escapedStr += "\\n"; break;
        case '\r': escapedStr += "\\r"; break;
        case '\t': escapedStr += "\\t"; break;
        default: escapedStr += c; break;
        }
    }
    return escapedStr;
}

// Function to send logs to Discord webhook with debug info
void SendDiscordEmbedForLogs(const std::string& webhookUrl, const std::string& title, const std::string& description, int color) {
    CURL* curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "accept: application/json");
        headers = curl_slist_append(headers, "content-type: application/json");

        // Escape JSON special characters
        std::string escapedTitle = EscapeJson(title);
        std::string escapedDescription = EscapeJson(description);

        // Create the JSON payload for the embed with color
        std::string payload = R"({"embeds": [{"title": ")" + escapedTitle + R"(", "description": ")" + escapedDescription + R"(", "color": )" + std::to_string(color) + R"(}]})";

        // Set cURL options
        curl_easy_setopt(curl, CURLOPT_URL, webhookUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Enable verbose output for debugging
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);  // Verbose debug mode enabled

        // Capture response and HTTP status code
        long http_code = 0;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout); // Write response to stdout

        // Perform the request
        res = curl_easy_perform(curl);

        // Debug information
        std::cout << "Sending webhook with payload: " << payload << std::endl;

        // Check for errors in the request
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        else {
            // Check HTTP response code
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            std::cout << "HTTP Response Code: " << http_code << std::endl;
        }

        // Cleanup
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();
}



int main() {

    // Retrieve IP address and VPN status
    std::string ip = GetIP();
    bool isVPN = IsUsingVPN(ip);

    // Init Session
    std::string InitSessionResponse = Authix::InitSession();
    bool InitSessionSuccess;
    std::string InitSessionMessage;
    std::string InitSessionData;

    if (InitSessionResponse.length() > 0) {
        json jsonData = json::parse(InitSessionResponse);
        InitSessionSuccess = jsonData["success"];
        if (!InitSessionSuccess) {
            InitSessionMessage = jsonData["message"];
            std::cout << "InitSessionSuccess: " << std::boolalpha << InitSessionSuccess << std::endl;
            std::cout << "InitSessionMessage: " << InitSessionMessage << std::endl;

            // Send failure webhook with red color
            Authix::SendWebhook(
                webhookUrl,
                "Init Session Failed",
                "",
                "Init Session Failed",
                "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nMessage: " + InitSessionMessage,
                0xFF0000 // Red color
            );

            std::this_thread::sleep_for(std::chrono::seconds(2));
            return 2;
        }
        else {
            InitSessionData = jsonData["data"];
        }
    }
    else {
        std::cout << "\nInitSessionResponse is 0" << std::endl;
        Authix::SendWebhook(
            webhookUrl,
            "Init Session Error",
            "",
            "Init Session Error",
            "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nInitSessionResponse is 0",
            0xFF0000 // Red color
        );

        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    // Decrypt Data Returned From Init Session
    std::string InitSessionDecryptedData = Authix::DecryptInitData(InitSessionData);
    std::string SessionID;
    int Expires;
    std::string NewIV;

    try {
        json jsonData = json::parse(InitSessionDecryptedData);
        SessionID = jsonData["session_id"];
        Expires = jsonData["expires_at"];
        NewIV = jsonData["iv"];
    }
    catch (const std::exception& e) {
        std::cout << "\nError during the JSON parsing: " << e.what() << std::endl;
        Authix::SendWebhook(
            webhookUrl,
            "Init Session Decrypt Error",
            "",
            "Init Session Decrypt Error",
            "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nError: " + e.what(),
            0xFF0000 // Red color
        );

        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    // Getting the hwid and the input key from the user
    std::string License;
    std::cout << "\nYour License --> ";
    std::cin >> License;
    std::cout << "\n";

    // Grabbing the user HWID (in this case we use Windows SID)
    std::string UserHwid = GrabSID();

    // Login Request
    std::string LoginResponse = Authix::Login(License, UserHwid, SessionID);
    bool LoginSuccess;
    std::string LoginData;
    std::string LoginMessage;

    if (LoginResponse.length() > 0) {
        json jsonData = json::parse(LoginResponse);
        LoginSuccess = jsonData["success"];
        if (!LoginSuccess) {
            LoginMessage = jsonData["message"];
            std::cout << "LoginSuccess: " << std::boolalpha << LoginSuccess << std::endl;
            std::cout << "LoginMessage: " << LoginMessage << std::endl;

            Authix::SendWebhook(
                webhookUrl,
                "Login Failed",
                SessionID,
                "Login Failed",
                "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nLicense Key: " + License + "\nMessage: " + LoginMessage,
                0xFF0000 // Red color
            );

            std::this_thread::sleep_for(std::chrono::seconds(2));
            return 3;
        }
        else {
            LoginData = jsonData["data"];
            std::cout << "LoginSuccess: " << std::boolalpha << LoginSuccess << std::endl;
        }
    }
    else {
        std::cout << "\nLoginResponse is 0" << std::endl;
        Authix::SendWebhook(
            webhookUrl,
            "Login Error",
            "",
            "Login Error",
            "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nLoginResponse is 0",
            0xFF0000 // Red color
        );

        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    // Decrypt Data Returned From Login Request
    std::string LoginDecryptedData = Authix::DecryptNextData(LoginData, NewIV);
    int LicenseExpiry;

    try {
        json jsonData = json::parse(LoginDecryptedData);
        LicenseExpiry = jsonData["expires_at"];
        std::cout << "LicenseExpiry: " << LicenseExpiry << std::endl;
        // Send success log to webhook with green color
        Authix::SendWebhook(
            webhookUrl,
            "Login Successful",
            SessionID,
            "Login Successful",
            "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nLicense Key: " + License + "\nLicense Expiry: " + std::to_string(LicenseExpiry),
            0x00FF00 // Green color
        );
    }
    catch (const std::exception& e) {
        std::cout << "\nError during the JSON parsing: " << e.what() << std::endl;
        Authix::SendWebhook(
            webhookUrl,
            "Login Decrypt Error",
            SessionID,
            "Login Decrypt Error",
            "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nError: " + e.what(),
            0xFF0000 // Red color
        );

        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    // GetFile Request
    std::string GetFileResponse = Authix::GetFile("FileNameHere", SessionID);
    bool GetFileSuccess;
    std::string GetFileData;
    std::string GetFileMessage;

    if (GetFileResponse.length() > 0) {
        json jsonData = json::parse(GetFileResponse);
        GetFileSuccess = jsonData["success"];
        if (!GetFileSuccess) {
            GetFileMessage = jsonData["message"];
            std::cout << "\nGetFileSuccess: " << std::boolalpha << GetFileSuccess << std::endl;
            std::cout << "GetFileMessage: " << GetFileMessage << std::endl;

            Authix::SendWebhook(
                webhookUrl,
                "Get File Failed",
                SessionID,
                "Get File Failed",
                "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nMessage: " + GetFileMessage,
                0xFF0000 // Red color
            );

            std::this_thread::sleep_for(std::chrono::seconds(2));
            return 3;
        }
        else {
            GetFileData = jsonData["data"];
            GetFileMessage = jsonData["message"];
            std::cout << "GetFileMessage: " << GetFileMessage << std::endl;
        }
    }
    else {
        std::cout << "\nGetFileResponse is 0" << std::endl;
        Authix::SendWebhook(
            webhookUrl,
            "Get File Error",
            SessionID,
            "Get File Error",
            "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nGetFileResponse is 0",
            0xFF0000 // Red color
        );

        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    std::cout << "GetFileData: " << GetFileData << std::endl;

    // Decrypt Data Returned From GetFile Request
    std::string GetFileDecryptedData = Authix::DecryptNextData(GetFileData, NewIV);
    std::cout << "GetFileDecryptedData: " << GetFileDecryptedData << std::endl;

    // Send log to webhook with green color
    Authix::SendWebhook(
        webhookUrl,
        "Get File Successful",
        SessionID,
        "Get File Successful",
        "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nFile Data: " + GetFileDecryptedData,
        0x00FF00 // Green color
    );

    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Send a LogMessage
    std::string LogMessageResponse = Authix::LogMessage("YourMessageHere", SessionID);
    bool LogMessageSuccess;
    std::string LogMessageMessage;

    if (LogMessageResponse.length() > 0) {
        json jsonData = json::parse(LogMessageResponse);
        LogMessageSuccess = jsonData["success"];
        if (!LogMessageSuccess) {
            LogMessageMessage = jsonData["message"];
            std::cout << "LogMessageSuccess: " << std::boolalpha << LogMessageSuccess << std::endl;
            std::cout << "LogMessageMessage: " << LogMessageMessage << std::endl;

            Authix::SendWebhook(
                webhookUrl,
                "Log Message Failed",
                SessionID,
                "Log Message Failed",
                "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nMessage: " + LogMessageMessage,
                0xFF0000 // Red color
            );

            std::this_thread::sleep_for(std::chrono::seconds(2));
            return 3;
        }
        else {
            std::cout << "LogMessageSuccess: " << std::boolalpha << LogMessageSuccess << std::endl;
        }
    }
    else {
        std::cout << "\nLogMessageResponse is 0" << std::endl;
        Authix::SendWebhook(
            webhookUrl,
            "Log Message Error",
            SessionID,
            "Log Message Error",
            "IP: " + ip + "\nVPN: " + (isVPN ? "Yes" : "No") + "\nLogMessageResponse is 0",
            0xFF0000 // Red color
        );

        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    return 0;
}

