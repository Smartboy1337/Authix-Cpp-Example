#include "Authix.hpp"
#include "Decryption.hpp"
#include <nlohmann/json.hpp>

std::string OwnerUUID = xorstr_("0000000-0000-0000-0000000000000"); // OwnerUUID from your dashboard
std::string AppName = xorstr_("Example"); //Application name from your dashboard
std::string AppSecretKey = xorstr_("000000000000000000000000000000000000000000000000000000000000"); // AppSecretKey from your dashboard
std::string Webhookname = "Example"; // Webhook name for logs

std::string webhookUrl = "https://api.authix.cc/webhook?webhook_name=" + Webhookname; //Don't change

// Function to handle curl write callback
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output)
{
    size_t total_size = size * nmemb;
    output->append((char*)contents, total_size);
    return total_size;
}

// Definitions of Authix functions
namespace Authix
{
    // Struct for InitSession request
    struct InitSessionRequest {
        std::string owner_uuid;
        std::string application;
        std::string init_iv;
    };

    void to_json(nlohmann::json& j, const InitSessionRequest& req) {
        j = nlohmann::json{
            {"owner_uuid", req.owner_uuid},
            {"application", req.application},
            {"init_iv", req.init_iv}
        };
    }

    std::string InitSession()
    {
        CURL* hnd = curl_easy_init();
        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
        curl_easy_setopt(hnd, CURLOPT_URL, "https://api.authix.cc/start");

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "accept: application/json");
        headers = curl_slist_append(headers, "content-type: application/json");
        headers = curl_slist_append(headers, "User-Agent: AuthixExample");
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

        std::string response_string;
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

        Decryption::init_iv();

        InitSessionRequest req{ OwnerUUID, AppName, ivKey };
        nlohmann::json j = req;
        std::string command = j.dump();

        curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
        curl_easy_perform(hnd);

        curl_easy_cleanup(hnd);
        curl_slist_free_all(headers);

        return response_string;
    }

    std::string DecryptInitData(std::string Data)
    {
        std::string DecryptedData = Decryption::InitialDecryptData(Data, AppSecretKey);
        return DecryptedData;
    }

    // Struct for Login request
    struct LoginRequest {
        std::string license_key;
        std::string hwid;
    };

    void to_json(nlohmann::json& j, const LoginRequest& req) {
        j = nlohmann::json{
            {"license_key", req.license_key},
            {"hwid", req.hwid}
        };
    }


    std::string Login(std::string License, std::string Hwid, std::string SessionID)
    {
        CURL* hnd = curl_easy_init();
        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
        curl_easy_setopt(hnd, CURLOPT_URL, "https://api.authix.cc/login");

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "accept: application/json");
        headers = curl_slist_append(headers, ("x-session-id: " + SessionID).c_str());
        headers = curl_slist_append(headers, "content-type: application/json");
        headers = curl_slist_append(headers, "User-Agent: AuthixExample");
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

        std::string response_string;
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

        auto command = std::format(R"({{"license_key":"{}","hwid":"{}"}})", License, Hwid);
        curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
        curl_easy_perform(hnd);

        curl_easy_cleanup(hnd);
        curl_slist_free_all(headers);

        return response_string;
    }

    // Struct for GetFile request
    struct GetFileRequest {
        std::string file_name;
    };

    void to_json(nlohmann::json& j, const GetFileRequest& req) {
        j = nlohmann::json{
            {"file_name", req.file_name}
        };
    }

    std::string GetFile(std::string FileName, std::string SessionID)
    {
        CURL* hnd = curl_easy_init();
        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
        curl_easy_setopt(hnd, CURLOPT_URL, "https://api.authix.cc/file");

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "accept: application/json");
        headers = curl_slist_append(headers, ("x-session-id: " + SessionID).c_str());
        headers = curl_slist_append(headers, "content-type: application/json");
        headers = curl_slist_append(headers, "User-Agent: AuthixExample");
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

        std::string response_string;
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

        GetFileRequest req{ FileName };
        nlohmann::json j = req;
        std::string command = j.dump();

        curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
        curl_easy_perform(hnd);

        curl_easy_cleanup(hnd);
        curl_slist_free_all(headers);

        return response_string;
    }

    // Struct for GetVariable request
    struct GetVariableRequest {
        std::string var_name;
    };

    void to_json(nlohmann::json& j, const GetVariableRequest& req) {
        j = nlohmann::json{
            {"var_name", req.var_name}
        };
    }

    std::string GetVariable(std::string VariableName, std::string SessionID)
    {
        CURL* hnd = curl_easy_init();
        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
        curl_easy_setopt(hnd, CURLOPT_URL, "https://api.authix.cc/var");

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "accept: application/json");
        headers = curl_slist_append(headers, ("x-session-id: " + SessionID).c_str());
        headers = curl_slist_append(headers, "content-type: application/json");
        headers = curl_slist_append(headers, "User-Agent: AuthixExample");
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

        std::string response_string;
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

        GetVariableRequest req{ VariableName };
        nlohmann::json j = req;
        std::string command = j.dump();

        curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
        curl_easy_perform(hnd);

        curl_easy_cleanup(hnd);
        curl_slist_free_all(headers);

        return response_string;
    }

    // Struct for LogMessage request
    struct LogMessageRequest {
        std::string message;
    };

    void to_json(nlohmann::json& j, const LogMessageRequest& req) {
        j = nlohmann::json{
            {"message", req.message}
        };
    }

    std::string LogMessage(std::string Message, std::string SessionID)
    {
        CURL* hnd = curl_easy_init();
        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
        curl_easy_setopt(hnd, CURLOPT_URL, "https://api.authix.cc/log");

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "accept: application/json");
        headers = curl_slist_append(headers, ("x-session-id: " + SessionID).c_str());
        headers = curl_slist_append(headers, "content-type: application/json");
        headers = curl_slist_append(headers, "User-Agent: AuthixExample");
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

        std::string response_string;
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

        LogMessageRequest req{ Message };
        nlohmann::json j = req;
        std::string command = j.dump();

        curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
        curl_easy_perform(hnd);

        curl_easy_cleanup(hnd);
        curl_slist_free_all(headers);

        return response_string;
    }

    std::string SendWebhook(const std::string& webhookUrl, const std::string& Message,
        const std::string& SessionID, const std::string& title,
        const std::string& description, int color)
    {
        CURL* hnd = curl_easy_init();
        if (!hnd) {
            std::cerr << "Error: Failed to initialize curl." << std::endl;
            return "";
        }

        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(hnd, CURLOPT_URL, webhookUrl.c_str());

        // Set headers
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        if (!SessionID.empty()) {
            headers = curl_slist_append(headers, ("x-session-id: " + SessionID).c_str());
        }
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "User-Agent: AuthixExample");
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

        // Set response handling
        std::string response_string;
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

        nlohmann::json payload;

        if (!title.empty() || !description.empty() || color != 0) {
            // Creating JSON payload for embed
            nlohmann::json embed;
            if (!title.empty()) embed["title"] = title;
            if (!description.empty()) embed["description"] = description;
            if (color != 0) embed["color"] = color;

            payload["embeds"] = nlohmann::json::array({ embed });
        }
        else {
            // Creating JSON payload for a simple message
            payload["content"] = Message;
        }

        std::string payload_str = payload.dump();
        curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, payload_str.c_str());

        // Perform the request
        CURLcode res = curl_easy_perform(hnd);

        // Error handling
        if (res != CURLE_OK) {
            std::cerr << "Error: curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        // Cleanup
        curl_easy_cleanup(hnd);
        curl_slist_free_all(headers);

        return response_string;
    }

    std::string DecryptNextData(std::string Data, std::string NewIV)
    {
        std::string DecryptedData = Decryption::DecryptData(Data, AppSecretKey, NewIV);
        return DecryptedData;
    }
}
