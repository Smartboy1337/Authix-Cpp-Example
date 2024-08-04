#include "Authix.hpp"
#include "Decryption.hpp"

std::string OwnerUUID = xorstr_("000000000000000000000000000");
std::string AppName = xorstr_("0000000000");
std::string AppSecretKey = xorstr_("0000000000000000000000000000000000000000000000000000000000000");

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output)
{
	size_t total_size = size * nmemb;
	output->append((char*)contents, total_size);

	return total_size;
}

namespace Authix
{
	std::string InitSession()
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, xorstr_("POST"));
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		curl_easy_setopt(hnd, CURLOPT_URL, xorstr_("https://api.authix.cc/start"));

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		Decryption::init_iv();

		std::string command = std::format(("{{\"owner_uuid\":\"{}\",\"application\":\"{}\",\"init_iv\":\"{}\"}}"), OwnerUUID, AppName, ivKey);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);
		
		return response_string;
	}
	std::string DecryptInitData(std::string Data)
	{
		std::string DecryptedData = Decryption::InitialDecryptData(Data, AppSecretKey);

		return DecryptedData;
	}

	std::string Login(std::string License, std::string Hwid, std::string SessionID)
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, xorstr_("POST"));
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		curl_easy_setopt(hnd, CURLOPT_URL, xorstr_("https://api.authix.cc/login"));

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, (xorstr_("x-session-id: ") + SessionID).c_str());
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		auto command = std::format(("{{\"license_key\":\"{}\",\"hwid\":\"{}\"}}"), License, Hwid);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);

		return response_string;
	}
	std::string GetFile(std::string FileName, std::string SessionID)
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, xorstr_("POST"));
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		curl_easy_setopt(hnd, CURLOPT_URL, xorstr_("https://api.authix.cc/file")); 

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, (xorstr_("x-session-id: ") + SessionID).c_str());
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		auto command = std::format(("{{\"file_name\":\"{}\"}}"), FileName);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);

		return response_string;
	}
	std::string GetVariable(std::string VariableName, std::string SessionID)
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, xorstr_("POST"));
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		curl_easy_setopt(hnd, CURLOPT_URL, xorstr_("https://api.authix.cc/var"));

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, (xorstr_("x-session-id: ") + SessionID).c_str());
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		auto command = std::format(("{{\"var_name\":\"{}\"}}"), VariableName);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);

		return response_string;
	}
	std::string LogMessage(std::string Message, std::string SessionID)
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, xorstr_("POST"));
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		curl_easy_setopt(hnd, CURLOPT_URL, xorstr_("https://api.authix.cc/log"));

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, (xorstr_("x-session-id: ") + SessionID).c_str());
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		auto command = std::format(("{{\"message\":\"{}\"}}"), Message);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);

		return response_string;
	}

	std::string DecryptNextData(std::string Data, std::string NewIV)
	{
		std::string DecryptedData = Decryption::DecryptData(Data, AppSecretKey, NewIV);

		return DecryptedData;
	}
}
