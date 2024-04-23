#include "Authix.hpp"
#include "Decryption.hpp"
#include "xorstr.hpp"


std::string PanelURL = xorstr_("https://panel.authix.cc/"); //Don't change that
std::string OwnerUUID = xorstr_("00000000000-0000-0000-0000-000000000000000"); //Can be found on your Dashboard
std::string AppName = xorstr_("Example"); //The name of your application, can be found on your Dashboard
std::string AppSecretKey = xorstr_("0000000000000000000000000000000000000000000000000000000000000000"); // AppSecret can be found on your Dashboard

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
		auto link = std::format("{}api/start", PanelURL);
		curl_easy_setopt(hnd, CURLOPT_URL, link.c_str());

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		Decryption::init_iv();

		auto command = std::format("{{\"owner_uuid\":\"{}\",\"application\":\"{}\",\"init_iv\":\"{}\"}}", OwnerUUID, AppName, ivKey);
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
		auto link = std::format("{}api/login", PanelURL);
		curl_easy_setopt(hnd, CURLOPT_URL, link.c_str());

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, (xorstr_("x-session-id: ") + SessionID).c_str());
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		auto command = std::format("{{\"license_key\":\"{}\",\"hwid\":\"{}\"}}", License, Hwid);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);

		return response_string;
	}
	std::string GetVariable(std::string VariableName, std::string SessionID)
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, xorstr_("POST"));
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		auto link = std::format("{}api/var", PanelURL);
		curl_easy_setopt(hnd, CURLOPT_URL, link.c_str());

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, xorstr_("accept: application/json"));
		headers = curl_slist_append(headers, (xorstr_("x-session-id: ") + SessionID).c_str());
		headers = curl_slist_append(headers, xorstr_("content-type: application/json"));
		headers = curl_slist_append(headers, xorstr_("User-Agent: AuthixExample"));
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		auto command = std::format("{{\"var_name\":\"{}\"}}", VariableName);
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