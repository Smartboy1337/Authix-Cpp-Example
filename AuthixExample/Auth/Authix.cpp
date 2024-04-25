#include "Authix.hpp"
#include "Decryption.hpp"

std::string OwnerUUID = xorstr_("9be44ee9-d7b2-4703-bc7e-cd6e7332e19b");
std::string AppName = xorstr_("BwPaidTemp");
std::string AppSecretKey = xorstr_("092add00674a85f9231ee63f3d732e26445bb9a6bace6c35475769956f0e1fd4");

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

	std::string DecryptNextData(std::string Data, std::string NewIV)
	{
		std::string DecryptedData = Decryption::DecryptData(Data, AppSecretKey, NewIV);

		return DecryptedData;
	}
}