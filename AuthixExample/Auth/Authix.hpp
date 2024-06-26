#ifndef AUTHIX_H
#define AUTHIX_H

#include "xorstr.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace Authix
{
	std::string InitSession();
	std::string DecryptInitData(std::string Data);

	std::string Login(std::string License, std::string Hwid, std::string SessionID);
	std::string GetVariable(std::string VariableName, std::string SessionID);
	std::string LogMessage(std::string Message, std::string SessionID);

	std::string DecryptNextData(std::string Data, std::string NewIV);
}

#endif // AUTHIX_H
