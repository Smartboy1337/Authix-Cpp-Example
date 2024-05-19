#include "main.hpp"
// Put the solution config on Release!

int main()
{
	//
	// Init Session
	//
	std::string InitSessionResponse = Authix::InitSession();

	bool InitSessionSuccess;
	std::string InitSessionMessage;
	std::string InitSessionData;

	if (InitSessionResponse.length() > 0)
	{
		// Here we parse the response to check if fail or not, if not we get the data on a single string since we need to decrypt only "data" param
		json jsonData = json::parse(InitSessionResponse);
		InitSessionSuccess = jsonData[xorstr_("success")];
		if (!InitSessionSuccess)
		{
			InitSessionMessage = jsonData[xorstr_("message")];
			std::cout << xorstr_("InitSessionSuccess: ") << std::boolalpha << InitSessionSuccess << std::endl;
			std::cout << xorstr_("InitSessionMessage: ") << InitSessionMessage << std::endl;

			Sleep(2000);
			return 2;
		}
		else
		{
			InitSessionData = jsonData[xorstr_("data")];
		}
	}
	else
	{
		std::cout << xorstr_("\nInitSessionResponse is 0") << std::endl;
		Sleep(2000);
		return 1;
	}


	//
	// Decrypt Data Returned From Init Session
	//
	std::string InitSessionDecryptedData = Authix::DecryptInitData(InitSessionData);

	std::string SessionID;
	int Expires;
	std::string NewIV;

	// Here we parse the decrypted data and save each param that will be needed for later
	try 
	{
		json jsonData = json::parse(InitSessionDecryptedData);

		SessionID = jsonData[xorstr_("session_id")];
		Expires = jsonData[xorstr_("expires_at")];
		NewIV = jsonData[xorstr_("iv")];
	}
	catch (const std::exception& e) 
	{
		std::cout << xorstr_("\nError during the JSON parsing: ") << e.what() << std::endl;
	}


	//
	// Getting the hwid and the input key from the user
	//
	std::string License;
	std::cout << xorstr_("\nYour License --> ");
	std::cin >> License;
	std::cout << xorstr_("\n");

	// Grabbing the user HWID (in this case we use Windows SID)
	std::string UserHwid = GrabSID();


	//
	// Login Request
	//
	std::string LoginResponse = Authix::Login(License, UserHwid, SessionID);

	bool LoginSuccess;
	std::string LoginData;
	std::string LoginMessage;

	if (LoginResponse.length() > 0)
	{
		// Here we parse the response to check if fail or not, if not we get the data on a single string since we need to decrypt only "data" param
		json jsonData = json::parse(LoginResponse);
		LoginSuccess = jsonData[xorstr_("success")];
		if (!LoginSuccess)
		{
			LoginMessage = jsonData[xorstr_("message")];
			std::cout << xorstr_("LoginSuccess: ") << std::boolalpha << LoginSuccess << std::endl;
			std::cout << xorstr_("LoginMessage: ") << LoginMessage << std::endl;

			Sleep(2000);
			return 3;
		}
		else
		{
			LoginData = jsonData[xorstr_("data")];
			std::cout << xorstr_("LoginSuccess: ") << std::boolalpha << LoginSuccess << std::endl;
		}
	}
	else
	{
		std::cout << xorstr_("\LoginResponse is 0") << std::endl;
		Sleep(2000);
		return 1;
	}


	//
	// Decrypt Data Returned From Login Request
	//
	std::string LoginDecryptedData = Authix::DecryptNextData(LoginData, NewIV);

	int LicenseExpiry;
	try
	{
		json jsonData = json::parse(LoginDecryptedData);

		LicenseExpiry = jsonData[xorstr_("expires_at")];

		std::cout << xorstr_("LicenseExpiry: ") << LicenseExpiry << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cout << xorstr_("\nError during the JSON parsing: ") << e.what() << std::endl;
	}


	//
	// Here Your Code After Login...
	//
	std::cout << xorstr_("\nSuccessfully Logged in!\n") << std::endl;


	//
	// Send a LogMessage
	//
	std::string LogMessageResponse = Authix::LogMessage(xorstr_("YourMessageHere"), SessionID);

	bool LogMessageSuccess;
	std::string LogMessageMessage;

	if (LogMessageResponse.length() > 0)
	{
		// Here we parse the response to check if fail or not
		json jsonData = json::parse(LogMessageResponse);
		LogMessageSuccess = jsonData[xorstr_("success")];
		if (!LogMessageSuccess)
		{
			LogMessageMessage = jsonData[xorstr_("message")];
			std::cout << xorstr_("\nLogMessageSuccess: ") << std::boolalpha << LogMessageSuccess << std::endl;
			std::cout << xorstr_("LogMessageMessage: ") << LogMessageMessage << std::endl;

			Sleep(2000);
			return 3;
		}
		else
		{
			LogMessageMessage = jsonData[xorstr_("message")];
			std::cout << xorstr_("LogMessageMessage: ") << LogMessageMessage << std::endl;
		}
	}
	else
	{
		std::cout << xorstr_("\nLogMessageResponse is 0") << std::endl;
		Sleep(2000);
		return 1;
	}


	//
	// GetVariable Request
	//
	std::string GetVariableResponse = Authix::GetVariable(xorstr_("YourVariableName"), SessionID);

	bool GetVariableSuccess;
	std::string GetVariableData;
	std::string GetVariableMessage;

	if (GetVariableResponse.length() > 0)
	{
		// Here we parse the response to check if fail or not, if not we get the data on a single string since we need to decrypt only "data" param
		json jsonData = json::parse(GetVariableResponse);
		GetVariableSuccess = jsonData[xorstr_("success")];
		if (!GetVariableSuccess)
		{
			GetVariableMessage = jsonData[xorstr_("message")];
			std::cout << xorstr_("\nGetVariableSuccess: ") << std::boolalpha << GetVariableSuccess << std::endl;
			std::cout << xorstr_("GetVariableMessage: ") << GetVariableMessage << std::endl;

			Sleep(2000);
			return 3;
		}
		else
		{
			GetVariableData = jsonData[xorstr_("data")];
			std::cout << xorstr_("\nGetVariableSuccess: ") << std::boolalpha << GetVariableSuccess << std::endl;
		}
	}
	else
	{
		std::cout << xorstr_("\nGetVariableResponse is 0") << std::endl;
		Sleep(2000);
		return 1;
	}


	//
	// Decrypt Data Returned From GetVariable Request and Print the Variable
	//
	std::string GetVariableDecryptedData = Authix::DecryptNextData(GetVariableData, NewIV);
	std::cout << xorstr_("\nYour Variable: ") << GetVariableDecryptedData << std::endl;


	// TODO:
	// StreamFile/GetFile
	// Send Webhook Message


	Sleep(-1);

	return 0;
}
