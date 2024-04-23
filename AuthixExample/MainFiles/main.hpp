#ifndef MAIN_H
#define MAIN_H

#include <Windows.h>
#include <iostream>
#include <format>
#include <random>
#include <sddl.h>

#include "../Auth/Authix.hpp"

char* ConvertToChar(const wchar_t* buffer)
{
    int size = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL);
    char* multiByteString = new char[size];
    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, multiByteString, size, NULL, NULL);

    return multiByteString;
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