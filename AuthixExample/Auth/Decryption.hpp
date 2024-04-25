#ifndef DECRYPTION_H
#define DECRYPTION_H

#include <Windows.h>
#include <iostream>
#include <random>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

std::string ivKey;

namespace Decryption
{
	static std::string encrypt_string(const std::string& plain_text, const std::string& key, const std::string& iv) {
		std::string cipher_text;

		try {
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
			encryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

			CryptoPP::StringSource encryptor(plain_text, true,
				new CryptoPP::StreamTransformationFilter(encryption,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(cipher_text),
						false
					)
				)
			);
		}
		catch (CryptoPP::Exception& ex) {
			MessageBoxA(0, ex.what(), xorstr_("Authix"), MB_ICONERROR);
			exit(0);
		}
		return cipher_text;
	}

	static std::string decrypt_string(const std::string& cipher_text, const std::string& key, const std::string& iv) {
		std::string plain_text;

		try {
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
			decryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

			CryptoPP::StringSource decryptor(cipher_text, true,
				new CryptoPP::HexDecoder(
					new CryptoPP::StreamTransformationFilter(decryption,
						new CryptoPP::StringSink(plain_text)
					)
				)
			);
		}
		catch (CryptoPP::Exception& ex) {
			MessageBoxA(0, xorstr_("Invalid API/Encryption key"), xorstr_("Authix"), MB_ICONERROR);
			exit(0);
		}
		return plain_text;
	}

	static std::string md5(const std::string& plain_text) {
		std::string hashed_text;
		CryptoPP::MD5 hash;

		try {
			CryptoPP::StringSource hashing(plain_text, true,
				new CryptoPP::HashFilter(hash,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(hashed_text),
						false
					)
				)
			);
		}
		catch (CryptoPP::Exception& ex) {
			MessageBoxA(0, ex.what(), xorstr_("Authix"), MB_ICONERROR);
			exit(0);
		}

		return hashed_text;
	}

	static std::string sha256(const std::string& plain_text) {
		std::string hashed_text;
		CryptoPP::SHA256 hash;

		try {
			CryptoPP::StringSource hashing(plain_text, true,
				new CryptoPP::HashFilter(hash,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(hashed_text),
						false
					)
				)
			);
		}
		catch (CryptoPP::Exception& ex) {
			MessageBoxA(0, ex.what(), xorstr_("Authix"), MB_ICONERROR);
			exit(0);
		}

		return hashed_text;
	}

	static std::string hex_encode(const std::string& plain_text) {
		std::string encoded_text;

		try {
			CryptoPP::StringSource encoding(plain_text, true,
				new CryptoPP::HexEncoder(
					new CryptoPP::StringSink(encoded_text),
					false
				)
			);
		}
		catch (CryptoPP::Exception& ex) {
			MessageBoxA(0, ex.what(), xorstr_("Authix"), MB_ICONERROR);
			exit(0);
		}

		return encoded_text;
	}

	static std::string hex_decode(const std::string& encoded_text) {
		std::string out;

		try {
			CryptoPP::StringSource decoding(encoded_text, true,
				new CryptoPP::HexDecoder(
					new CryptoPP::StringSink(out)
				)
			);
		}
		catch (CryptoPP::Exception& ex) {
			MessageBoxA(0, ex.what(), xorstr_("Authix"), MB_ICONERROR);
			exit(0);
		}

		return out;
	}

	static std::string encrypt(std::string message, std::string enc_key, std::string iv) {
		enc_key = sha256(enc_key).substr(0, 32);

		iv = sha256(iv).substr(0, 16);

		return encrypt_string(message, enc_key, iv);
	}

	static std::string Initialdecrypt(std::string message, std::string enc_key, std::string iv) {
		iv = sha256(md5(iv)).substr(0, 32);
		iv = hex_decode(iv);

		return decrypt_string(message, hex_decode(enc_key), iv);
	}

	std::string InitialDecryptData(std::string encryptedData, std::string secretKeyHex)
	{
		std::string decryptedData;
		try
		{
			decryptedData = Initialdecrypt(encryptedData, secretKeyHex, ivKey);
		}
		catch (const CryptoPP::Exception& e)
		{
			std::cerr << xorstr_("Exception caught: ") << e.what() << std::endl;
		}

		return decryptedData;
	}

	std::string DecryptData(std::string encryptedData, std::string secretKeyHex, std::string iv)
	{
		std::string decryptedData;
		try
		{
			decryptedData = decrypt_string(encryptedData, hex_decode(secretKeyHex), hex_decode(iv));
		}
		catch (const CryptoPP::Exception& e)
		{
			std::cerr << xorstr_("Exception caught: ") << e.what() << std::endl;
		}

		return decryptedData;
	}

	int RandomNumber()
	{
		std::mt19937 gen(std::time(nullptr));
		std::uniform_int_distribution<> distrib(35, 99);

		return distrib(gen);
	}

	void init_iv()
	{
		std::string str = xorstr_("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
		std::string newstr;
		int pos;

		std::srand(static_cast<unsigned int>(std::time(0)));

		while (newstr.size() != RandomNumber())
		{
			pos = rand() % str.size();
			newstr += str.substr(pos, 1);
		}

		ivKey = newstr;
		//return newstr;
	}
}

#endif // DECRYPTION_H