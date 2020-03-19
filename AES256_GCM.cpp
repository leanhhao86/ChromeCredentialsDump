#include "everything.h"

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#ifndef CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_DEFAULT_NO_DLL 1
#endif

#ifndef CRYPTOPP_ENABLE_NAMESPACE_WEAK
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#endif

/*
#ifdef _DEBUG

#ifndef x64
#pragma comment(lib, "cryptopp561/Win32/Output/Debug/cryptlib.lib")
#else
#pragma comment(lib, "cryptopp561/x64/Output/Debug/cryptlib.lib")
#endif
#else
#ifndef x64
#pragma comment(lib, "cryptopp561/Win32/Output/Release/cryptlib.lib")
#else
#pragma comment(lib, "cryptopp561/x64/Output/Release/cryptlib.lib")
#endif
#endif
*/
// Crypto++ Include

#include "cryptopp820/pch.h"
#include "cryptopp820/files.h"
#include "cryptopp820/default.h"
#include "cryptopp820/base64.h"
#include "cryptopp820/osrng.h"

//AES
#include "cryptopp820/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp820/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp820/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp820/aes.h"
using CryptoPP::AES;

#include "cryptopp820/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <iostream>
#include <string>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

static inline RandomNumberGenerator& PSRNG(void);
static inline RandomNumberGenerator& PSRNG(void)
{
	static AutoSeededRandomPool rng;
	rng.Reseed();
	return rng;
}

bool decrypt_aes256_gcm(const char* aesKey, const char* aesIV,
	const char* inBase64Text, char** outDecrypted, int& dataLength);
void Base64Decode(const std::string& inString, std::string& outString);
void HexDecode(const std::string& inString, std::string& outString);

static std::string m_ErrorMessage;


bool decrypt_aes256_gcm(const char* aesKey, const char* aesIV,
	const char* inBase64Text, char** outDecrypted, int& dataLength)
{
	bool bR = false;
	std::string outText;
	std::string pszDecodedText;
	Base64Decode(inBase64Text, pszDecodedText);

	if (strlen(aesKey) > 31 && strlen(aesIV) > 15)
	{
		try
		{
			GCM< AES >::Decryption aesDecryption;
			aesDecryption.SetKeyWithIV(reinterpret_cast<const byte*>(aesKey),
				AES::MAX_KEYLENGTH, reinterpret_cast<const byte*>(aesIV), AES::BLOCKSIZE);
			AuthenticatedDecryptionFilter df(aesDecryption, new StringSink(outText));

			StringSource(pszDecodedText, true,
				new Redirector(df /*, PASS_EVERYTHING */)
			); // StringSource

			bR = df.GetLastResult();

			dataLength = outText.length();
			if (outText.length() > 0)
			{
				if (*outDecrypted) free(*outDecrypted);
				*outDecrypted = (char*)malloc(dataLength + 1);
				memset(*outDecrypted, '\0', dataLength + 1);
				memcpy(*outDecrypted, outText.c_str(), dataLength);

				bR = true;
			}
			else
			{
				m_ErrorMessage.append("Decryption Failed");
			}
		}
		catch (CryptoPP::HashVerificationFilter::HashVerificationFailed & e)
		{
			m_ErrorMessage.append(e.what());
		}
		catch (CryptoPP::InvalidArgument & e)
		{
			m_ErrorMessage.append(e.what());
		}
		catch (CryptoPP::Exception & e)
		{
			m_ErrorMessage.append(e.what());
		}
	}
	else
	{
		m_ErrorMessage.append("AES Key or IV cannot be empty");
	}

	return bR;
}

void Base64Decode(const std::string& inString, std::string& outString)
{
	StringSource(inString, true, new Base64Decoder(new StringSink(outString)));
}

void HexDecode(const std::string& inString, std::string& outString)
{
	StringSource(inString, true, new HexDecoder(new StringSink(outString)));
}