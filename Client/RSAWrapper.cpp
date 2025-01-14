#include "RSAWrapper.h"

#include <osrng.h>
#include <files.h>
#include <base64.h>
#include <filesystem>
#include <iostream>


RSAWrapper::RSAWrapper()
{
	if (!loadPrivateKey())
	{
		CryptoPP::AutoSeededRandomPool rng;
		_privateKey.Initialize(rng, RSA_KEY_LENGTH);
		savePrivateKey();
	}
	_publicKey.AssignFrom(_privateKey);
}

bool RSAWrapper::loadPrivateKey()
{
	if (!std::filesystem::exists(PRIVATE_KEY_FILE))
	{
		return false;
	}

	// Read the Base64-encoded private key from the file
	std::string base64Key;
	CryptoPP::FileSource file(PRIVATE_KEY_FILE.c_str(), true, new CryptoPP::StringSink(base64Key));

	// Decode the Base64 content
	std::string decodedKey;
	CryptoPP::StringSource(base64Key, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedKey)));

	// Use the decoded content to initialize the private key
	CryptoPP::StringSource ss(decodedKey, true);
	_privateKey.BERDecode(ss);
	
	return true;
}

void RSAWrapper::savePrivateKey() const
{
	CryptoPP::Base64Encoder encoder(new CryptoPP::FileSink(PRIVATE_KEY_FILE.c_str()), false);
	_privateKey.DEREncode(encoder);
	encoder.MessageEnd();
}

std::vector<char> RSAWrapper::decrypt(const std::vector<char>& cipher) const
{
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(_privateKey);
	std::string plaintext;
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size(), true,
		new CryptoPP::PK_DecryptorFilter(rng, decryptor,
			new CryptoPP::StringSink(plaintext)
		)
	);

	return std::vector<char>(plaintext.begin(), plaintext.end());
}


std::vector<char> RSAWrapper::getPublicKey() const
{
	std::string publicKeyStr;
	CryptoPP::StringSink ss(publicKeyStr);
	_publicKey.Save(ss);

	// Convert the string to a std::vector<char>
	std::vector<char> publicKey(publicKeyStr.begin(), publicKeyStr.end());
	return publicKey;
}

std::string RSAWrapper::getBase64PrivateKey()
{
	// Create a string to hold the DER encoded key
	std::string derEncodedKey;
	CryptoPP::StringSink derSink(derEncodedKey);
	_privateKey.DEREncode(derSink);

	// Create a string to hold the Base64 encoded key
	std::string base64EncodedKey;
	CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(base64EncodedKey), false);

	// Encode DER to Base64
	CryptoPP::StringSource ss(derEncodedKey, true, new CryptoPP::Redirector(encoder));
	encoder.MessageEnd();  // Ensure the encoder flushes its content

	return base64EncodedKey;
}
