#include "AESWrapper.h"
#include "exceptions.h"

#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <cassert>



void AESWrapper::setKey(const std::vector<char>& key)
{
	// AES key size is 32 bytes (256 bits)
	if (key.size() != AES_KEY_SIZE)
	{
		throw AESWrapperError("Invalid AES key length");
	}
	_key = key;
}


std::vector<char> AESWrapper::encrypt(const std::vector<char>& plaintext) const
{
  
    // Initialize the zeroed IV (AES block size is 16 bytes)
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

    // Create AES encryption object in CBC mode
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor(
        reinterpret_cast<const CryptoPP::byte*>(_key.data()), _key.size(), iv);

    std::string ciphertext;

    // Encrypt the plaintext using CBC mode with PKCS padding
    CryptoPP::StringSource ss(
        reinterpret_cast<const CryptoPP::byte*>(plaintext.data()), plaintext.size(), true,
        new CryptoPP::StreamTransformationFilter(
            encryptor, new CryptoPP::StringSink(ciphertext)
        )
    );

    // Convert ciphertext to std::vector<char> for binary data handling
    return std::vector<char>(ciphertext.begin(), ciphertext.end());
}


std::vector<char> AESWrapper::decrypt(const std::vector<char>& ciphertext) const
{
	// Initialize the zeroed IV (AES block size is 16 bytes)
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

	// Create AES decryption object in CBC mode
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor(
		reinterpret_cast<const CryptoPP::byte*>(_key.data()), _key.size(), iv);

	std::string plaintext;

	// Decrypt the ciphertext using CBC mode with PKCS padding
	CryptoPP::StringSource ss(
		reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), ciphertext.size(), true,
		new CryptoPP::StreamTransformationFilter(
			decryptor, new CryptoPP::StringSink(plaintext)
		)
	);

	// Convert plaintext to std::vector<char> for binary data handling
	return std::vector<char>(plaintext.begin(), plaintext.end());
}
