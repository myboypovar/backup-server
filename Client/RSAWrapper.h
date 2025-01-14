#ifndef RSAWRAPPER_H
#define RSAWRAPPER_H


#include <rsa.h>

#include <string>
#include <vector>


constexpr size_t RSA_KEY_LENGTH = 1024;
constexpr size_t RSA_KEY_SIZE = 160;
const std::string PRIVATE_KEY_FILE = "priv.key";

/**
 * @brief RSAWrapper class
 *
 * This class provides methods to load, save, and decrypt data using RSA encryption.
 */
class RSAWrapper
{
public:
	/**
	 * @brief Constructor that generates a new RSA key pair if the private key file does not exist.
	 * Otherwise, it loads the private key from the file.
	 */
	RSAWrapper();
	
	/**
	 * @brief Load the private key from the file.
	 *
	 * @return true if the private key was loaded successfully; false if the private key file does not exist.
	 */
	bool loadPrivateKey();

	/**
	 * @brief Save the private key to the file.
	 */
	void savePrivateKey() const;

	/**
	 * @brief Decrypt the given cipher using the private key.
	 *
	 * @param cipher the cipher to decrypt
	 * @return the decrypted plaintext
	 */
	std::vector<char> decrypt(const std::vector<char>& cipher) const;

	/**
	 * @brief Get the public key.
	 *
	 * @return the public key
	 */
	std::vector<char> getPublicKey() const;

	/**
	 * @brief Get the base64-encoded private key.
	 *
	 * @return the base64-encoded private key
	 */
	std::string getBase64PrivateKey();

private:
	CryptoPP::RSA::PrivateKey _privateKey;
	CryptoPP::RSA::PublicKey _publicKey;
};


#endif // RSAWRAPPER_H
