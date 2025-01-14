#ifndef AES_WRAPPER_H
#define AES_WRAPPER_H

#include <vector>


constexpr size_t AES_KEY_SIZE = 32; // 256 bits AES key.


/**
 * @brief AESWrapper class
 *
 * This class provides methods to encrypt and decrypt data using AES-CBC symmetric key.
 */
class AESWrapper
{
public:
	/**
	 * @brief Set the key for encryption and decryption.
	 *
	 * @param key the key to set
	 */
	void setKey(const std::vector<char>& key);

	/**
	 * @brief Encrypt the given plaintext using the key.
	 *
	 * @param plaintext the plaintext to encrypt
	 * @return the encrypted ciphertext
	 */
	std::vector<char> encrypt(const std::vector<char>& plaintext) const;

	/**
	 * @brief Decrypt the given ciphertext using the key.
	 *
	 * @param ciphertext the ciphertext to decrypt
	 * @return the decrypted plaintext
	 */
	std::vector<char> decrypt(const std::vector<char>& ciphertext) const;

private:
	std::vector<char> _key;
};

#endif // AES_WRAPPER_H