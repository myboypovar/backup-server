#ifndef PAYLOAD_H
#define PAYLOAD_H


#include <string>
#include <vector>
#include <cstdint>


constexpr size_t PUBLIC_KEY_SIZE = 160;
constexpr size_t NAME_SIZE = 255;
constexpr size_t FILE_NAME_SIZE = 255;
constexpr size_t CONTENT_SIZE = 4;
constexpr size_t ORIGINAL_FILE_SIZE = 4;
constexpr size_t PACKET_NUMBER_SIZE = 2;
constexpr size_t TOTAL_PACKETS_SIZE = 2;
constexpr size_t CRC_SIZE = 4;


/**
 * @struct	NameRequest
 *
 * @brief	A name request.
 *
 * This struct represents a payload that contains a username.
*/
struct NameRequest
{
	std::string name;
};


/**
 * @struct	SendPublickKeyRequest
 *
 * @brief	A send publick key request.
 *
 * This struct represents a payload that contains a username and a public key.
*/
struct SendPublickKeyRequest
{
	std::string name;
	std::vector<char> publicKey;
};


/**
 * @struct	SendFileRequest
 *
 * @brief	A send file request.
 *
 * This struct represents a payload that contains the metadata of a file.
*/
struct SendFileRequest
{
	uint32_t contentSize;
	uint32_t originalFileSize;
	uint16_t packetNumber;
	uint16_t totalPackets;
	std::string fileName;
	std::vector<char> content;  // for binary data
};


/**
 * @struct	CRCRequest
 *
 * @brief	A CRC request.
 *
 * This struct represents a payload that contains the name of a file.
*/
struct CRCRequest
{
	std::string fileName;
};


/**
 * @struct	ClientIDResponse
 *
 * @brief	A client identifier response.
 *
 * This struct represents a payload that contains a client identifier.
*/
struct ClientIDResponse
{
	std::vector<char> clientID;
};


/**
 * @struct	SymmetricKeyResponse
 *
 * @brief	A symmetric key response.
 *
 * This struct represents a payload that contains a client identifier and a symmetric key.
*/
struct SymmetricKeyResponse
{
	std::vector<char> clientID;
	std::vector<char> symmetricKey;
};


/**
 * @struct	FileResponse
 *
 * @brief	A file response.
 *
 * This struct represents a payload that contains the metadata of a file.
*/
struct FileResponse
{
	std::vector<char> clientID;
	uint32_t contentSize;
	std::string fileName;
	uint32_t crc;
};


/**
 * @struct	ErrorResponse
 *
 * @brief	An error response.
 *
 * This struct represents an error from the server.
*/
struct ErrorResponse
{
};

#endif // PAYLOAD_H
