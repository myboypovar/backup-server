#ifndef PROTOCOL_H
#define PROTOCOL_H


#include "payload.h"

#include <string>
#include <variant>
#include <cstdint>


constexpr uint8_t CLIENT_VERSION = 3;
constexpr size_t CLIENT_ID_SIZE = 16;

/**
* @brief A union for the dynamic payload.
*/
using Payload = std::variant<NameRequest
	, SendPublickKeyRequest
	, SendFileRequest
	, CRCRequest
	, ClientIDResponse
	, SymmetricKeyResponse
	, FileResponse
	, ErrorResponse>;

/**
* @brief A struct for the request.
*/
struct Request
{
	std::vector<char> clientID;
	uint8_t version;
	uint16_t opCode;
	uint32_t payloadSize;
	Payload payload;
};

/**
* @brief A struct for the response.
*/
struct Response
{
	uint8_t version;
	uint16_t opCode;
	uint32_t payloadSize;
	Payload payload;
};

/**
* @brief An enum class for the request code.
*/
enum class RequestCode : uint16_t
{
	REQUEST_REGISTER = 825,
	REQUEST_PUBLIC_KEY = 826,
	REQUEST_LOGIN = 827,
	REQUEST_SEND_FILE = 828,

	REQUEST_CRC_VALID = 900,
	REQUEST_CRC_INVALID = 901,
	REQUEST_CRC_FATAL = 902
};

/**
* @brief An enum class for the response code.
*/
enum class ResponseCode : uint16_t
{
	RESPONSE_REGISTRATION = 1600,
	RESPONSE_REGISTRATION_FAILED = 1601,
	RESPONSE_AES_KEY = 1602,
	RESPONSE_FILE_VALID = 1603,
	RESPONSE_ACK = 1604,
	RESPONSE_LOGIN = 1605,
	RESPONSE_LOGIN_FAILED = 1606,
	RESPONSE_ERROR = 1607
};

#endif
