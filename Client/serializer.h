#ifndef SERIALIZER_H
#define SERIALIZER_H


#include "protocol.h"

#include <vector>
#include <cstdint>


/** 
* @brief functions for serializing and deserializing the request and response
*/
namespace Serializer
{
	/**
	* @brief serializes the request
	*/
	std::vector<char> serializeRequest(const Request& request);
	
	/**
	* @brief Serializes the request's payload.
	*/
	std::vector<char> serializePayload(const Payload& payload, uint32_t payloadSize);

	/**
	* @brief Deserializes the response.
	*/
	Response deserializeResponse(const std::vector<char>& buffer);

	/** 
	* @breif Deserializes the response's payload.
	*/
	Payload deserializePayload(const std::vector<char>& buffer, uint16_t opCode);
}

#endif // SERIALIZER_H
