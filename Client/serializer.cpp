#include "serializer.h"
#include "endian.h"
#include "exceptions.h"

#include <cstring>



std::vector<char> Serializer::serializeRequest(const Request& request)
{
	// Calculate the total size needed for serialization
	size_t totalSize = CLIENT_ID_SIZE + sizeof(request.version) + sizeof(request.opCode) + sizeof(request.payloadSize) + request.payloadSize;
	std::vector<char> buffer(totalSize,'\0');

	uint8_t version = request.version;
	uint16_t opCode = request.opCode;
	uint32_t payloadSize = request.payloadSize;

	// Convert the request members to little endian if necessary
	if (EndianConverter::isBigEndian())
	{
		// Convert the request members to little endian
		EndianConverter::toLittleEndian(version);
		EndianConverter::toLittleEndian(opCode);
		EndianConverter::toLittleEndian(payloadSize);
	}

	size_t offset = 0;

	// Serialize the request header members
	std::memcpy(buffer.data() + offset, request.clientID.data(), CLIENT_ID_SIZE);
	offset += CLIENT_ID_SIZE;
	std::memcpy(buffer.data() + offset, &version, sizeof(version));
	offset += sizeof(version);
	std::memcpy(buffer.data() + offset, &opCode, sizeof(opCode));
	offset += sizeof(opCode);
	std::memcpy(buffer.data() + offset, &payloadSize, sizeof(payloadSize));
	offset += sizeof(payloadSize);

	// Serialize the payload
	auto payloadData = serializePayload(request.payload, request.payloadSize);
	std::memcpy(buffer.data() + offset, payloadData.data(), payloadData.size());
	
	return buffer;
}

// Helper functions for serialization
std::vector<char> serializeNameRequest(const NameRequest& p, uint32_t payloadSize)
{
	std::vector<char> buffer(payloadSize,'\0');
	std::memcpy(buffer.data(), p.name.c_str(), p.name.size());
	return buffer;
}

std::vector<char> serializeSendPublicKeyRequest(const SendPublickKeyRequest& p, uint32_t payloadSize)
{
	std::vector<char> buffer(payloadSize,'\0');
	std::memcpy(buffer.data(), p.name.c_str(), p.name.size());
	std::memcpy(buffer.data() + NAME_SIZE, p.publicKey.data(), PUBLIC_KEY_SIZE);
	return buffer;
}

std::vector<char> serializeSendFileRequest(const SendFileRequest& p, uint32_t payloadSize)
{
	std::vector<char> buffer(payloadSize,'\0');
	size_t offset = 0;

	uint32_t contentSize = p.contentSize;
	uint32_t originalFileSize = p.originalFileSize;
	uint16_t packetNumber = p.packetNumber;
	uint16_t totalPackets = p.totalPackets;

	if (EndianConverter::isBigEndian()) 
	{
		EndianConverter::toLittleEndian(contentSize);
		EndianConverter::toLittleEndian(originalFileSize);
		EndianConverter::toLittleEndian(packetNumber);
		EndianConverter::toLittleEndian(totalPackets);
	}

	std::memcpy(buffer.data() + offset, &contentSize, CONTENT_SIZE);
	offset += CONTENT_SIZE;
	std::memcpy(buffer.data() + offset, &originalFileSize, ORIGINAL_FILE_SIZE);
	offset += ORIGINAL_FILE_SIZE;
	std::memcpy(buffer.data() + offset, &packetNumber, PACKET_NUMBER_SIZE);
	offset += PACKET_NUMBER_SIZE;
	std::memcpy(buffer.data() + offset, &totalPackets, TOTAL_PACKETS_SIZE);
	offset += TOTAL_PACKETS_SIZE;
	std::memcpy(buffer.data() + offset, p.fileName.c_str(), p.fileName.size());
	offset += FILE_NAME_SIZE;
	std::memcpy(buffer.data() + offset, p.content.data(), p.contentSize);

	return buffer;
}

std::vector<char> serializeCRCRequest(const CRCRequest& p, uint32_t payloadSize)
{
	std::vector<char> buffer(payloadSize);
	std::memcpy(buffer.data(), p.fileName.c_str(), p.fileName.size());
	return buffer;
}

std::vector<char> Serializer::serializePayload(const Payload& payload, uint32_t payloadSize)
{
	return std::visit([payloadSize](const auto& p) -> std::vector<char>
		{
		using T = std::decay_t<decltype(p)>;
		if constexpr (std::is_same_v<T, NameRequest>)
		{
			return serializeNameRequest(p, payloadSize);
		}
		else if constexpr (std::is_same_v<T, SendPublickKeyRequest>)
		{
			return serializeSendPublicKeyRequest(p, payloadSize);
		}
		else if constexpr (std::is_same_v<T, SendFileRequest>)
		{
			return serializeSendFileRequest(p, payloadSize);
		}
		else if constexpr (std::is_same_v<T, CRCRequest>)
		{
			return serializeCRCRequest(p, payloadSize);
		}
		else
		{
			throw SerializationError("Unsupported payload type");
		}
		}, payload);
}

Response Serializer::deserializeResponse(const std::vector<char>& buffer)
{
	if (buffer.size() < sizeof(Response::version) + sizeof(Response::opCode) + sizeof(Response::payloadSize))
	{
		throw SerializationError("Response serialization error.");
	}
	// Deserialize the response from the buffer
	Response response;

	// Copy each member from the buffer sequentially
	size_t offset = 0;

	// Copy version
	std::memcpy(&response.version, buffer.data() + offset, sizeof(response.version));
	offset += sizeof(response.version);

	// Copy opCode
	std::memcpy(&response.opCode, buffer.data() + offset, sizeof(response.opCode));
	offset += sizeof(response.opCode);

	// Copy payload size
	std::memcpy(&response.payloadSize, buffer.data() + offset, sizeof(response.payloadSize));
	offset += sizeof(response.payloadSize);

	// Copy payload
	auto payloadData = std::vector<char>(buffer.begin() + offset, buffer.end());
	
	response.payload = deserializePayload(payloadData, response.opCode);
	
	return response;
}


Payload Serializer::deserializePayload(const std::vector<char>& buffer, uint16_t opCode)
{
	auto code = static_cast<ResponseCode>(opCode);

	if (code == ResponseCode::RESPONSE_REGISTRATION || code == ResponseCode::RESPONSE_ACK || code == ResponseCode::RESPONSE_LOGIN_FAILED)
	{
		ClientIDResponse clientIDResponse;
		clientIDResponse.clientID.resize(CLIENT_ID_SIZE);
		std::copy(buffer.begin(), buffer.begin() + CLIENT_ID_SIZE, clientIDResponse.clientID.begin());
		return clientIDResponse;
	}
	else if (code == ResponseCode::RESPONSE_AES_KEY || code == ResponseCode::RESPONSE_LOGIN)
	{
		SymmetricKeyResponse symmetricKeyResponse;
		symmetricKeyResponse.clientID.resize(CLIENT_ID_SIZE);
		symmetricKeyResponse.symmetricKey.resize(buffer.size() - CLIENT_ID_SIZE);
		std::copy(buffer.begin(), buffer.begin() + CLIENT_ID_SIZE, symmetricKeyResponse.clientID.begin());
		std::copy(buffer.begin() + CLIENT_ID_SIZE, buffer.end(), symmetricKeyResponse.symmetricKey.begin());
		return symmetricKeyResponse;
	}
	else if (code == ResponseCode::RESPONSE_FILE_VALID)
	{
		FileResponse fileResponse;
		size_t offset = 0;
		fileResponse.clientID.resize(CLIENT_ID_SIZE);
		std::copy(buffer.begin() + offset, buffer.begin() + offset + CLIENT_ID_SIZE, fileResponse.clientID.begin());
		offset += CLIENT_ID_SIZE;
		std::memcpy(&fileResponse.contentSize, buffer.data() + offset, CONTENT_SIZE);
		offset += CONTENT_SIZE;
		fileResponse.fileName.resize(FILE_NAME_SIZE);
		std::copy(buffer.begin() + offset, buffer.begin() + offset + FILE_NAME_SIZE, fileResponse.fileName.begin());
		offset += FILE_NAME_SIZE;
		std::memcpy(&fileResponse.crc, buffer.data() + offset, CRC_SIZE);
		return fileResponse;
	}
	else if (code == ResponseCode::RESPONSE_REGISTRATION_FAILED || code == ResponseCode::RESPONSE_ERROR)
	{
		return ErrorResponse{};
	}
	else
	{
		throw SerializationError("Invalid response code");
	}
}