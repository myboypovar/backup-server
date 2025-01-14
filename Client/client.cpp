#include "client.h"
#include "endian.h"
#include "exceptions.h"
#include "serializer.h"
#include "utils.h"
#include "cksum.h"

#include <iostream>


Client::Client()
	: _fileHandler(FileHandler())
	, _connection(Connection())
	, _rsaWrapper(RSAWrapper())
	, _aesWrapper(AESWrapper())
	, _errorCount(0)
	, _fileToSend("")
	, _fileCRC(0)
	, _sendingFile(false)
{
}


bool Client::startClient()
{
	std::string user;
	std::string clientID;
	std::string filePrivateKey;
	Request request;
	bool writeToFile = false;

	if (!getRegisterInfo(user, _fileToSend))
	{
		return false;
	}
	try
	{
		if (!getLoginInfo(user, clientID, filePrivateKey))
		{
			return false;
		}
	}
	catch (const FileError&)
	{
		// if the saved file doesn't exist, create a registration request.
		std::vector<char> uuid(CLIENT_ID_SIZE, 0);  // don't care about the value
		request = createNameRequest(user, uuid , static_cast<uint16_t>(RequestCode::REQUEST_REGISTER));
		writeToFile = true;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return false;
	}

	if (!writeToFile)
	{
		// if the saved file exists, create a login request.
		auto uuid = hexToUuidBytes(clientID);
		request = createNameRequest(user, uuid, static_cast<uint16_t>(RequestCode::REQUEST_LOGIN));
	}
	if (!_connection.connect())
	{
		return false;
	}
	_request.reset();
	_request = std::make_unique<Request>(request);
	return true;
}


bool Client::sendAndReceive()
{
	bool connected = true;
	while (connected)
	{
		if (!_sendingFile)  // if not sending a file, send the request
		{
			try
			{
				sendRequest(*_request);
			}
			catch (std::exception& e)
			{
				std::cerr << e.what() << std::endl;
				return false;
			}
		}
		_sendingFile = false; // reset the flag, file was sent.
		try
		{
			auto response = receiveResponse();
			
			_response.reset();
			_response = std::make_unique<Response>(response);
			if (!handleResponse())
			{
				_connection.close();
				connected = false;
			}
		}
		catch (const std::exception& e)
		{
			std::cerr << e.what() << std::endl;
			connected = false;
		}
		
	}
	if (RequestCode(_request->opCode) == RequestCode::REQUEST_CRC_VALID)
	{
		return true;
	}
	return false;
}


bool Client::getRegisterInfo(std::string& user, std::string& sendFile)
{
	try
	{
		// Open the file, if it doesn't exist, an exception is thrown
		if (!_fileHandler.open(REQUEST_FILE_NAME, FileMode::READ))
		{
			return false;
		}
	}
	catch (FileError& e)
	{
		std::cerr << e.what() << std::endl;
		return false;
	}

	std::string addr;
	std::string port;
	
	if (!_fileHandler.parseRegisterFile(addr, port, user, sendFile))
	{
		return false;
	}
	_fileHandler.close();

	// Check if the user and sendFile inputs are valid
	if (user.empty())
	{
		std::cerr << "Invalid username" << std::endl;
		return false;
	}
	if (user.size() >= NAME_SIZE)
	{
		std::cerr << "Username too long" << std::endl;
		return false;
	}
	if (sendFile.empty())
	{
		std::cerr << "Invalid file name" << std::endl;
		return false;
	}
	if (sendFile.size() >= FILE_NAME_SIZE)
	{
		std::cerr << "File name too long" << std::endl;
		return false;
	}
	
	// Set the server IP and port
	if (!_connection.setServerIP(addr, port))
	{
		return false;
	}
	return true;
}


bool Client::getLoginInfo(std::string& user, std::string& uuid, std::string& privateKey)
{
	if (!_fileHandler.open(USER_FILE_NAME, FileMode::READ))
	{
		return false;
	}
	
	if (!_fileHandler.parseLoginFile(user, uuid, privateKey))
	{
		return false;
	}
	_fileHandler.close();
	return true;
}


void Client::sendRequest(const Request& request)
{
	std::vector<char> buffer;
	
	buffer = Serializer::serializeRequest(request);
	_connection.send(buffer);
	
}


Response Client::receiveResponse() 
{
	auto response = Serializer::deserializeResponse(_connection.receive());
	return response;
}


bool Client::saveUserInfo(const std::string& name, const std::vector<char>& uuid, const std::string& privateKey)
{
	try
	{
		if (!_fileHandler.open(USER_FILE_NAME, FileMode::WRITE))
		{
			return false;
		}
	}
	catch (const FileError& e)
	{
		e.what();
		return false;
	}
	if (!_fileHandler.writeUserInfo(name, uuidToHex(uuid), privateKey))
	{
		return false;
	}
	_fileHandler.close();
	return true;
}


Request Client::createNameRequest(const std::string& user, const std::vector<char>& clientID, uint16_t opCode) const
{
	NameRequest nameRequest{ user };
	auto version = CLIENT_VERSION;
	auto payloadSize = getPayloadSize(nameRequest);
	return Request{ clientID, version, opCode, payloadSize, nameRequest };
}


Request Client::createPublicKeyRequest(const std::string& user, const std::vector<char>& publicKey, const std::vector<char>& clientID, uint16_t opCode) const
{
	SendPublickKeyRequest sendPublicKeyRequest{ user, publicKey };
	auto version = CLIENT_VERSION;
	auto payloadSize = getPayloadSize(sendPublicKeyRequest);
	return Request{ clientID, version, opCode, payloadSize, sendPublicKeyRequest };
}


uint32_t Client::getPayloadSize(const Payload& payload) const
{
	// lambda function to get the size of the payload
	return std::visit([](const auto& p) -> uint32_t {
		using T = std::decay_t<decltype(p)>;

		if constexpr (std::is_same_v<T, ClientIDResponse>)
			return CLIENT_ID_SIZE;

		else if constexpr (std::is_same_v<T, NameRequest>)
			return NAME_SIZE;

		else if constexpr (std::is_same_v<T, SendPublickKeyRequest>)
			return NAME_SIZE + PUBLIC_KEY_SIZE;

		else if constexpr (std::is_same_v<T, SendFileRequest>)
			return CONTENT_SIZE
			+ ORIGINAL_FILE_SIZE
			+ PACKET_NUMBER_SIZE
			+ TOTAL_PACKETS_SIZE
			+ FILE_NAME_SIZE
			+ p.contentSize;

		else if constexpr (std::is_same_v<T, SymmetricKeyResponse>)
			return CLIENT_ID_SIZE + static_cast<uint32_t>(p.symmetricKey.size());

		else if constexpr (std::is_same_v<T, FileResponse>)
			return CLIENT_ID_SIZE
			+ CONTENT_SIZE
			+ FILE_NAME_SIZE
			+ CRC_SIZE;

		else if constexpr (std::is_same_v<T, CRCRequest>)
			return FILE_NAME_SIZE;

		// error case
		else
			return 0;
		}, payload);
}


bool Client::handleResponse()
{
	auto code = static_cast<ResponseCode>(_response->opCode);
	std::cout << "Response code: " << static_cast<int>(code) << std::endl;

	if (code == ResponseCode::RESPONSE_REGISTRATION)
	{
		// save the username , clientID, and the private key in a file.
		_errorCount = 0;
		auto clientID = std::get<ClientIDResponse>(_response->payload).clientID;
		auto name = std::get<NameRequest>(_request->payload).name;
		saveUserInfo(name, clientID, _rsaWrapper.getBase64PrivateKey());

		auto request{ createPublicKeyRequest(name, _rsaWrapper.getPublicKey(), clientID, static_cast<uint16_t>(RequestCode::REQUEST_PUBLIC_KEY)) };
		_request.reset();
		_request = std::make_unique<Request>(request);
		return true;
	}

	else if (code == ResponseCode::RESPONSE_REGISTRATION_FAILED)
	{
		std::cerr << "Server responded with an error" << std::endl;
		_errorCount++;
		if (_errorCount == MAX_ERRORS)
		{
			std::cerr << "Fatal Error: Registration failed" << std::endl;
			return false;
		}
		return true;
	}

	else if (code == ResponseCode::RESPONSE_LOGIN || code == ResponseCode::RESPONSE_AES_KEY)
	{
		_errorCount = 0;
		auto clientID = std::get<SymmetricKeyResponse>(_response->payload).clientID;
		auto encryptedKey = std::get<SymmetricKeyResponse>(_response->payload).symmetricKey;
		auto aesKey = _rsaWrapper.decrypt(encryptedKey);
		_aesWrapper.setKey(aesKey);
		handleFileRequest();
		return true;
	}

	else if (code == ResponseCode::RESPONSE_LOGIN_FAILED)
	{
		_fileHandler.deleteFile(USER_FILE_NAME);
		std::string user;
		std::string sendFile;
		if (!getRegisterInfo(user, sendFile))
		{
			return false;
		}
		auto request{ createNameRequest(user, std::vector<char>(CLIENT_ID_SIZE, '\0'), static_cast<uint16_t>(RequestCode::REQUEST_REGISTER))};
		_request.reset();
		_request = std::make_unique<Request>(request);
		return true;
	}

	else if (code == ResponseCode::RESPONSE_FILE_VALID)
	{
		auto crc = std::get<FileResponse>(_response->payload).crc;
		if (crc == _fileCRC)
		{
			_errorCount = 0;
			CRCRequest crcRequest{ _fileToSend };
			Request request{ _request->clientID, CLIENT_VERSION, static_cast<uint16_t>(RequestCode::REQUEST_CRC_VALID), getPayloadSize(crcRequest), crcRequest };
			
			_request.reset();
			_request = std::make_unique<Request>(request);
			return true;
		}
		else
		{
			std::cerr << "CRC mismatch" << std::endl;
			_errorCount++;
			if (_errorCount > MAX_ERRORS)
			{
				std::cerr << "Fatal Error: CRC mismatch" << std::endl;
				CRCRequest crcRequest{ _fileToSend };
				Request request{ _request->clientID, CLIENT_VERSION, static_cast<uint16_t>(RequestCode::REQUEST_CRC_FATAL), getPayloadSize(crcRequest), crcRequest };
				_request.reset();
				_request = std::make_unique<Request>(request);
				sendRequest(*_request);
				return false;
			}
			CRCRequest crcRequest{ _fileToSend };
			Request request{ _request->clientID, CLIENT_VERSION, static_cast<uint16_t>(RequestCode::REQUEST_CRC_INVALID), getPayloadSize(crcRequest), crcRequest };
			_request.reset();
			_request = std::make_unique<Request>(request);
			sendRequest(*_request);
			handleFileRequest();
			return true;
		}
		
	}
	else if (code == ResponseCode::RESPONSE_ACK)
	{
		return false;
	}
	else if (code == ResponseCode::RESPONSE_ERROR)
	{
		std::cerr << "Server responded with an error" << std::endl;
		_errorCount++;
		if (_errorCount == MAX_ERRORS)
		{
			std::cerr << "Fatal Error: Server responded with an error" << std::endl;
			return false;
		}
	}
	else
	{
		std::cerr << "Invalid response" << std::endl;
		return false;
	}
}


void Client::handleFileRequest()
{
	if (!_fileHandler.open(_fileToSend, FileMode::READ_BINARY))
	{
		return;
	}

	size_t fileSize = _fileHandler.getFileSize();
	if (fileSize == 0)
	{
		_fileHandler.close();
		throw FileError("File is empty");
	}
	if (fileSize > MAX_FILE_SIZE)
	{
		_fileHandler.close();
		throw FileError("File is too large");
	}
	std::vector<char> fileContent = _fileHandler.readFile(fileSize);
	_fileHandler.close();

	_fileCRC = readfileCRC(_fileToSend);
	std::string fileName = _fileHandler.getFileNameFromPath(_fileToSend);

	std::vector<char> encryptedFile = _aesWrapper.encrypt(fileContent);
	std::vector<char>().swap(fileContent); // Release the memory

	size_t headerSize = CLIENT_ID_SIZE + sizeof(Request::version) + sizeof(Request::opCode) + sizeof(Request::payloadSize);
	size_t payloadHeaderSize = CONTENT_SIZE + ORIGINAL_FILE_SIZE + PACKET_NUMBER_SIZE + TOTAL_PACKETS_SIZE + FILE_NAME_SIZE;

	size_t firstPayloadSize = PACKET_LENGTH - payloadHeaderSize - headerSize;
	size_t payloadSize = PACKET_LENGTH - payloadHeaderSize;

	size_t remainingSize = (encryptedFile.size() > firstPayloadSize)  // Deduce the first packet from the file size
		? encryptedFile.size() - firstPayloadSize
		: 0;

	size_t totalPackets = 1; // Start with the first packet
	if (remainingSize > 0) {
		totalPackets += (remainingSize + payloadSize - 1) / payloadSize;
	}

	if (totalPackets > UINT16_MAX)
	{
		throw FileError("File too large");
	}
	else
	{
		std::vector<char> contentChunk(encryptedFile.begin(), encryptedFile.begin() + firstPayloadSize);

		// send the first packet.
		SendFileRequest sendFileRequest
		{
			static_cast<uint32_t>(contentChunk.size()),
			static_cast<uint32_t>(fileSize),
			1,
			static_cast<uint16_t>(totalPackets),
			fileName,
			contentChunk
		};
		Request request
		{
			_request->clientID,
			CLIENT_VERSION,
			static_cast<uint16_t>(RequestCode::REQUEST_SEND_FILE),
			getPayloadSize(sendFileRequest),
			sendFileRequest
		};
		_request.reset();
		_request = std::make_unique<Request>(request);
		sendRequest(*_request);
		_sendingFile = true;
	}
	
	if (totalPackets > 1)
	{
		size_t offset = firstPayloadSize;
		bool keepSending = true;
		for (uint16_t i = 2; keepSending; i++)
		{
			if (offset + payloadSize >= encryptedFile.size())
			{
				payloadSize = encryptedFile.size() - offset;
				keepSending = false;
			}

			std::vector<char> packetContent(encryptedFile.begin() + offset, encryptedFile.begin() + offset + payloadSize);
			
			offset += payloadSize;
			SendFileRequest packet
			{
				static_cast<uint32_t>(packetContent.size()),
				static_cast<uint32_t>(fileSize),
				i,
				static_cast<uint16_t>(totalPackets),
				fileName,
				packetContent
			};
			sendFilePayload(packet);
		}
	}
}


void Client::sendFilePayload(const SendFileRequest& sendFileRequest)
{
	auto buffer = Serializer::serializePayload(sendFileRequest, getPayloadSize(sendFileRequest));
	_connection.send(buffer);
}
