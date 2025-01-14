#ifndef CLIENT_H
#define CLIENT_H


#include "protocol.h"
#include "connection.h"
#include "file-handler.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <string>
#include <cstdint>
#include <memory>
#include <vector>


const std::string REQUEST_FILE_NAME = "transfer.info";
const std::string USER_FILE_NAME = "me.info";
constexpr int MAX_ERRORS = 3;
constexpr size_t MAX_FILE_SIZE = UINT32_MAX;


/**********************************************************************************************//**
 * @class	Client
 *
 * @brief	A client that connects to a server and sends a file.
 *
 * This class represents a client that connects to a server and sends a file.
 * The client will send a request to the server and receive a response. The client will continue to send requests and receive responses until the connection is closed.
 **************************************************************************************************/
class Client
{
public:

	/**********************************************************************************************//**
	 * @fn	Client::Client()
	 *
	 * @brief	Default constructor.
	 *
	 * Initializes a new instance of the Client class.
	 **************************************************************************************************/
	Client();

	/** 
	* @brief Starts the client.
	* 
	* This method starts the client by setting up the connection to the server and getting the user information.
	* 
	* @return true if the client was started successfully; false otherwise.
	*/
	bool startClient();

	/**
	* @brief Sends a request to the server and receives a response.
	* 
	* This method sends a request to the server and receives a response. It will continue to send requests and receive responses until the connection is closed.
	* 
	* @return true if the file was sent successfully; false otherwise.
	*/
	bool sendAndReceive();

	/**
	* @brief Sets the server informatino, gets the username and the file to transfer from a file.
	* 
	* This method sets the server information, gets the username and the file to transfer from a file.
	* 
	* @param user The user's name.
	* @param sendFile The file to transfer.
	* @return true if the server information was set successfully; false otherwise.
	*/
	bool getRegisterInfo(std::string& user, std::string& sendFile);

	/**
	* @brief Gets the user information from a file.
	*
	* This method reads the user information from a file. The user information includes the user's name, UUID, and private key in base64 format.
	*
	* @param user The user's name.
	* @param uuid The user's UUID.
	* @param privateKey The user's private key in base64 format.
	* @return true if the user information was read successfully; false otherwise.
	*/
	bool getLoginInfo(std::string& user, std::string& uuid, std::string& privateKey);

	/**
	* @brief Sends a request to the server.
	*
	* This method serializes the request and sends it to the server.
	*
	* @param request The request to send.
	*/
	void sendRequest(const Request& request);

	/**
	* @brief Receives a response from the server.
	*
	* This method receives a response from the server and deserializes it.
	*
	* @return The response from the server.
	*/
	Response receiveResponse();

	/**
	* @brief Saves the user information to a file.
	*
	* This method saves the user information to a file. The user information includes the user's name, UUID, and private key in base64 format.
	*
	* @param name The user's name.
	* @param uuid The user's UUID.
	* @param privateKey The user's private key in base64 format.
	* @return true if the user information was saved successfully; false otherwise.
	*/
	bool saveUserInfo(const std::string& name, const std::vector<char>& uuid, const std::string& privateKey);

	/**
	* @brief Creates a name request.
	*
	* This method creates a name request to send to the server. The request contains the user's name.
	*
	* @param user The user's name.
	* @param clientID The client ID.
	* @param opCode The request code.
	* @return The name request.
	*/
	Request createNameRequest(const std::string& user, const std::vector<char>& clientID, uint16_t opCode) const;

	/**
	* @brief Creates a public key request.
	*
	* This method creates a public key request to send to the server. The request contains the user's name and public key.
	*
	* @param user The user's name.
	* @param publicKey The user's public key.
	* @param clientID The client ID.
	* @param opCode The request code.
	* @return The public key request.
	*/
	Request createPublicKeyRequest(const std::string& user, const std::vector<char>& publicKey, const std::vector<char>& clientID, uint16_t opCode) const;

	/**
	 * @brief Gets the size of the payload.
	 *
	 * This method determines the size of the payload based on the type of the payload.
	 *
	 * @param payload The payload to get the size of.
	 * @return The size of the payload.
	 */
	uint32_t getPayloadSize(const Payload& payload) const;

	/**
	* @brief Handles the server response.
	*
	* This method handles the server response based on the response code. It will
	* determine the next action to take based on the response code.
	*
	* @return true if the there is a request to be sent to the server, false otherwise.
	*/
	bool handleResponse();

	/**
	 * @brief Handles the file transfer request to the server.
	 *
	 * This method reads a file from disk, encrypts it using AES, and sends it to the server
	 * in multiple packets. It ensures that the file is properly split into chunks that fit
	 * within the packet size limits.
	 *
	 * @return true if the file was successfully sent; false otherwise.
	 * @throws FileError if there is an issue reading the file or if the file size is too large.
	 */
	void handleFileRequest();

	/**
	 * @brief Sends a file packet to the server.
	 *
	 * This method serializes the file packet which is the header of the content of the file
	 * and sends it to the server.
	 *
	 * @param sendFileRequest The file packet to send.
	 */
	void sendFilePayload(const SendFileRequest& sendFileRequest);


private:
	FileHandler _fileHandler;
	Connection _connection;
	RSAWrapper _rsaWrapper;
	AESWrapper _aesWrapper;
	int _errorCount;
	std::unique_ptr<Request> _request;
	std::unique_ptr<Response> _response;
	std::string _fileToSend;
	uint32_t _fileCRC;
	bool _sendingFile;
};




#endif
