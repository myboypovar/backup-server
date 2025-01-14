#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include "protocol.h"

#include <string>
#include <fstream>
#include <vector>


/**
* @brief File mode
*/
enum class FileMode
{
	READ,
	WRITE,
	READ_BINARY,
	WRITE_BINARY,
};

/**
* @brief FileHandler class
* 
* This class provides methods to open, read, and write to files.
*/
class FileHandler
{
public:
	/**
	* @brief Constructor
	*/
	FileHandler();

	/**
	* @brief Destructor the closes the file.
	*/
	~FileHandler();

	/**
	* @brief Open a file
	* 
	* @param path the path to the file
	* @param mode the mode to open the file
	* @return true if the file was opened successfully; false otherwise
	*/
	bool open(const std::string& path, FileMode mode);

	/**
	* @brief Close the file
	*/
	void close();

	/**
	* @brief Gets the name of the file from it's path
	* 
	* @param filePath the path to the file
	* @return the name of the file
	*/
	std::string getFileNameFromPath(const std::string& filePath) const;

	/** 
	* @brief Parse the register file and return the server information
	* 
	* @param addr the server address
	* @param port the server port
	* @param user the user name
	* @param fileTransfer the file to be transferred to the server.
	* @return true if the server information was read successfully; false otherwise
	*/
	bool parseRegisterFile(std::string& addr, std::string& port, std::string& user, std::string& fileTransfer);

	/**
	* @brief Parse the login file and return the user information
	* 
	* @param user the user name
	* @param uuid the user's UUID
	* @param privateKey the user's private key in base64 format
	* @return true if the user information was read successfully; false otherwise
	*/
	bool parseLoginFile(std::string& user, std::string& uuid, std::string& privateKey);

	/**
	* @brief Write the user information to a file
	* 
	* @param user the user name
	* @param uuid the user's UUID
	* @param privateKey the user's private key in base64 format
	* @return true if the user information was written successfully; false otherwise
	*/
	bool writeUserInfo(const std::string& user, const std::string& uuid, const std::string& privateKey);

	/**
	* @brief delete a file
	* 
	* @param fileName the name of the file to be deleted
	*/
	void deleteFile(const std::string& fileName) const;

	/**
	* @brief Read from a file and return its contents
	* 
	* @param size the size of the file
	* @return the contents of the file
	*/
    std::vector<char> readFile(size_t size);
	
	/**
	* @brief Get the size of the file
	* 
	* @return the size of the file
	*/
	size_t getFileSize();

private:
	std::fstream _file;
	std::string _name;
	std::string _fileToTransfer;
};

#endif
