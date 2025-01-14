#ifndef CONNECTION_H
#define CONNECTION_H


#include <boost/asio.hpp>
#include <string>
#include <vector>

using boost::asio::ip::tcp;

constexpr size_t PACKET_LENGTH = 32768;

/**
* @brief Connection class
* 
* This class represents a connection to a server and provides methods to connect to the server and
* sends and receives data.
*/
class Connection
{
public:

	/**
	* @brief Constructor
	* 
	* Initializes a new instance of the Connection class.
	*/
	Connection();

	/**
	* @brief Destructor
	* 
	* Closes the connection
	*/
	~Connection();

	/**
	* @brief Close the connection
	*/
	void close();

	/**
	* @brief Set the server IP address and port
	* 
	* @param address the IP address of the server
	* @param port the port of the server
	* @return true if the address and port are valid; false otherwise
	*/
	bool setServerIP(const std::string& address, const std::string& port);
	/**
	* @brief Check if the address is valid
	* 
	* @param address the address to be checked.
	* @return true if the address is valid; false otherwise
	*/
	bool isValidAddress(const std::string& address) const;

	/**
	* @brief Check if the port is valid
	* 
	* @param port the port to be checked.
	* @return true if the port is valid; false otherwise
	*/
	bool isValidPort(const std::string& port) const;

	/**
	* @brief Connect to the server
	*
	* @return true if the connection was successful; false otherwise
	*/
	bool connect();

	/**
	* @brief Send data to the server
	* 
	* @param data a vector of chars containing the data to be sent to the server
	*/
	void send(const std::vector<char>& data);
	/** 
	* @brief Receive data from the server
	* 
	* Receives data from the server and returns it as a vector of chars
	* 
	* @return a vector of chars containing the data received from the server
	*/
	std::vector<char> receive();


private:
	boost::asio::io_context _io_context;
	tcp::resolver _resolver;
	tcp::socket _socket;
	std::string _address;
	std::string _port;

};

#endif
