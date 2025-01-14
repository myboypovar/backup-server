#include "connection.h"
#include "utils.h"
#include "exceptions.h"

#include <iostream>


Connection::Connection() 
	: _io_context(boost::asio::io_context())
	, _resolver(tcp::resolver(_io_context))
	, _socket(tcp::socket(_io_context))
	, _address("")
	, _port("")
{
}

Connection::~Connection()
{
	close();
}

void Connection::close()
{
	if (_socket.is_open())
	{
		try
		{
			_socket.close();
		}
		catch (const boost::system::system_error& e)
		{
			std::cerr << "Error closing socket: " << e.what() << std::endl;
		}
	}
}


bool Connection::setServerIP(const std::string& address, const std::string& port)
{
	if (isValidAddress(address) && isValidPort(port))
	{
		_address = address;
		_port = port;
		return true;
	}
	return false;
}


bool Connection::isValidAddress(const std::string& address) const
{
	boost::system::error_code ec;
	boost::asio::ip::address::from_string(address, ec);
	if (ec)
	{
		std::cerr << "Invalid address" << std::endl;
		return false;
	}
	return true;
}


bool Connection::isValidPort(const std::string& port) const
{
	if (isNumber(port))
	{
		int portInt = std::stoi(port);
		if (portInt > 0 && portInt < 65536) 
		{
			return true;
		}
	}
	std::cerr << "Invalid port" << std::endl;
	return false;
}


bool Connection::connect()
{
	try
	{
		tcp::resolver::results_type endpoints = _resolver.resolve(_address, _port);
		boost::asio::connect(_socket, endpoints);
		std::cout << "Connected to " << _address << ":" << _port << std::endl;
	}
	catch (const boost::system::system_error& e)
	{
		std::cerr << e.what() << std::endl;
		return false;
	}
	return true;
}


void Connection::send(const std::vector<char>& data)
{
	try
	{
		boost::asio::write(_socket, boost::asio::buffer(data));
	}
	catch (const boost::system::system_error& e)
	{
		throw ConnectionError(e.what());
	}
}


std::vector<char> Connection::receive()
{
	std::vector<char> data(PACKET_LENGTH);
	try
	{
		size_t bytesRead = _socket.read_some(boost::asio::buffer(data));
		if (bytesRead > PACKET_LENGTH)
		{
			throw ConnectionError("Received too many bytes");
		}
		data.resize(bytesRead);
		return data;
	}
	catch (const boost::system::system_error&)
	{
		throw ConnectionError("Error receiving data");
	}
}
