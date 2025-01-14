#include "file-handler.h"
#include "exceptions.h"

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>




FileHandler::FileHandler()
	: _file()
	, _name("")
{
}

FileHandler::~FileHandler()
{
	close();
}

bool FileHandler::open(const std::string& name, FileMode mode)
{
	if (mode == FileMode::READ)
	{
		if (!boost::filesystem::exists(name))
		{
			throw FileError("File does not exist");
		}
		if (!boost::filesystem::is_regular_file(name))
		{
			std::cerr << name << " is not a file" << std::endl;
			return false;
		}
		_file.open(name, std::ios::in);
	}
	else if (mode == FileMode::WRITE)
	{
		_file.open(name, std::ios::out);
	}
	else if (mode == FileMode::READ_BINARY)
	{
		if (!boost::filesystem::exists(name))
		{
			throw FileError("File does not exist");
		}
		if (!boost::filesystem::is_regular_file(name))
		{
			std::cerr << name << " is not a file" << std::endl;
			return false;
		}
		_file.open(name, std::ios::in | std::ios::binary);
	}
	else if (mode == FileMode::WRITE_BINARY)
	{
		_file.open(name, std::ios::out | std::ios::binary);
	}
	else
	{
		std::cerr << "Invalid file mode in file "<< name << std::endl;
		return false;
	}
	_name = name;
	return true;
}

std::string FileHandler::getFileNameFromPath(const std::string& filePath) const
{
	auto pos = filePath.find_last_of("/\\");
	if (pos == std::string::npos)
	{
		return filePath;
	}
	return filePath.substr(pos + 1);

}

void FileHandler::close()
{
	try
	{
		if (_file.is_open())
		{
			_file.close();
			_name = "";
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
}


bool FileHandler::parseRegisterFile(std::string& addr, std::string& port, std::string& user, std::string& fileTransfer)
{
	if (!_file.is_open())
	{
		std::cerr << "The File \""<< _name << " \" is not open" << std::endl;
		return false;
	}

	std::string line;
	int lineCount = 0;
	
	while (std::getline(_file, line))
	{
		if (line.empty())
		{
			continue;
		}

		lineCount++;
		boost::trim(line);

		if (lineCount == 1)  // get the address and port
		{
			auto pos = line.find(':');
			if (pos == std::string::npos)
			{
				std::cerr << "Invalid address, \":\" was not found in file " << _name << std::endl;
				close();
				return false;
			}

			std::string tempAddr = line.substr(0, pos);
			std::string tempPort = line.substr(pos + 1);
			boost::trim(tempAddr);
			boost::trim(tempPort);
			addr = tempAddr;
			port = tempPort;
		}

		else if (lineCount == 2)  // get the user name
		{
			user = line;
		}
		else if (lineCount == 3)  // get the file name to transfer to the server
		{
			fileTransfer = line;
		}
		else if (lineCount > 3) // Too many lines
		{
			std::cerr << "Too many lines in file: " << _name << std::endl;
			close();
			return false;
		}
	}
	if (lineCount < 3) // Too few lines
	{
		std::cerr << "Too few lines in file: " << _name << std::endl;
		close();
		return false;
	}
	return true;
}

bool FileHandler::parseLoginFile(std::string& user, std::string& uuid, std::string& privateKey)
{
	if (!_file.is_open())
	{
		std::cerr << "The File \"" << _name << " \" is not open" << std::endl;
		return false;
	}

	std::string line;
	int lineCount = 0;

	while (std::getline(_file, line))
	{
		if (line.empty())
		{
			continue;
		}

		lineCount++;
		boost::trim(line);

		if (lineCount == 1)  // get the user name
		{
			user = line;
		}
		else if (lineCount == 2)  // get the uuid
		{
			uuid = line;
		}
		else if (lineCount == 3)  // get the private key
		{
			privateKey = line;
		}
		else if (lineCount > 3) // Too many lines
		{
			std::cerr << "Too many lines in file: " << _name << std::endl;
			close();
			return false;
		}
		else if (lineCount < 3) // Too few lines
		{
			std::cerr << "Too few lines in file: " << _name << std::endl;
			close();
			return false;
		}
	}
	return true;
}


bool FileHandler::writeUserInfo(const std::string& user, const std::string& uuid, const std::string& privateKey)
{
	if (!_file.is_open())
	{
		std::cerr << "The File \"" << _name << " \" is not open" << std::endl;
		return false;
	}

	_file << user << std::endl;
	_file << uuid << std::endl;
	_file << privateKey << std::endl;
	return true;
}


void FileHandler::deleteFile(const std::string& fileName) const
{
	try
	{
		boost::filesystem::remove(fileName);
	}
	catch (const boost::filesystem::filesystem_error& e)
	{
		std::cerr << "Error deleting file: " << fileName << '\t' << e.what() << std::endl;
	}
}


std::vector<char> FileHandler::readFile(size_t size)
{
	auto buffer = std::vector<char>(size);
	if (!_file.is_open())
	{
		throw FileError("The file is not open");
	}
	if (size == 0)
	{
		close();
		throw FileError("Invalid file size");
	}
	_file.read(buffer.data(), size);
	return buffer;
}


size_t FileHandler::getFileSize()
{
	if (!_file.is_open())
	{
		throw FileError("The file is not open");
	}
	_file.seekg(0, std::ios::end);
	size_t size = _file.tellg();
	_file.seekg(0, std::ios::beg);
	return size;
}