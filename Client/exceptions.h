#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>
#include <string>


/**
 * @brief Custom exception class
 */
class CustomException : public std::exception
{
public:
    explicit CustomException(const std::string& message)
        : _message(message) {}

    const char* what() const noexcept override
    {
        return _message.c_str();
    }

private:
    std::string _message;
};

class FileError : public CustomException
{
public:
    explicit FileError(const std::string& message)
        : CustomException("FileError: " + message) {}
};

class ConnectionError : public CustomException
{
public:
    explicit ConnectionError(const std::string& message)
        : CustomException("ConnectionError: " + message) {}
};

class SerializationError : public CustomException
{
public:
    explicit SerializationError(const std::string& message)
        : CustomException("SerializationError: " + message) {}
};

class AESWrapperError : public CustomException
{
public:
	explicit AESWrapperError(const std::string& message)
		: CustomException("AESWrapperError: " + message) {}
};


#endif // EXCEPTIONS_H
