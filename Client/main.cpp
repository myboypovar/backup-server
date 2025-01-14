#include "client.h"

#include <iostream>



int main()
{
	Client client{};

	try 
	{
		client.startClient();

		if (client.sendAndReceive())
		{
			std::cout << "File was sent successfully" << std::endl;
		}
		else
		{
			std::cout << "File was not sent successfully" << std::endl;
			return -1;
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return -1;
	}

	return 0;
}