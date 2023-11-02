#include "error.h"
#include <iostream>

void exit( const std::string& error )
{
	std::cout << error;
	system("pause");
	exit(1);
}
