using namespace std;

#include <iostream>
#include <fstream>
#include <string>

int Hash(char* funcName)
{
	char* v1;
	char v2;
	unsigned int result;

	v1 = funcName;
	v2 = *funcName;

	for (result = 0; *v1; v2 = *v1)
	{
		result = ((result << 7) | (result >> 25)) ^ v2;
		++v1;
	}
	return result;
}

int main(int argc, char** argv)
{
	ifstream input(argv[1]);
	string line;
	while (getline(input, line))
	{

		// Find the bytes of the line
		char chrFuncName[100];
		strcpy_s(chrFuncName, line.c_str);

		// Hash the name
		int hash = Hash(chrFuncName);
		cout << "0x" << hex << hash << ' ' << line << '\n';
	}
}