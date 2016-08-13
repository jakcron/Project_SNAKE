#include "UserSettings.h"

int main(int argc, char** argv)
{
	UserSettings userset;

	return userset.ParseUserArgs(argc, argv);
}