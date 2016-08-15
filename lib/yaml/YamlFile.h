#pragma once
#include "YamlFileLayout.h"
#include "YamlReader.h"

class YamlFile
{
public:
	YamlFile();
	~YamlFile();

	int ParseFile(const char* path, YamlFileLayout layout);

	bool DoesExistElement(const std::string& element);
	const std::string& GetElementKeyValue(const std::string& element);
	const std::vector<std::string>& GetElementKeyList(const std::string& element);

private:
	YamlFileLayout layout_;
	YamlReader reader_;

};

