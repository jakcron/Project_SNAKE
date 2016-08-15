#pragma once

#include <string>
#include <vector>

class YamlElement
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_CHILD_ALREADY_EXISTS,
		ERR_CHILD_NOT_FOUND,
	};


	enum ElementType
	{
		ELEMENT_NODE,
		ELEMENT_SINGLE_KEY,
		ELEMENT_LIST_KEY,
	};

	YamlElement();
	YamlElement(const std::string& name, ElementType type);
	~YamlElement();

	int SetName(const std::string& name);
	int SetType(ElementType type);
	int AddChild(const YamlElement& child);


	const std::string& name(void) const { return name_; }
	ElementType type(void) const { return type_; }
	std::vector<YamlElement>& childs() { return childs_; }

private:
	std::string name_;
	ElementType type_;

	std::vector<YamlElement> childs_;
};

