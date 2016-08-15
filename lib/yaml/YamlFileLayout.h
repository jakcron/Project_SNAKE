#pragma once

#include <string>
#include <vector>

#include "YamlElement.h"

class YamlFileLayout
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_PARENT_NOT_FOUND,
		ERR_PARENT_NOT_NODE,
		ERR_CHILD_ALREADY_EXISTS,
		ERR_CHILD_INVALID
	};

	// these are special names which refer to nonspecifc Elements

	// kRootParent refers to the root node, paths do not need to include this string
	const std::string kRootParent = "#ROOT_PARENT#";

	// kAnyChild indicates that the parent can accept any child provided they match the Element type (type NODE is forbidden)
	// parents with an kAnyChild child may not have other childs
	const std::string kAnyChild = "#ANY_CHILD#";

	YamlFileLayout();
	~YamlFileLayout();

	int AddChild(const std::string& parent_name, const std::string& child_name, YamlElement::ElementType child_type);

	const YamlElement& root() const { return root_; }

private:
	YamlElement root_;

	int ResolveElementPath(const std::string& parent, YamlElement*& element);
};