#include "YamlFileLayout.h"

YamlFileLayout::YamlFileLayout() :
	root_(kRootParent, YamlElement::ELEMENT_NODE)
{
}

YamlFileLayout::~YamlFileLayout()
{
}

int YamlFileLayout::AddChild(const std::string& parent_name, const std::string& child_name, YamlElement::ElementType child_type)
{
	YamlElement* parent;
	
	// resolve parent path to a YamlElement
	if (ResolveElementPath(parent_name, parent) != ERR_NOERROR)
	{
		return ERR_PARENT_NOT_FOUND;
	}

	// check the parent is a node
	if (parent->type() != YamlElement::ELEMENT_NODE)
	{
		return ERR_PARENT_NOT_NODE;
	}

	// verify the child doesn't already exist
	for (auto& child : parent->childs())
	{
		if (child.name() == child_name)
		{
			return ERR_CHILD_ALREADY_EXISTS;
		}
	}

	// verify that the child isn't generic and there already exist childs
	if (child_name == kAnyChild && parent->childs().size())
	{
		return ERR_CHILD_INVALID;
	}


	// verify that the generic child isn't a node
	if (child_name == kAnyChild && child_type == YamlElement::ELEMENT_NODE)
	{
		return ERR_CHILD_INVALID;
	}

	// verfiy that the child doesn't have the reserved kRootParent name
	if (child_name == kRootParent)
	{
		return ERR_CHILD_INVALID;
	}

	// add new child
	parent->AddChild(YamlElement(child_name, child_type));

	return ERR_NOERROR;
}

int YamlFileLayout::ResolveElementPath(const std::string& parent, YamlElement*& element)
{
	// if the path is the root path, return root
	if (parent == kRootParent)
	{
		element = &root_;
		return ERR_NOERROR;
	}

	YamlElement* cur = &root_;

	std::size_t start, end;
	std::string element_name;
	
	// this while loop traverses the parent path until the final parent is located
	start = 0;
	while (start != std::string::npos)
	{
		// get string of next level
		end = parent.find('/', start);
		if (end != std::string::npos)
		{
			element_name = parent.substr(start, end - start);
			start = end + 1;
		}
		else
		{
			element_name = parent.substr(start);
			start = end;
		}

		// check if it's in the child list, return on fail
		int result = ERR_PARENT_NOT_FOUND;
		for (auto& child : cur->childs())
		{
			if (child.name() == element_name)
			{
				cur = &child;
				result = ERR_NOERROR;
				break;
			}
		}

		if (result != ERR_NOERROR)
		{
			return result;
		}
	}

	element = cur;

	return ERR_NOERROR;
}
