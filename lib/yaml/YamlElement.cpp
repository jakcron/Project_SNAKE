#include "YamlElement.h"



YamlElement::YamlElement()
{
}

YamlElement::YamlElement(const std::string & name, ElementType type)
{
	SetName(name);
	SetType(type);
}


YamlElement::~YamlElement()
{
}

int YamlElement::SetName(const std::string & name)
{
	name_ = name;
	return ERR_NOERROR;
}

int YamlElement::SetType(ElementType type)
{
	type_ = type;
	return ERR_NOERROR;
}

int YamlElement::AddChild(const YamlElement & child)
{
	for (auto& i : childs_)
	{
		if (i.name() == child.name())
		{
			return ERR_CHILD_ALREADY_EXISTS;
		}
	}

	childs_.push_back(child);

	return ERR_NOERROR;
}

int YamlElement::AddData(const std::string& str)
{
	data_.push_back(str);
	return 0;
}

int YamlElement::AddData(const std::vector<std::string>& str)
{
	for (const auto& sub_str : str)
	{
		AddData(sub_str);
	}

	return 0;
}


const YamlElement * YamlElement::GetChild(const std::string & name) const
{
	for (const auto& child : childs_)
	{
		if (child.name_ == name)
		{
			return &child;
		}
	}

	return nullptr;
}

YamlElement* YamlElement::EditChild(const std::string& name)
{
	for (auto& child : childs_)
	{
		if (child.name_ == name)
		{
			return &child;
		}
	}

	return nullptr;
}
