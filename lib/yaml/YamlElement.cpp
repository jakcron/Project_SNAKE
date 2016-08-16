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
	return AddChild(child, false);
}

int YamlElement::AddChild(const YamlElement & child, bool allow_duplicates)
{
	if (!allow_duplicates)
	{
		for (auto& i : childs_)
		{
			if (i.name() == child.name())
			{
				return ERR_CHILD_ALREADY_EXISTS;
			}
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


size_t YamlElement::GetChildOccurence(const std::string & name) const
{
	size_t num = 0;
	for (const auto& child : childs_)
	{
		if (child.name_ == name)
		{
			num++;
		}
	}

	return num;
}

const YamlElement* YamlElement::GetChild(const std::string & name) const
{
	return GetChild(name, 0);
}

const YamlElement * YamlElement::GetChild(const std::string & name, size_t pos) const
{
	size_t num = 0;
	for (const auto& child : childs_)
	{
		if (child.name_ == name)
		{
			// return if the child is at the correct position
			if (num == pos)
			{
				return &child;
			}
			
			num++;
		}
	}

	return nullptr;
}

YamlElement* YamlElement::EditChild(const std::string& name)
{
	return EditChild(name, 0);
}

YamlElement * YamlElement::EditChild(const std::string & name, size_t pos)
{
	size_t num = 0;
	for (auto& child : childs_)
	{
		if (child.name_ == name)
		{
			// return if the child is at the correct position
			if (num == pos)
			{
				return &child;
			}

			num++;
		}
	}

	return nullptr;
}
