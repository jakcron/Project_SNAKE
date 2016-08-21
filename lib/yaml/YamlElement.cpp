#include "YamlElement.h"



YamlElement::YamlElement()
{
}

YamlElement::YamlElement(const std::string & parent_path, const std::string & name, ElementType type)
{
	SetParentPath(parent_path);
	SetName(name);
	SetType(type);
}

YamlElement::YamlElement(const std::string & name, ElementType type)
{
	SetParentPath("");
	SetName(name);
	SetType(type);
}


YamlElement::~YamlElement()
{
}

int YamlElement::SetParentPath(const std::string & parent_path)
{
	parent_path_ = parent_path;
	return ERR_NOERROR;
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
	// prevent multiple data from being set to a SINGLE_KEY
	// TODO decide whether correct behavior is to override rather than ignore
	if (!data_.empty() && type_ == ELEMENT_SINGLE_KEY)
	{
		return ERR_NOERROR;
	}

	data_.push_back(str);
	return ERR_NOERROR;
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
