#include "YamlElement.h"


YamlElement::YamlElement() noexcept
{
}

YamlElement::YamlElement(const std::string & parent_path, const std::string & name, ElementType type) noexcept
{
	SetParentPath(parent_path);
	SetName(name);
	SetType(type);
}

YamlElement::YamlElement(const std::string & name, ElementType type) noexcept
{
	SetParentPath("");
	SetName(name);
	SetType(type);
}


YamlElement::~YamlElement() noexcept
{
}

void YamlElement::SetParentPath(const std::string & parent_path) noexcept
{
	parent_path_ = parent_path;
}

void YamlElement::SetName(const std::string & name) noexcept
{
	name_ = name;
}

void YamlElement::SetType(ElementType type) noexcept
{
	type_ = type;
}

void YamlElement::AddChild(const YamlElement & child)
{
	AddChild(child, false);
}

void YamlElement::AddChild(const YamlElement & child, bool allow_duplicates)
{
	if (!allow_duplicates)
	{
		for (auto& i : childs_)
		{
			if (i.name() == child.name())
			{
				throw ProjectSnakeException(kModuleName, "Child(" + child.name() + ") already exists in parent(" + parent_path_ + ")");
			}
		}
	}

	childs_.push_back(child);
}

void YamlElement::AddData(const std::string& str)
{
	// prevent multiple data from being set to a SINGLE_KEY
	// TODO decide whether correct behavior is to override rather than ignore
	if (!data_.empty() && type_ == ELEMENT_SINGLE_KEY)
	{
		//throw ProjectSnakeException(kModuleName, "Attempted to overwrite to an existing data element");
		return;
	}

	data_.push_back(str);
}

void YamlElement::AddData(const std::vector<std::string>& str)
{
	for (const auto& sub_str : str)
	{
		AddData(sub_str);
	}
}


size_t YamlElement::GetChildOccurence(const std::string & name) const noexcept
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

const YamlElement* YamlElement::GetChild(const std::string & name) const noexcept
{
	return GetChild(name, 0);
}

const YamlElement * YamlElement::GetChild(const std::string & name, size_t pos) const noexcept
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

YamlElement* YamlElement::EditChild(const std::string& name) noexcept
{
	return EditChild(name, 0);
}

YamlElement * YamlElement::EditChild(const std::string & name, size_t pos) noexcept
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
