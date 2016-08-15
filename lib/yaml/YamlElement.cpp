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