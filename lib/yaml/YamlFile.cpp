#include "YamlFile.h"
#include <cstdint>

#define YAML_DEBUG 1

YamlFile::YamlFile() :
	allow_duplicate_data_childs_(false),
	layout_(kRootParent, layout_.ELEMENT_NODE),
	data_(kRootParent, data_.ELEMENT_NODE)
{
}


YamlFile::~YamlFile()
{
}

int YamlFile::ParseFile(const char * path)
{
	if (reader_.LoadFile(path) != reader_.ERR_NOERROR)
	{
		return ERR_READER_FAILED_TO_OPEN_FILE;
	}

	return ProcessYamlElement(&layout_, &data_);
}

int YamlFile::AddChildToRoot(const std::string & child_name, YamlElement::ElementType child_type)
{
	return AddChildToParent(kRootParent, child_name, child_type);
}

int YamlFile::AddGenericChildToParent(const std::string & parent_path, YamlElement::ElementType child_type)
{
	return AddChildToParent(parent_path, kAnyChild, child_type);
}

int YamlFile::AddChildToParent(const std::string& parent_path, const std::string& child_name, YamlElement::ElementType child_type)
{
	YamlElement* parent = nullptr;

	// if the parent path is the root parent, don't resolve
	if (parent_path == kRootParent)
	{
		parent = &layout_;
	}
	else
	{
		parent = ResolveElementPath(&layout_, parent_path);
	}

	// attempt to get parent element
	if (parent == nullptr)
	{
		return ERR_PATH_FAILED_TO_RESOLVE;
	}

	// create child
	YamlElement child(child_name, child_type);

	// forbid anychilds being nodes
	if (child_name == kAnyChild && child_type == child.ELEMENT_NODE)
	{
		return ERR_FORBIDDEN_ATTRIBUTE;
	}

	// forbid rootparent from being created again
	if (child_name == kRootParent)
	{
		return ERR_FORBIDDEN_ATTRIBUTE;
	}

	// prevent adding children when an anychild exists
	if (parent->GetChild(kAnyChild) != nullptr)
	{
		return ERR_CHILD_ALREADY_EXISTS;
	}

	// prevent adding an anychild when children exist
	if (child_name == kAnyChild && !parent->childs().empty())
	{
		return ERR_CHILD_ALREADY_EXISTS;
	}

	// add child to parent
	if (parent->AddChild(child) != parent->ERR_NOERROR)
	{
		return ERR_CHILD_ALREADY_EXISTS;
	}

	return ERR_NOERROR;
}

void YamlFile::AllowDuplicateDataChilds(bool allow)
{
	allow_duplicate_data_childs_ = allow;
}

const YamlElement* YamlFile::GetLayoutElement(const std::string& path)
{
	return ResolveElementPath(&layout_, path);
}

const YamlElement* YamlFile::GetDataElement(const std::string& path)
{
	return ResolveElementPath(&data_, path);
}

int YamlFile::ProcessYamlElement(const YamlElement* layout, YamlElement* data)
{
	if (data->type() == data->ELEMENT_NODE)
	{
#ifdef YAML_DEBUG
		printf("[YAML DEBUG] NODE(%s) entered\n", data->name().c_str());
		for (const auto& child : layout->childs())
		{
			printf("[YAML DEBUG] NODE(%s) -> EXP_CHILD(%s)\n", layout->name().c_str(), child.name().c_str());
		}
#endif

		// check if the layout supports children
		if (layout->childs().empty())
		{
			return ERR_NODE_HAS_NO_CHILDREN;
		}

		
		// move into children of the element
		reader_.GetEvent();
		if (!reader_.is_event_mapping_start())
		{
			return ERR_YAML_MAPPING_EVENT_DID_NOT_OCCUR;
		}

		// get level for children
		uint32_t level = reader_.level();

		while (reader_.GetEvent() && reader_.level() >= level)
		{
			if (!reader_.is_event_scalar()) continue;
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] NODE(%s) -> CHILD(%s) encountered\n", data->name().c_str(), reader_.event_string().c_str());
#endif
			// get layout child for layout reference
			const YamlElement* layout_child = layout->GetChild(reader_.event_string());
			if (layout_child == nullptr)
			{
				// attempt to get the anychild wildcard reference element
				layout_child = layout->GetChild(kAnyChild);

				if (layout_child == nullptr)
				{
					return ERR_NODE_HAS_NO_SUCH_CHILD;
				}
			}

			YamlElement* data_child = data->EditChild(reader_.event_string());
			// if the data doesn't have such a child yet (or duplicate childs are allowed), create it
			if (data_child == nullptr || allow_duplicate_data_childs_)
			{
				data->AddChild(YamlElement(reader_.event_string(), layout_child->type()), allow_duplicate_data_childs_);				
				data_child = data->EditChild(reader_.event_string(), data->GetChildOccurence(reader_.event_string()) - 1);
			}

			// process child
			int ret = ProcessYamlElement(layout_child, data_child);
			if (ret != ERR_NOERROR) 
			{
				return ret;
			}
		}
	}
	else if (data->type() == data->ELEMENT_SINGLE_KEY)
	{
#ifdef YAML_DEBUG
		printf("[YAML DEBUG] SINGLE_KEY(%s) entered\n", data->name().c_str());
#endif
		// temporary storage
		std::string tmp;

		if (reader_.SaveValue(tmp) != reader_.ERR_NOERROR)
		{
			return ERR_READER_UNEXPECTED_LAYOUT;
		}
		data->AddData(tmp);
	}
	else if (data->type() == data->ELEMENT_LIST_KEY)
	{
#ifdef YAML_DEBUG
		printf("[YAML DEBUG] LIST_KEY(%s) entered\n", data->name().c_str());
#endif
		// temporary storage
		std::vector<std::string> tmp(0);

		if (reader_.SaveValueSequence(tmp) != reader_.ERR_NOERROR)
		{
			return ERR_READER_UNEXPECTED_LAYOUT;
		}

		data->AddData(tmp);
	}
	else
	{
		return ERR_UNKNOWN_ELEMENT_TYPE;
	}
	
	return ERR_NOERROR;
}

YamlElement* YamlFile::ResolveElementPath(YamlElement* root, const std::string& path)
{
	if (root->name() != kRootParent)
	{
		return nullptr;
	}

	YamlElement* cur = root;

	std::size_t start, end;
	std::string element_name;

	// this while loop traverses the parent path until the final parent is located
	start = 0;
	while (start != std::string::npos)
	{
		// get string of next level
		end = path.find('/', start);
		if (end != std::string::npos)
		{
			element_name = path.substr(start, end - start);
			start = end + 1;
		}
		else
		{
			element_name = path.substr(start);
			start = end;
		}

		// check if it's in the child list, return on fail
		if (cur->GetChild(element_name) == nullptr)
		{
			return nullptr;
		}

		// update ptr to current level
		cur = cur->EditChild(element_name);
	}

	return cur;
}
