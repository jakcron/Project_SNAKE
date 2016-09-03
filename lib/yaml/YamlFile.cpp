#include "YamlFile.h"
#include <cstdint>

//#define YAML_DEBUG true

YamlFile::YamlFile() noexcept :
	allow_duplicate_data_childs_(false),
	layout_(kRootParent, layout_.ELEMENT_NODE),
	data_(kRootParent, data_.ELEMENT_NODE)
{
}

YamlFile::~YamlFile() noexcept
{
}

void YamlFile::ParseFile(const char* path)
{
	reader_.LoadFile(path);
	ProcessYamlElement(&layout_, &data_);
}

void YamlFile::AddChildToRoot(const std::string & child_name, YamlElement::ElementType child_type)
{
	AddChildToParent(kRootParent, child_name, child_type);
}

void YamlFile::AddGenericChildToParent(const std::string & parent_path, YamlElement::ElementType child_type)
{
	AddChildToParent(parent_path, kAnyChild, child_type);
}

void YamlFile::AddChildToParent(const std::string& parent_path, const std::string& child_name, YamlElement::ElementType child_type)
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
		throw ProjectSnakeException(kModuleName, "Failed to add child(" + child_name + ") to parent(" + parent_path + "), reason: parent does not exist");
		//return ERR_PATH_FAILED_TO_RESOLVE;
	}

	// create child
	YamlElement child(child_name, child_type);

	if (parent_path != kRootParent)
	{
		child.SetParentPath(parent_path);
	}

	// forbid anychilds being nodes
	if (child_name == kAnyChild && child_type == child.ELEMENT_NODE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to add (" + child_name + ") child to parent(" + parent_path + "), reason: child is a node which is illegal");
		//return ERR_FORBIDDEN_ATTRIBUTE;
	}

	// forbid rootparent from being created again
	if (child_name == kRootParent)
	{
		throw ProjectSnakeException(kModuleName, "Failed to add (" + child_name + ") to parent(" + parent_path + "), reason: child uses a reserved name");
		//return ERR_FORBIDDEN_ATTRIBUTE;
	}

	// prevent adding children when an anychild exists
	if (parent->GetChild(kAnyChild) != nullptr)
	{
		throw ProjectSnakeException(kModuleName, "Failed to add child(" + child_name + ") to parent(" + parent_path + "), reason: " + kAnyChild + " exists as a child, no others can be added");
		//return ERR_CHILD_ALREADY_EXISTS;
	}

	// prevent adding an anychild when children exist
	if (child_name == kAnyChild && !parent->childs().empty())
	{
		throw ProjectSnakeException(kModuleName, "Failed to add child(" + child_name + ") to parent(" + parent_path + "), reason: attempted to add " + kAnyChild  + " when other children existed");
		//return ERR_CHILD_ALREADY_EXISTS;
	}

	// add child to parent
	parent->AddChild(child);
}

void YamlFile::AllowDuplicateDataChilds(bool allow) noexcept
{
	allow_duplicate_data_childs_ = allow;
}

const YamlElement* YamlFile::GetLayoutElement(const std::string& path) noexcept
{
	return ResolveElementPath(&layout_, path);
}

const YamlElement* YamlFile::GetDataElement(const std::string& path) noexcept
{
	return ResolveElementPath(&data_, path);
}

void YamlFile::ProcessYamlElement(const YamlElement* layout, YamlElement* data)
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

		// get parent path for children
		std::string new_parent_path = "";
		if (data->name() != kRootParent)
		{
			if (!data->parent_path().empty())
			{
				new_parent_path += data->parent_path() + "/";
			}

			new_parent_path += data->name();
		}

		// check if the layout supports children
		if (layout->childs().empty())
		{
			throw ProjectSnakeException(kModuleName, "Node: " + new_parent_path + " has no children");
			//return ERR_NODE_HAS_NO_CHILDREN;
		}

		// move into children of the element
		reader_.GetEvent();
		if (!reader_.is_event_mapping_start())
		{
			throw ProjectSnakeException(kModuleName, "Unexpect YAML layout, expected MAPPING event at: " + new_parent_path);
			//return ERR_YAML_MAPPING_EVENT_DID_NOT_OCCUR;
		}

		// get level for children
		uint32_t level = reader_.level();

		// iterate through children
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
#ifdef YAML_ERROR
					printf("[YAML ERROR] Unrecognised Key: %s%s%s\n", new_parent_path.c_str(), new_parent_path.empty()? "" : "/", reader_.event_string().c_str());
#endif
					throw ProjectSnakeException(kModuleName, "Unrecognised Key: " + new_parent_path + (new_parent_path.empty() ? "" : "/") + reader_.event_string());
					//return ERR_NODE_HAS_NO_SUCH_CHILD;
				}
			}

			YamlElement* data_child = data->EditChild(reader_.event_string());
			// if the data doesn't have such a child yet (or duplicate childs are allowed), create it
			if (data_child == nullptr || allow_duplicate_data_childs_)
			{
				data->AddChild(YamlElement(new_parent_path,reader_.event_string(), layout_child->type()), allow_duplicate_data_childs_);
				data_child = data->EditChild(reader_.event_string(), data->GetChildOccurence(reader_.event_string()) - 1);
			}

			// process child
			ProcessYamlElement(layout_child, data_child);
			//int ret = ProcessYamlElement(layout_child, data_child);
			//if (ret != ERR_NOERROR) 
			//{
			//	return ret;
			//}
		}
	}
	else if (data->type() == data->ELEMENT_SINGLE_KEY)
	{
#ifdef YAML_DEBUG
		printf("[YAML DEBUG] SINGLE_KEY(%s) entered\n", data->name().c_str());
#endif
		// temporary storage
		std::string tmp;

		reader_.SaveValue(tmp);
		data->AddData(tmp);
	}
	else if (data->type() == data->ELEMENT_LIST_KEY)
	{
#ifdef YAML_DEBUG
		printf("[YAML DEBUG] LIST_KEY(%s) entered\n", data->name().c_str());
#endif
		// temporary storage
		std::vector<std::string> tmp(0);

		reader_.SaveValueSequence(tmp);
		data->AddData(tmp);
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Unknown YAML element type " + data->type());
	}
}

YamlElement* YamlFile::ResolveElementPath(YamlElement* root, const std::string& path) noexcept
{
	if (root->name() != kRootParent)
	{
		return nullptr;
	}

#ifdef YAML_DEBUG
	printf("[YAML DEBUG] RESOLVE_PATH(%s)", path.c_str());
#endif

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
#ifdef YAML_DEBUG
			printf(" FAIL\n");
#endif
			return nullptr;
		}

		// update ptr to current level
		cur = cur->EditChild(element_name);
	}

#ifdef YAML_DEBUG
	printf(" SUCCESS\n");
#endif
	return cur;
}
