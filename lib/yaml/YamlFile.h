#pragma once
#include "YamlReader.h"
#include "YamlElement.h"


class YamlFile
{
public:
	enum ErrorCodes
	{
		ERR_NOERROR,
		ERR_NODE_HAS_NO_CHILDREN,
		ERR_NODE_HAS_NO_SUCH_CHILD,
		ERR_UNKNOWN_ELEMENT_TYPE,
		ERR_READER_UNEXPECTED_LAYOUT,
		ERR_READER_FAILED_TO_OPEN_FILE,
		ERR_PATH_FAILED_TO_RESOLVE,
		ERR_FORBIDDEN_ATTRIBUTE,
		ERR_CHILD_ALREADY_EXISTS,
		ERR_YAML_MAPPING_EVENT_DID_NOT_OCCUR,
	};

	YamlFile();
	~YamlFile();

	int ParseFile(const char* path);

	// configure layout
	int AddChildToRoot(const std::string& child_name, YamlElement::ElementType child_type);
	int AddGenericChildToParent(const std::string& parent_path, YamlElement::ElementType child_type);
	int AddChildToParent(const std::string& parent_path, const std::string& child_name, YamlElement::ElementType child_type);

	// retreve element
	// GetLayoutElement retrieves the prototype yaml layout data
	const YamlElement* GetLayoutElement(const std::string& path);

	// GetDataElement retrieves the processed yaml file data
	const YamlElement* GetDataElement(const std::string& path);
private:
	const std::string kRootParent = "#ROOTPARENT#";
	const std::string kAnyChild = "#ANYCHILD#";

	YamlReader reader_;
	YamlElement layout_;
	YamlElement data_;


	int ProcessYamlElement(const YamlElement* layout, YamlElement* data);

	YamlElement* ResolveElementPath(YamlElement* root, const std::string& path);
};

