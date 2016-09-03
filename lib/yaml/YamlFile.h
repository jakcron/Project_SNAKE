#pragma once
#include "YamlReader.h"
#include "YamlElement.h"


class YamlFile
{
public:
	YamlFile() noexcept;
	~YamlFile() noexcept;

	void ParseFile(const char* path);

	// configure layout
	void AddChildToRoot(const std::string& child_name, YamlElement::ElementType child_type);
	void AddGenericChildToParent(const std::string& parent_path, YamlElement::ElementType child_type);
	void AddChildToParent(const std::string& parent_path, const std::string& child_name, YamlElement::ElementType child_type);
	void AllowDuplicateDataChilds(bool allow) noexcept;

	// retreve element
	// GetLayoutElement retrieves the prototype yaml layout data
	const YamlElement* GetLayoutElement(const std::string& path) noexcept;

	// GetDataElement retrieves the processed yaml file data
	const YamlElement* GetDataElement(const std::string& path) noexcept;
private:
	const std::string kModuleName = "YAML_FILE";

	const std::string kRootParent = "#ROOTPARENT#";
	const std::string kAnyChild = "#ANYCHILD#";

	bool allow_duplicate_data_childs_;

	YamlReader reader_;
	YamlElement layout_;
	YamlElement data_;


	void ProcessYamlElement(const YamlElement* layout, YamlElement* data);

	YamlElement* ResolveElementPath(YamlElement* root, const std::string& path) noexcept;
};

