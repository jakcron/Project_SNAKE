#pragma once

#include <string>
#include <vector>
#include <fnd/project_snake_exception.h>

class YamlElement
{
public:
	enum ElementType
	{
		ELEMENT_NODE,
		ELEMENT_SINGLE_KEY,
		ELEMENT_LIST_KEY,
	};

	YamlElement() noexcept;
	YamlElement(const std::string& parent_path, const std::string& name, ElementType type) noexcept;
	YamlElement(const std::string& name, ElementType type) noexcept;
	~YamlElement() noexcept;

	// complex data setters
	void SetParentPath(const std::string& parent_path) noexcept;
	void SetName(const std::string& name) noexcept;
	void SetType(ElementType type) noexcept;
	void AddChild(const YamlElement& child);
	void AddChild(const YamlElement& child, bool allow_duplicates);
	void AddData(const std::string& str);
	void AddData(const std::vector<std::string>& str);

	// complex data getters
	size_t GetChildOccurence(const std::string& name) const noexcept;
	const YamlElement* GetChild(const std::string& name) const noexcept;
	const YamlElement* GetChild(const std::string& name, size_t pos) const noexcept;
	YamlElement* EditChild(const std::string& name) noexcept;
	YamlElement* EditChild(const std::string& name, size_t pos) noexcept;

	// inline simple data getters
	const std::string& parent_path(void) const { return parent_path_; }
	const std::string& name(void) const { return name_; }
	ElementType type(void) const { return type_; }
	const std::vector<YamlElement>& childs() const { return childs_; }
	const std::vector<std::string>& data() const { return data_; }

private:
	const std::string kModuleName = "YAML_ELEMENT";

	std::string parent_path_;
	std::string name_;
	ElementType type_;

	std::vector<YamlElement> childs_;
	std::vector<std::string> data_;
};

