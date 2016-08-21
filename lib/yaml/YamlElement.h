#pragma once

#include <string>
#include <vector>

class YamlElement
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_CHILD_ALREADY_EXISTS,
		ERR_CHILD_NOT_FOUND,
	};


	enum ElementType
	{
		ELEMENT_NODE,
		ELEMENT_SINGLE_KEY,
		ELEMENT_LIST_KEY,
	};

	YamlElement();
	YamlElement(const std::string& parent_path, const std::string& name, ElementType type);
	YamlElement(const std::string& name, ElementType type);
	~YamlElement();

	// complex data setters
	int SetParentPath(const std::string& parent_path);
	int SetName(const std::string& name);
	int SetType(ElementType type);
	int AddChild(const YamlElement& child);
	int AddChild(const YamlElement& child, bool allow_duplicates);
	int AddData(const std::string& str);
	int AddData(const std::vector<std::string>& str);

	// complex data getters
	size_t GetChildOccurence(const std::string& name) const;
	const YamlElement* GetChild(const std::string& name) const;
	const YamlElement* GetChild(const std::string& name, size_t pos) const;
	YamlElement* EditChild(const std::string& name);
	YamlElement* EditChild(const std::string& name, size_t pos);

	// inline simple data getters
	const std::string& parent_path(void) const { return parent_path_; }
	const std::string& name(void) const { return name_; }
	ElementType type(void) const { return type_; }
	const std::vector<YamlElement>& childs() const { return childs_; }
	const std::vector<std::string>& data() const { return data_; }

private:
	std::string parent_path_;
	std::string name_;
	ElementType type_;

	std::vector<YamlElement> childs_;
	std::vector<std::string> data_;
};

