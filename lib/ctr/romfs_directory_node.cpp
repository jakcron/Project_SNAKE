#include "romfs_directory_node.h"



RomfsDirectoryNode::RomfsDirectoryNode()
{
	ClearDeserialisedVariables();
}

RomfsDirectoryNode::RomfsDirectoryNode(const u8 * data)
{
	DeserialiseData(data);
}


RomfsDirectoryNode::~RomfsDirectoryNode()
{
}

const u8 * RomfsDirectoryNode::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t RomfsDirectoryNode::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void RomfsDirectoryNode::ClearDeserialisedVariables()
{
	//node_id_ = 0;
	parent_node_ = 0;
	sibling_node_ = 0;
	dir_child_node_ = 0;
	file_child_node_ = 0;
	hashmap_sibling_node_ = 0;
	name_.clear();
}

void RomfsDirectoryNode::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(GetNodeSize()) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	sDirectoryNode* node = (sDirectoryNode*)serialised_data_.data();

	// serialise struct variables
	node->set_parent_node(parent_node_);
	node->set_sibling_node(sibling_node_);
	node->set_child_node(dir_child_node_);
	node->set_file_node(file_child_node_);
	node->set_hashmap_sibling_node(hashmap_sibling_node_);
	node->set_name_size(name_.length() * sizeof(char16_t));

	char16_t* name = (char16_t*)(serialised_data_.data() + sizeof(sDirectoryNode));
	for (size_t i = 0; i < name_.length(); i++)
	{
		name[i] = le_hword(name_[i]);
	}
}

void RomfsDirectoryNode::SetName(const std::u16string & name)
{
	name_ = name;
}

void RomfsDirectoryNode::SetParentNode(u32 parentID)
{
	parent_node_ = parentID;
}

void RomfsDirectoryNode::SetSiblingNode(u32 siblingID)
{
	sibling_node_ = siblingID;
}

void RomfsDirectoryNode::SetDirectoryChildNode(u32 childID)
{
	dir_child_node_ = childID;
}

void RomfsDirectoryNode::SetFileChildNode(u32 childID)
{
	file_child_node_ = childID;
}

void RomfsDirectoryNode::SetHashSiblingNode(u32 siblingID)
{
	hashmap_sibling_node_ = siblingID;
}

void RomfsDirectoryNode::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	const sDirectoryNode* node = (const sDirectoryNode*)data;
	size_t size = node->node_size();

	// allocate memory for serialised data
	if (serialised_data_.alloc(size) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	// save local copy of serialised data
	memcpy(serialised_data_.data(), data, size);
	node = (const sDirectoryNode*)serialised_data_.data_const();

	// check data wasn't corrupted
	if (node->node_size() != size)
	{
		throw ProjectSnakeException(kModuleName, "Data corruption");
	}

	// deserialise struct variables
	parent_node_ = node->parent_node();
	sibling_node_ = node->sibling_node();
	dir_child_node_ = node->dir_child_node();
	file_child_node_ = node->file_child_node();
	hashmap_sibling_node_ = node->hashmap_sibling_node();

	name_.clear();
	const char16_t* name = (const char16_t*)(serialised_data_.data_const() + sizeof(sDirectoryNode));
	for (size_t i = 0; i < node->name_size() / 2; i++)
	{
		name_.push_back(le_hword(name[i]));
	}
}

const std::u16string & RomfsDirectoryNode::GetName() const
{
	return name_;
}

u32 RomfsDirectoryNode::GetParentNode() const
{
	return parent_node_;
}

u32 RomfsDirectoryNode::GetSiblingNode() const
{
	return sibling_node_;
}

size_t RomfsDirectoryNode::GetDirectoryChildNode() const
{
	return dir_child_node_;
}

size_t RomfsDirectoryNode::GetFileChildNode() const
{
	return file_child_node_;
}

u32 RomfsDirectoryNode::GetHashSiblingNode() const
{
	return hashmap_sibling_node_;
}

size_t RomfsDirectoryNode::GetNodeSize() const
{
	return sizeof(sDirectoryNode) + align(name_.length() * sizeof(char16_t), sizeof(u32));
}

u32 RomfsDirectoryNode::GetNodeHash() const
{
	size_t len = name_.length();
	u32 hash = init_path_hash(parent_node_);
	for (size_t i = 0; i < len; i++)
	{
		hash = update_path_hash(hash, name_[i]);
	}
	return hash;
}
