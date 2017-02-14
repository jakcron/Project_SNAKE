#include "romfs_file_node.h"



RomfsFileNode::RomfsFileNode()
{
	ClearDeserialisedVariables();
}

RomfsFileNode::RomfsFileNode(const u8 * data)
{
	DeserialiseData(data);
}


RomfsFileNode::~RomfsFileNode()
{
}

const u8 * RomfsFileNode::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t RomfsFileNode::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void RomfsFileNode::ClearDeserialisedVariables()
{
	//node_id_ = 0;
	parent_node_ = 0;
	sibling_node_ = 0;
	data_offset_ = 0;
	data_size_ = 0;
	hashmap_sibling_node_ = 0;
	name_.clear();
}

void RomfsFileNode::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(GetNodeSize()) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	sFileNode* node = (sFileNode*)serialised_data_.data();

	// serialise struct variables
	node->set_parent_node(parent_node_);
	node->set_sibling_node(sibling_node_);
	node->set_data_offset(data_offset_);
	node->set_data_size(data_size_);
	node->set_hashmap_sibling_node(hashmap_sibling_node_);
	node->set_name_size(name_.length() * sizeof(char16_t));

	char16_t* name = (char16_t*)(serialised_data_.data() + sizeof(sFileNode));
	for (size_t i = 0; i < name_.length(); i++)
	{
		name[i] = le_hword(name_[i]);
	}
}

void RomfsFileNode::SetName(const std::u16string & name)
{
	name_ = name;
}

void RomfsFileNode::SetParentNode(u32 parentID)
{
	parent_node_ = parentID;
}

void RomfsFileNode::SetSiblingNode(u32 siblingID)
{
	sibling_node_ = siblingID;
}

void RomfsFileNode::SetDataOffset(size_t offset)
{
	data_offset_ = offset;
}

void RomfsFileNode::SetDataSize(size_t size)
{
	data_size_ = size;
}

void RomfsFileNode::SetHashSiblingNode(u32 siblingID)
{
	hashmap_sibling_node_ = siblingID;
}

void RomfsFileNode::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();
	
	const sFileNode* node = (const sFileNode*)data;
	size_t size = node->node_size();

	// allocate memory for serialised data
	if (serialised_data_.alloc(size) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	// save local copy of serialised data
	memcpy(serialised_data_.data(), data, size);
	node = (const sFileNode*)serialised_data_.data_const();

	// check data wasn't corrupted
	if (node->node_size() != size)
	{
		throw ProjectSnakeException(kModuleName, "Data corruption");
	}

	// deserialise struct variables
	parent_node_ = node->parent_node();
	sibling_node_ = node->sibling_node();
	data_offset_ = node->data_offset();
	data_size_ = node->data_size();
	hashmap_sibling_node_ = node->hashmap_sibling_node();

	name_.clear();
	const char16_t* name = (const char16_t*)(serialised_data_.data_const() + sizeof(sFileNode));
	for (size_t i = 0; i < node->name_size() / 2; i++)
	{
		name_.push_back(le_hword(name[i]));
	}
}

const std::u16string & RomfsFileNode::GetName() const
{
	return name_;
}

u32 RomfsFileNode::GetParentNode() const
{
	return parent_node_;
}

u32 RomfsFileNode::GetSiblingNode() const
{
	return sibling_node_;
}

size_t RomfsFileNode::GetDataOffset() const
{
	return data_offset_;
}

size_t RomfsFileNode::GetDataSize() const
{
	return data_size_;
}

u32 RomfsFileNode::GetHashSiblingNode() const
{
	return hashmap_sibling_node_;
}

size_t RomfsFileNode::GetNodeSize() const
{
	return sizeof(sFileNode) + align(name_.length() * sizeof(char16_t), sizeof(u32));
}

u32 RomfsFileNode::GetNodeHash() const
{
	size_t len = name_.length();
	u32 hash = init_path_hash(parent_node_);
	for (size_t i = 0; i < len; i++)
	{
		hash = update_path_hash(hash, name_[i]);
	}
	return hash;
}
