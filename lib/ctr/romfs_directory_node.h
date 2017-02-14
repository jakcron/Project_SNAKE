#pragma once
#include <fnd/types.h>
#include <fnd/memory_blob.h>

class RomfsDirectoryNode
{
public:
	RomfsDirectoryNode();
	RomfsDirectoryNode(const u8* data);
	~RomfsDirectoryNode();

	// access serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// serialiser methods
	void SerialiseData();
	void SetName(const std::u16string& name);
	void SetParentNode(u32 parentID);
	void SetSiblingNode(u32 siblingID);
	void SetDirectoryChildNode(u32 childID);
	void SetFileChildNode(u32 childID);
	void SetHashSiblingNode(u32 siblingID);

	// deserialiser methods
	void DeserialiseData(const u8* data);
	const std::u16string& GetName() const;
	u32 GetParentNode() const;
	u32 GetSiblingNode() const;
	size_t GetDirectoryChildNode() const;
	size_t GetFileChildNode() const;
	u32 GetHashSiblingNode() const;

	// calculated properties
	size_t GetNodeSize() const; // to be used externally predict the serialised data size before serialisation occurs (if required)
	u32 GetNodeHash() const;

private:
	const std::string kModuleName = "ROMFS_DIRECTORY_NODE";
	static const u32 kPathHashIv = 123456789;

	// Private Structures
#pragma pack (push, 1)
	struct sDirectoryNode
	{
	private:
		u32 parent_node_;
		u32 sibling_node_; // pointer to first sibling
		u32 dir_child_node_; // pointer to first child
		u32 file_child_node_; // pointer to first file
		u32 hashmap_sibling_node_;
		u32 name_size_;
	public:
		u32 parent_node() const { return le_word(parent_node_); }
		u32 sibling_node() const { return le_word(sibling_node_); }
		u32 dir_child_node() const { return le_word(dir_child_node_); }
		u32 file_child_node() const { return le_word(file_child_node_); }
		u32 hashmap_sibling_node() const { return le_word(hashmap_sibling_node_); }
		u32 name_size() const { return le_word(name_size_); }
		u32 node_size() const { return align(sizeof(*this) + name_size(), 4); }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_parent_node(u32 node) { parent_node_ = le_word(node); }
		void set_sibling_node(u32 node) { sibling_node_ = le_word(node); }
		void set_child_node(u32 node) { dir_child_node_ = le_dword(node); }
		void set_file_node(u32 node) { file_child_node_ = le_dword(node); }
		void set_hashmap_sibling_node(u32 node) { hashmap_sibling_node_ = le_word(node); }
		void set_name_size(u32 byte_len) { name_size_ = le_word(byte_len); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	//u32 node_id_;
	u32 parent_node_;
	u32 sibling_node_;
	u32 dir_child_node_;
	u32 file_child_node_;
	u32 hashmap_sibling_node_;
	std::u16string name_;

	void ClearDeserialisedVariables();

	static inline u32 init_path_hash(u32 parent) { return parent ^ kPathHashIv; }
	static inline u32 update_path_hash(u32 hash, char16_t chr) { return ((u32)((hash >> 5) | (hash << 27))) ^ ((u16)chr); /* ror hash, xor with chr */ }
};
	
