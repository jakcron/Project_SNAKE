#pragma once
#include <fnd/types.h>
#include <fnd/memory_blob.h>

class RomfsFileNode
{
public:
	RomfsFileNode();
	RomfsFileNode(const u8* data);
	~RomfsFileNode();

	// access serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// serialiser methods
	void SerialiseData();
	void SetName(const std::u16string& name);
	void SetParentNode(u32 parentID);
	void SetSiblingNode(u32 siblingID);
	void SetDataOffset(size_t offset);
	void SetDataSize(size_t size);
	void SetHashSiblingNode(u32 siblingID);

	// deserialiser methods
	void DeserialiseData(const u8* data);
	const std::u16string& GetName() const;
	u32 GetParentNode() const;
	u32 GetSiblingNode() const;
	size_t GetDataOffset() const;
	size_t GetDataSize() const;
	u32 GetHashSiblingNode() const;
	
	// calculated properties
	size_t GetNodeSize() const; // to be used externally predict the serialised data size before serialisation occurs (if required)
	u32 GetNodeHash() const;

private:
	const std::string kModuleName = "ROMFS_FILE_NODE";
	static const u32 kPathHashIv = 123456789;

	// Private Structures
#pragma pack (push, 1)
	struct sFileNode
	{
	private:
		u32 parent_node_;
		u32 sibling_node_;
		u64 data_offset_;
		u64 data_size_;
		u32 hash_node_;
		u32 name_size_;
	public:
		u32 parent_node() const { return le_word(parent_node_); }
		u32 sibling_node() const { return le_word(sibling_node_); }
		u64 data_offset() const { return le_dword(data_offset_); }
		u64 data_size() const { return le_dword(data_size_); }
		u32 hashmap_sibling_node() const { return le_word(hash_node_); }
		u32 name_size() const { return le_word(name_size_); }
		u32 node_size() const { return align(sizeof(*this) + name_size(), 4); }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_parent_node(u32 node) { parent_node_ = le_word(node); }
		void set_sibling_node(u32 node) { sibling_node_ = le_word(node); }
		void set_data_offset(u64 offset) { data_offset_ = le_dword(offset); }
		void set_data_size(u64 size) { data_size_ = le_dword(size); }
		void set_hashmap_sibling_node(u32 node) { hash_node_ = le_word(node); }
		void set_name_size(u32 byte_len) { name_size_ = le_word(byte_len); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	//u32 node_id_;
	u32 parent_node_;
	u32 sibling_node_;
	size_t data_offset_;
	size_t data_size_;
	u32 hashmap_sibling_node_;
	std::u16string name_;

	void ClearDeserialisedVariables();

	static inline u32 init_path_hash(u32 parent) { return parent ^ kPathHashIv; }
	static inline u32 update_path_hash(u32 hash, char16_t chr) { return ((u32)((hash >> 5) | (hash << 27))) ^ ((u16)chr); /* ror hash, xor with chr */ }
};

