#include "romfs_file_tree.h"



RomfsFileTree::RomfsFileTree()
{
	ClearDeserialisedVariables();
}

RomfsFileTree::RomfsFileTree(const u8 * data)
{
	DeserialiseData(data);
}


RomfsFileTree::~RomfsFileTree()
{
}

const u8 * RomfsFileTree::GetSerialisedData() const
{
	return serialised_data_.data();
}

size_t RomfsFileTree::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void RomfsFileTree::SerialiseData()
{
	// Do final work
	CalculateFileDataOffsets();
	UpdateHashMapTables();
	CreateAbstractFileTree(kRootDirID, abstracted_file_tree_);
	
	// create header
	RomfsHeader hdr;
	hdr.SetDirInfo(dir_node_table_size_, dir_hashmap_table_.size() * sizeof(u32));
	hdr.SetFileInfo(file_node_table_size_, file_hashmap_table_.size() * sizeof(u32));
	hdr.SerialiseData();

	// save data offset
	data_offset_ = hdr.GetDataOffset();

	// calculate data size
	CalculateDataSize();

	// allocate memory
	if (serialised_data_.alloc(hdr.GetDataOffset()) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	// copy serialised header
	memcpy(serialised_data_.data(), hdr.GetSerialisedData(), hdr.GetSerialisedDataSize());

	// serialise the dir hash map table
	u32* hash_table = (u32*)(serialised_data_.data() + hdr.GetDirHashMapTableOffset());
	for (size_t i = 0; i < dir_hashmap_table_.size(); i++)
	{
		hash_table[i] = le_word(dir_hashmap_table_[i]);
	}

	// serialise the dir node table
	for (size_t i = 0; i < dir_node_table_.size(); i++)
	{
		dir_node_table_[i].SerialiseData();
		memcpy(serialised_data_.data() + hdr.GetDirNodeTableOffset() + dir_virt_to_phys_map_[i], dir_node_table_[i].GetSerialisedData(), dir_node_table_[i].GetSerialisedDataSize());
	}

	// serialise the file hash map table
	hash_table = (u32*)(serialised_data_.data() + hdr.GetFileHashMapTableOffset());
	for (size_t i = 0; i < file_hashmap_table_.size(); i++)
	{
		hash_table[i] = le_word(file_hashmap_table_[i]);
	}

	// serialise the file node table
	for (size_t i = 0; i < file_node_table_.size(); i++)
	{
		file_node_table_[i].SerialiseData();
		memcpy(serialised_data_.data() + hdr.GetFileNodeTableOffset() + file_virt_to_phys_map_[i], file_node_table_[i].GetSerialisedData(), file_node_table_[i].GetSerialisedDataSize());
	}
}

u32 RomfsFileTree::AddDirectory(const std::u16string& name, u32 parentID)
{
	u32 node_id = dir_node_table_size_;
	RomfsDirectoryNode node;

	// set parameters
	node.SetName(name);
	node.SetParentNode(parentID == kDirIsRoot? 0 : parentID);
	node.SetSiblingNode(kNullNode);
	node.SetDirectoryChildNode(kNullNode);
	node.SetFileChildNode(kNullNode);

	// if this isn't the root directory, chase after sibling linked list
	if (parentID != kDirIsRoot)
	{
		// add node to sibling linked list
		// if a linked list of siblings exists
		RomfsDirectoryNode* parent = get_dir_node(parentID);
		if (parent->GetDirectoryChildNode() != kNullNode)
		{
			RomfsDirectoryNode* sibling = get_dir_node(parent->GetDirectoryChildNode());

			// find end of sibling linked list
			while (sibling->GetSiblingNode() != kNullNode)
			{
				sibling = get_dir_node(sibling->GetSiblingNode());
			}

			// update sibling linked list
			sibling->SetSiblingNode(node_id);
		}
		// otherwise start the linked list
		else
		{
			parent->SetDirectoryChildNode(node_id);
		}
	}

	

	// add to phys<->virt maps
	dir_virt_to_phys_map_.push_back(node_id);
	dir_phys_to_virt_map_[node_id] = dir_node_table_.size();

	// add to dir table
	dir_node_table_.push_back(node);

	// update dir node table size
	dir_node_table_size_ += node.GetNodeSize();

	return node_id;
}

u32 RomfsFileTree::AddFile(const std::u16string& name, u32 parentID, size_t size)
{
	u32 node_id = file_node_table_size_;
	RomfsFileNode node;

	// set parameters
	node.SetName(name);
	node.SetParentNode(parentID);
	node.SetSiblingNode(kNullNode);
	node.SetDataSize(size);
	node.SetDataOffset(0); // is set to the actual value later in CalculateFileDataOffsets()

	// add node to sibling linked list
	// if a linked list of siblings exists
	RomfsDirectoryNode* parent = get_dir_node(parentID);
	if (parent->GetFileChildNode() != kNullNode)
	{
		RomfsFileNode* sibling = get_file_node(parent->GetFileChildNode());

		// find end of sibling linked list
		while (sibling->GetSiblingNode() != kNullNode) 
		{ 
			sibling = get_file_node(sibling->GetSiblingNode());
		}

		// update sibling linked list
		sibling->SetSiblingNode(node_id);
	}
	// otherwise start the linked list
	else
	{
		parent->SetFileChildNode(node_id);
	}

	// add to phys<->virt maps
	file_virt_to_phys_map_.push_back(node_id);
	file_phys_to_virt_map_[node_id] = file_node_table_.size();

	// add to file table
	file_node_table_.push_back(node);

	// update file node table size
	file_node_table_size_ += node.GetNodeSize();

	return node_id;
}

void RomfsFileTree::AddFileTree(const DirectoryNode & node)
{
	InitialiseDirNodeTable();
	AddFileTree(kRootDirID, node);
}

void RomfsFileTree::DeserialiseData(const u8 * data)
{
	// deserialise header
	RomfsHeader hdr(data);

	// clear deserialised variables
	ClearDeserialisedVariables();

	// save copy of serialised data
	size_t metadata_size = hdr.GetDataOffset();
	if (serialised_data_.alloc(metadata_size) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, metadata_size);
	
	// save data offset
	data_offset_ = hdr.GetDataOffset();

	// deserialise hash tables
	const u32* table = (const u32*)(serialised_data_.data() + hdr.GetDirHashMapTableOffset());
	for (size_t i = 0; i < hdr.GetDirHashMapTableSize() / sizeof(u32); i++)
	{
		dir_hashmap_table_.push_back(le_word(table[i]));
	}

	table = (const u32*)(serialised_data_.data() + hdr.GetFileHashMapTableOffset());
	for (size_t i = 0; i < hdr.GetFileHashMapTableSize() / sizeof(u32); i++)
	{
		file_hashmap_table_.push_back(le_word(table[i]));
	}

	// save dir node table
	dir_node_table_size_ = hdr.GetDirNodeTableSize();
	const u8* dir_node_ptr = (const u8*)(serialised_data_.data() + hdr.GetDirNodeTableOffset());
	for (u32 pos = 0; pos < dir_node_table_size_; pos += dir_node_table_.back().GetNodeSize())
	{

		// save maps
		dir_virt_to_phys_map_.push_back(pos);
		//printf("dir_phys_to_virt_map_[%08x] = %08x\n", pos, (u32)dir_node_table_.size());
		dir_phys_to_virt_map_[pos] = dir_node_table_.size();

		// save node
		dir_node_table_.push_back(dir_node_ptr + pos);

#ifdef ROMFS_DEBUG
		printf("dir_node name: \"");
		DebugAsciiPrint(dir_node_table_.back().GetName());
		printf("\"\n");
#endif
	}

	// save file node table
	file_node_table_size_ = hdr.GetFileNodeTableSize();
	const u8* file_node_ptr = (const u8*)(serialised_data_.data() + hdr.GetFileNodeTableOffset());
	for (u32 pos = 0; pos < file_node_table_size_; pos += file_node_table_.back().GetNodeSize())
	{
		// save maps
		file_virt_to_phys_map_.push_back(pos);
		file_phys_to_virt_map_[pos] = file_node_table_.size();

		// save node
		file_node_table_.push_back(file_node_ptr + pos);

#ifdef ROMFS_DEBUG
		printf("file_node name: \"");
		DebugAsciiPrint(file_node_table_.back().GetName());
		printf("\"\n");
#endif
	}
 
	// calculate data size from file node table
	CalculateDataSize();
#ifdef ROMFS_DEBUG
	printf("data size: 0x%lx\n", data_size_);
#endif

	// generate abstract file tree structure
	CreateAbstractFileTree(kRootDirID, abstracted_file_tree_);
	//DebugDumpFileTreeAscii(0, 0);
}

const RomfsFileTree::DirectoryNode & RomfsFileTree::GetFileTree() const
{
	return abstracted_file_tree_;
}

size_t RomfsFileTree::GetTotalDirCount() const
{
	return dir_node_table_.size();
}

size_t RomfsFileTree::GetTotalFileCount() const
{
	return file_node_table_.size();
}

size_t RomfsFileTree::GetDataOffset() const
{
	return data_offset_;
}

size_t RomfsFileTree::GetDataSize() const
{
	return data_size_;
}

u32 RomfsFileTree::CalcHashMapTableSize(u32 node_num) const
{
#define D(a) (count % (a) == 0)
	u32 count = node_num;
	if (count < 3) count = 3;
	else if (count < 19) count |= 1;
	else while (D(2) || D(3) || D(5) || D(7) || D(11) || D(13) || D(17)) count++;
	return count;
#undef D
}

void RomfsFileTree::UpdateHashMapTables()
{
	u32 stubed_node = RomfsFileTree::kNullNode;

	// initialize tables
	dir_hashmap_table_.clear();
	dir_hashmap_table_.reserve(CalcHashMapTableSize(dir_node_table_.size()));	
	for (size_t i = 0; i < dir_hashmap_table_.capacity(); i++)
	{
		dir_hashmap_table_.push_back(stubed_node);
	}

	file_hashmap_table_.clear();
	file_hashmap_table_.reserve(CalcHashMapTableSize(file_node_table_.size()));
	for (size_t i = 0; i < file_hashmap_table_.capacity(); i++)
	{
		file_hashmap_table_.push_back(stubed_node);
	}

	// start hashmap link list with root directory
	u32 hash_index = get_dir_node(kRootDirID)->GetNodeHash() % dir_hashmap_table_.size();
	get_dir_node(kRootDirID)->SetHashSiblingNode(dir_hashmap_table_[hash_index]);
	dir_hashmap_table_[hash_index] = kRootDirID;

	// recursively update directories
	UpdateHashMapTableForDirectory(kRootDirID);
}

void RomfsFileTree::UpdateHashMapTableForDirectory(u32 dirID)
{
	RomfsDirectoryNode* parent = get_dir_node(dirID);

	// iterate through child files
	if (parent->GetFileChildNode() != kNullNode)
	{
		RomfsFileNode* file = get_file_node(parent->GetFileChildNode());

		u32 hash_index = file->GetNodeHash() % file_hashmap_table_.size();
		file->SetHashSiblingNode(file_hashmap_table_[hash_index]);
		file_hashmap_table_[hash_index] = parent->GetFileChildNode();

		while (file->GetSiblingNode() != kNullNode)
		{
			u32 curID = file->GetSiblingNode();

			file = get_file_node(curID);

			hash_index = file->GetNodeHash() % file_hashmap_table_.size();
			file->SetHashSiblingNode(file_hashmap_table_[hash_index]);
			file_hashmap_table_[hash_index] = curID;
		}
	}

	// iterate through child directories
	if (parent->GetDirectoryChildNode() != kNullNode)
	{
		RomfsDirectoryNode* child = get_dir_node(parent->GetDirectoryChildNode());

		u32 hash_index = child->GetNodeHash() % dir_hashmap_table_.size();
		child->SetHashSiblingNode(dir_hashmap_table_[hash_index]);
		dir_hashmap_table_[hash_index] = parent->GetDirectoryChildNode();

		while (child->GetSiblingNode() != kNullNode)
		{
			u32 curID = child->GetSiblingNode();

			child = get_dir_node(curID);

			hash_index = child->GetNodeHash() % dir_hashmap_table_.size();
			child->SetHashSiblingNode(dir_hashmap_table_[hash_index]);
			dir_hashmap_table_[hash_index] = curID;
		}
	}

	// iterate through child directories for their children
	if (parent->GetDirectoryChildNode() != kNullNode)
	{
		UpdateHashMapTableForDirectory(parent->GetDirectoryChildNode());
		const RomfsDirectoryNode* child = get_dir_node(parent->GetDirectoryChildNode());

		while (child->GetSiblingNode() != kNullNode)
		{
			UpdateHashMapTableForDirectory(child->GetSiblingNode());
			child = get_dir_node(child->GetSiblingNode());
		}
	}

	
}

void RomfsFileTree::CalculateFileDataOffsets()
{
	size_t pos = 0;
	for (size_t i = 0; i < file_node_table_.size(); i++)
	{
		if (file_node_table_[i].GetDataSize() > 0)
		{
			file_node_table_[i].SetDataOffset(pos);
			pos = align(pos + file_node_table_[i].GetDataSize(), Crypto::kAesBlockSize);
		}
		else
		{
			file_node_table_[i].SetDataOffset(0);
		}
	}
}

void RomfsFileTree::CalculateDataSize()
{
	data_size_ = 0;
	for (size_t i = 0; i < file_node_table_.size(); i++)
	{
		if (file_node_table_[i].GetDataSize() > 0)
		{
			if (file_node_table_[i].GetDataOffset() != data_size_)
			{
				throw ProjectSnakeException(kModuleName, "File node has an invalid data offset");
			}
			data_size_ += align(file_node_table_[i].GetDataSize(), Crypto::kAesBlockSize);
		}
	}
}

void RomfsFileTree::InitialiseDirNodeTable()
{
	RomfsDirectoryNode node;
	node.SetParentNode(0);
	node.SetSiblingNode(kNullNode);
	node.SetDirectoryChildNode(kNullNode);
	node.SetFileChildNode(kNullNode);
	node.SetHashSiblingNode(kNullNode);
	node.SetName(std::u16string());

	// create maps
	dir_virt_to_phys_map_.push_back((u32)0);
	dir_phys_to_virt_map_[0] = 0;
	
	// add to table
	dir_node_table_.push_back(node);
	dir_node_table_size_ += dir_node_table_.back().GetNodeSize();
}

void RomfsFileTree::AddFileTree(u32 parentID, const DirectoryNode & node)
{
	for (size_t i = 0; i < node.GetFileList().size(); i++)
	{
		AddFile(node.GetFileList()[i].GetName(), parentID, node.GetFileList()[i].GetSize());
	}

	std::vector<u32> dirIDs;
	for (size_t i = 0; i < node.GetDirList().size(); i++)
	{
		dirIDs.push_back(AddDirectory(node.GetDirList()[i].GetName(), parentID));
	}

	for (size_t i = 0; i < node.GetDirList().size(); i++)
	{
		AddFileTree(dirIDs[i], node.GetDirList()[i]);
	}
}

void RomfsFileTree::CreateAbstractFileTree(u32 dirID, DirectoryNode & node)
{
	//printf("CreateAbstractFileTree(%08x, node)\n", dirID);
	// get parent
	const RomfsDirectoryNode* parent = get_dir_node(dirID);

	// set name
	node.SetName(parent->GetName());

	// store file nodes
	if (parent->GetFileChildNode() != kNullNode)
	{
		const RomfsFileNode* file = get_file_node(parent->GetFileChildNode());

		node.EditFileList().push_back(FileNode(file->GetName(), file->GetDataOffset(), file->GetDataSize()));

		// process sibling linked list
		while (file->GetSiblingNode() != kNullNode)
		{
			file = get_file_node(file->GetSiblingNode());
			node.EditFileList().push_back(FileNode(file->GetName(), file->GetDataOffset(), file->GetDataSize()));
		}
	}
	
	// store dir nodes
	if (parent->GetDirectoryChildNode() != kNullNode)
	{
		node.EditDirList().push_back(DirectoryNode());
		CreateAbstractFileTree(parent->GetDirectoryChildNode(), node.EditDirList().back());


		// process sibling linked list
		const RomfsDirectoryNode* child = get_dir_node(parent->GetDirectoryChildNode());
		while (child->GetSiblingNode() != kNullNode)
		{
			node.EditDirList().push_back(DirectoryNode());
			CreateAbstractFileTree(child->GetSiblingNode(), node.EditDirList().back());

			child = get_dir_node(child->GetSiblingNode());
		}
	}
}

#ifdef ROMFS_DEBUG

void RomfsFileTree::DebugAsciiPrint(const std::u16string & str)
{
	for (size_t i = 0; i < str.length(); i++)
	{
		printf("%c", str[i]);
	}
}

void RomfsFileTree::DebugDumpFileTreeAscii(u32 dirID, u32 level)
{
	const RomfsDirectoryNode* parent = get_dir_node(dirID);

	for (u32 i = 0; i < level; i++) { putchar(' '); }
	DebugAsciiPrint(parent->GetName());
	printf("\n");

	if (parent->GetFileChildNode() != kNullNode)
	{


		const RomfsFileNode* file = get_file_node(parent->GetFileChildNode());

		for (u32 i = 0; i < level + 1; i++) { putchar(' '); }
		DebugAsciiPrint(file->GetName());
		printf(" (offset=0x%lx) (size=0x%lx)\n", file->GetDataOffset(), file->GetDataSize());


		while (file->GetSiblingNode() != kNullNode)
		{
			file = get_file_node(file->GetSiblingNode());
			for (u32 i = 0; i < level + 1; i++) { putchar(' '); }
			DebugAsciiPrint(file->GetName());
			printf(" (offset=0x%lx) (size=0x%lx)\n", file->GetDataOffset(), file->GetDataSize());
		}
	}

	if (parent->GetDirectoryChildNode() != kNullNode)
	{
		DebugDumpFileTreeAscii(parent->GetDirectoryChildNode(), level + 1);

		const RomfsDirectoryNode* child = get_dir_node(parent->GetDirectoryChildNode());
		
		while (child->GetSiblingNode() != kNullNode)
		{
			DebugDumpFileTreeAscii(child->GetSiblingNode(), level + 1);

			child = get_dir_node(child->GetSiblingNode());
		}
	}
}

#endif

void RomfsFileTree::ClearDeserialisedVariables()
{
	dir_virt_to_phys_map_.clear();
	dir_phys_to_virt_map_.clear();
	file_virt_to_phys_map_.clear();
	file_phys_to_virt_map_.clear();
	
	dir_hashmap_table_.clear();
	dir_node_table_.clear();
	dir_node_table_size_ = 0;
	file_hashmap_table_.clear();
	file_node_table_.clear();
	file_node_table_size_ = 0;
	
	data_size_ = 0;
	data_offset_ = 0;
}
