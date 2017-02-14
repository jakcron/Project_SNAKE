#pragma once

//#define ROMFS_DEBUG

#include <map>
#include <vector>
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <ctr/romfs_header.h>
#include <ctr/romfs_directory_node.h>
#include <ctr/romfs_file_node.h>

class RomfsFileTree
{
public:
	/* Abstracted file system structure */
	class FileNode
	{
	public:
		FileNode() {}
		FileNode(const FileNode& other) : name_(other.GetName()), offset_(other.GetOffset()), size_(other.GetSize()) {}
		FileNode(const std::u16string& name, size_t offset, size_t size) : name_(name), offset_(offset), size_(size) {}
		~FileNode() {}

		void operator=(const FileNode& other) { SetName(other.GetName()); SetOffset(other.GetOffset()); SetSize(other.GetSize()); }

		void SetName(const std::u16string& name) { name_ = name; }
		void SetOffset(size_t offset) { offset_ = offset; }
		void SetSize(size_t size) { size_ = size; }

		const std::u16string& GetName() const { return name_; }
		const size_t GetOffset() const { return offset_; }
		const size_t GetSize() const { return size_; }
	private:
		std::u16string name_;
		size_t offset_;
		size_t size_;
	};

	class DirectoryNode
	{
	public:
		DirectoryNode() {}
		~DirectoryNode() {}

		void operator=(const DirectoryNode& other) 
		{
			SetName(other.GetName());

			// copy files
			file_list_.clear();
			for (size_t i = 0; i < other.GetFileList().size(); i++)
			{
				file_list_.push_back(FileNode(other.GetFileList()[i]));
			}

			// copy directories
			dir_list_.clear();
			for (size_t i = 0; i < other.GetDirList().size(); i++)
			{
				dir_list_.push_back(DirectoryNode(other.GetDirList()[i]));
			}
		}

		void SetName(const std::u16string& name) { name_ = name; }
		std::vector<DirectoryNode>& EditDirList() { return dir_list_; }
		std::vector<FileNode>& EditFileList() { return file_list_; }

		const std::u16string& GetName() const { return name_; }
		const std::vector<DirectoryNode>& GetDirList() const { return dir_list_; }
		const std::vector<FileNode>& GetFileList() const { return file_list_; }
	private:
		std::u16string name_;
		std::vector<DirectoryNode> dir_list_;
		std::vector<FileNode> file_list_;
	};

	// root directory ID
	static const u32 kRootDirID = 0;
	static const u32 kDirIsRoot = 0xfffffffe;

	// Constructor/Destructor
	RomfsFileTree();
	RomfsFileTree(const u8* data);
	~RomfsFileTree();

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	u32 AddDirectory(const std::u16string& name, u32 parentID); // returns dirID
	u32 AddFile(const std::u16string& name, u32 parentID, size_t size); // returns fileID
	void AddFileTree(const DirectoryNode& node);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	const DirectoryNode& GetFileTree() const;
	size_t GetTotalDirCount() const;
	size_t GetTotalFileCount() const;
	size_t GetDataOffset() const;
	size_t GetDataSize() const;

#ifdef ROMFS_DEBUG
	void DebugAsciiPrint(const std::u16string& str);
	void DebugDumpFileTreeAscii(u32 parentID, u32 level);
#endif

private:
	const std::string kModuleName = "ROMFS_FILE_TREE";
	static const u32 kNullNode = 0xffffffff;

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	std::vector<u32> dir_virt_to_phys_map_; // translate between vector index and physical memory layout
	std::map<u32, u32> dir_phys_to_virt_map_; // translate between physical memory layout and vector index 
	std::vector<u32> file_virt_to_phys_map_; // translate between vector index and physical memory layout
	std::map<u32, u32> file_phys_to_virt_map_; // translate between physical memory layout and vector index 

	
	std::vector<u32> dir_hashmap_table_;
	std::vector<RomfsDirectoryNode> dir_node_table_;
	u32 dir_node_table_size_;
	std::vector<u32> file_hashmap_table_;
	std::vector<RomfsFileNode> file_node_table_;
	u32 file_node_table_size_;

	size_t data_offset_;
	size_t data_size_;

	// abstracted file tree structure
	DirectoryNode abstracted_file_tree_;

	// helper methods
	u32 CalcHashMapTableSize(u32 node_num) const;
	
	inline RomfsDirectoryNode* get_dir_node(u32 physical_addr) { return &dir_node_table_[dir_phys_to_virt_map_[physical_addr]]; }
	inline RomfsFileNode* get_file_node(u32 physical_addr) { return &file_node_table_[file_phys_to_virt_map_[physical_addr]]; }

	// final calculations
	void UpdateHashMapTables();
	void UpdateHashMapTableForDirectory(u32 dirID); // This method simulates the processing order of nintendo's makerom
	void CalculateFileDataOffsets();
	void CalculateDataSize();

	void AddFileTree(u32 parentID, const DirectoryNode& node);
	void CreateAbstractFileTree(u32 dirID, DirectoryNode & node);
	void InitialiseDirNodeTable();
	void ClearDeserialisedVariables();
};

