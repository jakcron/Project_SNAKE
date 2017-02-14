#pragma once
#include <string>
#include <vector>
#include <fnd/types.h>
#include <fnd/memory_blob.h>

class SystemControlInfo
{
public:
	// Public constants
	static const int kProcessTitleLength = 8;
	static const size_t kMaxDependencyNum = 48;

	// Constructor/Destructor
	SystemControlInfo();
	SystemControlInfo(const u8* data); // implied deserialisation
	SystemControlInfo(const SystemControlInfo& other);
	~SystemControlInfo();

	void operator=(const SystemControlInfo& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetProcessTitle(const std::string& title);
	void SetIsCodeCompressed(bool compressed);
	void SetIsSdmcTitle(bool sdmc_title);
	void SetRemasterVersion(u16 version);
	void SetTextSegmentInfo(u32 address, u32 page_num, u32 size);
	void SetRodataSegmentInfo(u32 address, u32 page_num, u32 size);
	void SetDataSegmentInfo(u32 address, u32 page_num, u32 size);
	void SetStackSize(u32 size);
	void SetBssSize(u32 size);
	void SetDependencyList(const std::vector<u64>& list);
	void SetSaveDataSize(u32 size);
	void SetJumpId(u64 id);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	const std::string& GetProcessTitle() const;
	bool IsCodeCompressed() const;
	bool IsSdmcTitle() const;
	u16 GetRemasterVersion() const;
	u32 GetTextAddress() const;
	u32 GetTextPageNum() const;
	u32 GetTextSize() const;
	u32 GetRodataAddress() const;
	u32 GetRodataPageNum() const;
	u32 GetRodataSize() const;
	u32 GetDataAddress() const;
	u32 GetDataPageNum() const;
	u32 GetDataSize() const;
	u32 GetStackSize() const;
	u32 GetBssSize() const;
	const std::vector<u64> GetDependencyList() const;
	u32 GetSaveDataSize() const;
	u64 GetJumpId() const;

private:
	const std::string kModuleName = "SYSTEM_CONTROL_INFO";

	// Private Structures
#pragma pack (push, 1)
	struct sCodeSegmentInfo
	{
	private:
		u32 address_;
		u32 page_num_;
		u32 size_;
	public:
		u32 address() const { return le_word(address_); }
		u32 page_num() const { return le_word(page_num_); }
		u32 size() const { return le_word(size_); }

		void operator=(const sCodeSegmentInfo& other)
		{
			set_address(other.address());
			set_page_num(other.page_num());
			set_size(other.size());
		}

		void clear() { memset(this, 0, sizeof(sCodeSegmentInfo)); }

		void set_address(u32 address) { address_ = le_word(address); }
		void set_page_num(u32 page_num) { page_num_ = le_word(page_num); }
		void set_size(u32 size) { size_ = le_word(size); }
	};

	struct sSystemControlInfo
	{
	private:
		// process info
		char process_title_[kProcessTitleLength];
		u8 reserved0[5];
		union
		{
			u8 flag_;
			struct
			{
				u8 is_code_compressed_ : 1;
				u8 is_sdmc_title_ : 1;
			};
		};
		u16 remaster_version_;

		// code info
		sCodeSegmentInfo text_;
		u32 stack_size_;
		sCodeSegmentInfo rodata_;
		u8 reserved1[4];
		sCodeSegmentInfo data_;
		u32 bss_size_;

		// system info
		u64 dependency_list_[kMaxDependencyNum];
		u32 save_data_size_;
		u8 reserved2[4];
		u64 jump_id_;
		u8 reserved3[0x30];
	public:
		const char* process_title() const { return process_title_; }
		bool is_code_compressed() const { return is_code_compressed_; }
		bool is_sdmc_title() const { return is_sdmc_title_; }
		u16 remaster_version() const { return le_hword(remaster_version_); }
		const sCodeSegmentInfo* text() const { return &text_; }
		const sCodeSegmentInfo* rodata() const { return &rodata_; }
		const sCodeSegmentInfo* data() const { return &data_; }
		u32 stack_size() const { return stack_size_; }
		u32 bss_size() const { return bss_size_; }
		u64 dependency(int index) const { return le_dword(dependency_list_[index]); }
		u32 save_data_size() const { return le_word(save_data_size_); }
		u64 jump_id() const { return le_dword(jump_id_); }

		void clear() { memset(this, 0, sizeof(sSystemControlInfo)); }

		void set_process_title(const char* title) { strncpy(process_title_, title, kProcessTitleLength); }
		void set_is_code_compressed(bool compressed) { is_code_compressed_ = compressed; }
		void set_is_sdmc_title(bool sdmc_title) { is_sdmc_title_ = sdmc_title; }
		void set_remaster_version(u16 version) { remaster_version_ = le_hword(version); }
		void set_text(u32 address, u32 page_num, u32 size) { text_.set_address(address); text_.set_page_num(page_num); text_.set_size(size); }
		void set_rodata(u32 address, u32 page_num, u32 size) { rodata_.set_address(address); rodata_.set_page_num(page_num); rodata_.set_size(size); }
		void set_data(u32 address, u32 page_num, u32 size) { data_.set_address(address); data_.set_page_num(page_num); data_.set_size(size); }
		void set_stack_size(u32 size) { stack_size_ = le_word(size); }
		void set_bss_size(u32 size) { bss_size_ = le_word(size); }
		void set_dependency(int index, u64 title_id) { dependency_list_[index] = le_dword(title_id); }
		void set_save_data_size(u32 size) { save_data_size_ = le_word(size); }
		void set_jump_id(u64 id) { jump_id_ = le_dword(id); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	std::string process_title_;
	bool is_code_compressed_;
	bool is_sdmc_title_;
	u16 remaster_version_;
	sCodeSegmentInfo text_;
	sCodeSegmentInfo rodata_;
	sCodeSegmentInfo data_;
	u32 stack_size_;
	u32 bss_size_;
	std::vector<u64> dependency_list_;
	u32 save_data_size_;
	u64 jump_id_;

	void ClearDeserialisedVariables();
};

