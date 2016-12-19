#pragma once
#include <string>
#include <vector>
#include <fnd/types.h>
#include <fnd/ByteBuffer.h>
#include <ctr/system_control_info.h>
#include <ctr/ctr_program_id.h>

class CiaFooter
{
public:
	CiaFooter();
	CiaFooter(const u8* data, size_t size);
	CiaFooter(const CiaFooter& other);
	~CiaFooter();

	void operator=(const CiaFooter& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseFooter();
	void SetDependencyList(const std::vector<u64>& dependency_list);
	void SetFirmwareTitleId(u64 title_id);
	void SetIcon(const u8* data, size_t size);

	// Data Deserialisation
	void DeserialiseFooter(const u8* data, size_t size);
	const std::vector<u64>& GetDependencyList() const;
	u64 GetFirmwareTitleId() const;
	const u8* GetIcon() const;
	size_t GetIconSize() const;

private:
	const std::string kModuleName = "CIA_FOOTER";

	// private structures
#pragma pack (push, 1)
	struct sCiaFooterBody
	{
	private:
		u64 dependency_list_[SystemControlInfo::kMaxDependencyNum];
		u8 padding0[0x180];
		u32 firm_title_id_low_;
		u8 padding1[0xfc];
	public:
		u64 dependency(int index) const { return le_dword(dependency_list_[index]); }
		u64 firm_title_id() const { return CtrProgramId::make_ctr_id(CtrProgramId::CATEGORY_FIRMWARE, 0, 0) | le_word(firm_title_id_low_); }

		void clear() { memset(this, 0, sizeof(sCiaFooterBody)); }

		void set_dependency(int index, u64 id) { dependency_list_[index] = le_dword(id); }
		void set_firm_title_id(u64 id) { firm_title_id_low_ = le_word(((u32)id)); }
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// deserialised variables
	std::vector<u64> dependency_list_;
	u64 firm_title_id_;
	ByteBuffer icon_;


	void ClearDeserialisedVariables();
};

