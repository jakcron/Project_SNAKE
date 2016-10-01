#pragma once
#include <string>
#include <vector>
#include "types.h"
#include "ByteBuffer.h"
#include "program_id.h"

class CiaFooter
{
public:
	CiaFooter();
	~CiaFooter();

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Ticket Serialisation
	void SerialiseFooter();
	void SetDependencyList(const std::vector<u64>& dependency_list);
	void SetFirmwareTitleId(u64 title_id);
	void SetIcon(const u8* data, size_t size);

	// Ticket Deserialisation
	void DeserialiseFooter(const u8* data, size_t size);
	const std::vector<u64>& GetDependencyList() const;
	u64 GetFirmwareTitleId() const;
	const u8* GetIcon() const;
	size_t GetIconSize() const;

private:
	const std::string kModuleName = "CIA_FOOTER";

	static const size_t kMaxDependencyNum = 0x30;

	// private structures
#pragma pack (push, 1)
	struct sCiaFooterBody
	{
		struct sDependencyList
		{
			u64 title_id[kMaxDependencyNum];
			u8 padding[0x180];
		} dependency_list;
		struct sCoreVersion
		{
			u32 firm_title_id_low;
			u8 padding[0xfc];
		} core_version;
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// serialised data staging ground
	sCiaFooterBody body_;

	// serialised data get interface
	inline u64 dependency_title_id(int index) const { return le_dword(body_.dependency_list.title_id[index]); }
	inline u64 firmware_title_id() const { return ProgramId::make_ctr_id(ProgramId::CATEGORY_FIRMWARE, 0, 0) | le_word(body_.core_version.firm_title_id_low); }

	// serialised data set interface
	inline void set_dependency_title_id(int index, u64 title_id) { body_.dependency_list.title_id[index] = le_dword(title_id); }
	inline void set_firmware_title_id(u64 title_id) { body_.core_version.firm_title_id_low = le_word(((u32)title_id)); }

	// deserialised variables
	std::vector<u64> dependency_list_;
	u64 firm_title_id_;
	ByteBuffer icon_;


	void ClearDeserialisedVariables();
};

