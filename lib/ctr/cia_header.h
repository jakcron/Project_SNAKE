#pragma once
#include <vector>
#include "types.h"
#include "ByteBuffer.h"

class CiaHeader
{
public:
	// Public constants
	static const int kCiaMaxContentNum = 0x10000;

	// Constructor/Destructor
	CiaHeader();
	~CiaHeader();

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Header Serialisation
	void SerialiseHeader();
	void SetCertificateChainSize(size_t size);
	void SetTicketSize(size_t size);
	void SetTmdSize(size_t size);
	void SetCxiMetaDataSize(size_t size);
	void SetContentSize(size_t size);
	void EnableContent(u16 index);

	// Header Deserialisation
	void DeserialiseHeader(const u8* cia_data);
	size_t GetCertificateChainOffset() const;
	size_t GetCertificateChainSize() const;
	size_t GetTicketOffset() const;
	size_t GetTicketSize() const;
	size_t GetTmdOffset() const;
	size_t GetTmdSize() const;
	size_t GetCxiMetaDataOffset() const;
	size_t GetCxiMetaDataSize() const;
	size_t GetContentOffset() const;
	size_t GetContentSize() const;
	size_t GetPredictedCiaSize() const;
	bool IsContentEnabled(u16 index) const;
	const std::vector<u16>& GetEnabledContentList() const;

private:
	const std::string kModuleName = "CIA_HEADER";

	static const int kCiaSizeAlign = 0x40;
	static const u16 kCiaType = 0;
	static const u16 kCiaVersion = 0;
	static const int kCiaContentMaskSize = kCiaMaxContentNum/8;

	// Private Structures
#pragma pack (push, 1)
	struct sCiaHeader
	{
		u32 header_size;
		u16 type;
		u16 version;
		u32 certificate_size;
		u32 ticket_size;
		u32 title_metadata_size;
		u32 cxi_metadata_size;
		u64 content_total_size;
		u8 content_mask[kCiaContentMaskSize];
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// serialised data staging ground
	sCiaHeader header_;

	// serialised data get interface
	inline u32 header_size() const { return le_word(header_.header_size); }
	inline u16 type() const { return le_hword(header_.type); }
	inline u16 version() const { return le_hword(header_.version); }
	inline u32 certificate_size() const { return le_word(header_.certificate_size); }
	inline u32 ticket_size() const { return le_word(header_.ticket_size); }
	inline u32 title_metadata_size() const { return le_word(header_.title_metadata_size); }
	inline u32 cxi_metadata_size() const { return le_word(header_.cxi_metadata_size); }
	inline u64 content_size() const { return le_dword(header_.content_total_size); }
	inline bool is_content_index_set(u16 index) const { return ((header_.content_mask[index / 8] & BIT(7 - (index % 8))) != 0); }

	// serialised data set interface
	inline void set_header_size(u32 header_size) { header_.header_size = le_word(header_size); }
	inline void set_type(u16 type) { header_.type = le_hword(type); }
	inline void set_version(u16 version) { header_.version = le_hword(version); }
	inline void set_certificate_size(u32 certificate_size) { header_.certificate_size = le_word(certificate_size); }
	inline void set_ticket_size(u32 ticket_size) { header_.ticket_size = le_word(ticket_size); }
	inline void set_title_metadata_size(u32 title_metadata_size) { header_.title_metadata_size = le_word(title_metadata_size); }
	inline void set_cxi_metadata_size(u32 cxi_metadata_size) { header_.cxi_metadata_size = le_word(cxi_metadata_size); }
	inline void set_content_size(u64 content_size) { header_.content_total_size = le_dword(content_size); }
	inline void set_content_index(u16 index) { header_.content_mask[index / 8] |= BIT(7 - (index % 8)); }

	// members for deserialised data
	struct sSectionGeometry
	{
		size_t offset;
		size_t size;
	};
	
	u16 type_;
	u16 version_;
	sSectionGeometry cert_;
	sSectionGeometry tik_;
	sSectionGeometry tmd_;
	sSectionGeometry meta_data_;
	sSectionGeometry content_;
	std::vector<u16> enabled_content_;
	size_t predicted_cia_size_;

	// utils
	void CalculateSectionOffsets();
	void CalculateCiaSize();
	bool IsSupportedType(u16 type);
	bool IsSupportedFormatVersion(u16 version);

	void ClearDeserialisedVariables();
};
