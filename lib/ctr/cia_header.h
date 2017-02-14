#pragma once
#include <vector>
#include <fnd/types.h>
#include <fnd/memory_blob.h>

class CiaHeader
{
public:
	// Public constants
	static const int kCiaMaxContentNum = 0x10000;

	// Constructor/Destructor
	CiaHeader();
	CiaHeader(const u8* data);
	CiaHeader(const CiaHeader& other);
	~CiaHeader();

	void operator=(const CiaHeader& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Header Serialisation
	void SerialiseHeader();
	void SetCertificateChainSize(size_t size);
	void SetTicketSize(size_t size);
	void SetTmdSize(size_t size);
	void SetFooterSize(size_t size);
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
	size_t GetFooterOffset() const;
	size_t GetFooterSize() const;
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
	private:
		u32 header_size_;
		u16 type_;
		u16 version_;
		u32 certificate_size_;
		u32 ticket_size_;
		u32 tmd_size_;
		u32 footer_size_;
		u64 content_size_;
		u8 content_mask_[kCiaContentMaskSize];
	public:
		u32 header_size() const { return le_word(header_size_); }
		u16 type() const { return le_hword(type_); }
		u16 version() const { return le_hword(version_); }
		u32 certificate_size() const { return le_word(certificate_size_); }
		u32 ticket_size() const { return le_word(ticket_size_); }
		u32 tmd_size() const { return le_word(tmd_size_); }
		u32 footer_size() const { return le_word(footer_size_); }
		u64 content_size() const { return le_dword(content_size_); }
		bool is_content_index_set(u16 index) const { return ((content_mask_[index / 8] & BIT(7 - (index % 8))) != 0); }

		void clear() { memset(this, 0, sizeof(sCiaHeader)); }

		void set_header_size(u32 size) { header_size_ = le_word(size); }
		void set_type(u16 type) { type_ = le_hword(type); }
		void set_version(u16 version) { version_ = le_hword(version); }
		void set_certificate_size(u32 size) { certificate_size_ = le_word(size); }
		void set_ticket_size(u32 size) { ticket_size_ = le_word(size); }
		void set_tmd_size(u32 size) { tmd_size_ = le_word(size); }
		void set_footer_size(u32 size) { footer_size_ = le_word(size); }
		void set_content_size(u64 size) { content_size_ = le_dword(size); }
		void enable_content_index(u16 index) { content_mask_[index / 8] |= BIT(7 - (index % 8)); }
		void disable_content_index(u16 index) { content_mask_[index / 8] &= ~BIT(7 - (index % 8)); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// members for deserialised data
	struct sSectionGeometry
	{
		size_t offset;
		size_t size;
	};
	
	u16 type_;
	u16 version_;
	sSectionGeometry certs_;
	sSectionGeometry tik_;
	sSectionGeometry tmd_;
	sSectionGeometry footer_;
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
