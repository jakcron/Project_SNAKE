#pragma once
#include "types.h"
#include "ByteBuffer.h"

class WadHeader
{
public:
	WadHeader();
	~WadHeader();

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Header Serialisation
	void SerialiseHeader();
	void SetCertificateChainSize(size_t size);
	void SetTicketSize(size_t size);
	void SetTmdSize(size_t size);
	void SetContentSize(size_t size);
	void SetFooterSize(size_t size);
	

	// Header Deserialisation
	void DeserialiseHeader(const u8* wad_data);
	size_t GetCertificateChainOffset() const;
	size_t GetCertificateChainSize() const;
	size_t GetTicketOffset() const;
	size_t GetTicketSize() const;
	size_t GetTmdOffset() const;
	size_t GetTmdSize() const;
	size_t GetContentOffset() const;
	size_t GetContentSize() const;
	size_t GetFooterOffset() const;
	size_t GetFooterSize() const;
	size_t GetPredictedWadSize() const;


private:
	const std::string kModuleName = "WAD_HEADER";

	enum WadTypes
	{
		WAD_TYPE_0 = 0x4973, //="Is"
		WAD_TYPE_1 = 0x6962, //="ib"
		WAD_TYPE_2 = 0x426B  //="Bk"
	};

	enum WadVersions
	{
		WAD_VERSION_0 = 0
	};

	static const int kSizeAlign = 0x40;

	// Private Structures
#pragma pack (push, 1)
	struct sWadHeader
	{
		u32 header_size;
		u16 type;
		u16 version;
		u32 certificate_size;
		u8 reserved[4];
		u32 ticket_size;
		u32 tmd_size;
		u32 content_size;
		u32 footer_size;
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// serialised data staging ground
	sWadHeader header_;

	// serialised data get interface
	inline u32 header_size() const { return be_word(header_.header_size); }
	inline u16 type() const { return be_hword(header_.type); }
	inline u16 version() const { return be_hword(header_.version); }
	inline u32 certificate_size() const { return be_word(header_.certificate_size); }
	inline u32 ticket_size() const { return be_word(header_.ticket_size); }
	inline u32 tmd_size() const { return be_word(header_.tmd_size); }
	inline u32 content_size() const { return be_word(header_.content_size); }
	inline u32 footer_size() const { return be_word(header_.footer_size); }
	

	// serialised data set interface
	inline void set_header_size(u32 header_size) { header_.header_size = be_word(header_size); }
	inline void set_type(u16 type) { header_.type = be_hword(type); }
	inline void set_version(u16 version) { header_.version = be_hword(version); }
	inline void set_certificate_size(u32 certificate_size) { header_.certificate_size = be_word(certificate_size); }
	inline void set_ticket_size(u32 ticket_size) { header_.ticket_size = be_word(ticket_size); }
	inline void set_tmd_size(u32 tmd_size) { header_.tmd_size = be_word(tmd_size); }
	inline void set_content_size(u32 content_size) { header_.content_size = be_word(content_size); }
	inline void set_footer_size(u32 footer_size) { header_.footer_size = be_word(footer_size); }
	

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
	size_t predicted_wad_size_;

	// utils
	void CalculateSectionOffsets();
	void CalculateWadSize();
	bool IsSupportedType(u16 type);
	bool IsSupportedFormatVersion(u16 version);

	void ClearDeserialisedVariables();
};

