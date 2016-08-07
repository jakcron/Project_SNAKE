#pragma once
#include <vector>
#include "types.h"

class CiaHeader
{
public:
	CiaHeader();
	~CiaHeader();

	int CreateCiaHeader();

	inline const u8* data_blob() const { return (u8*)&header_; }
	inline u32 data_size() const { return sizeof(struct sCiaHeader); }

	void SetCertificateSize(u32 size);
	void SetTicketSize(u32 size);
	void SetTmdSize(u32 size);
	void SetMetaSize(u32 size);
	void SetContentSize(u64 size);
	void SetContentMask(const std::vector<u16>& indexes);

	inline u32 certificate_size() const { return le_word(header_.certificate_size); }
	inline u32 certificate_offset() const { return (u32)align(sizeof(struct sCiaHeader), kCiaSizeAlign); }
	inline u32 ticket_size() const { return le_word(header_.ticket_size); }
	inline u32 ticket_offset() const { return (u32)align(certificate_offset() + certificate_size(), kCiaSizeAlign); }
	inline u32 title_metadata_size() const { return le_word(header_.title_metadata_size); }
	inline u32 title_metadata_offset() const { return (u32)align(ticket_offset() + ticket_size(), kCiaSizeAlign); }
	inline u64 content_size() const { return le_dword(header_.content_total_size); }
	inline u32 content_offset() const { return (u32)align(title_metadata_offset() + title_metadata_size(), kCiaSizeAlign); }
	inline u32 cxi_metadata_size() const { return le_word(header_.cxi_metadata_size); }
	inline u64 cxi_metadata_offset() const { return align(content_offset() + content_size(), kCiaSizeAlign); }

	inline u64 cia_size() const { return cxi_metadata_size() ? cxi_metadata_offset() + cxi_metadata_size() : content_offset() + content_size(); }
private:
	static const int kCiaSizeAlign = 0x40;
	static const u16 kCiaType = 0;
	static const u16 kCiaVersion = 0;
	static const int kCiaContentMaskSize = 0x2000;

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

	struct sCiaHeader header_;
};
