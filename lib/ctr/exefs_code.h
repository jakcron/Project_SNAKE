#pragma once
#include "types.h"
#include "elf.h"
#include "ByteBuffer.h"

class ExefsCode
{
public:
	ExefsCode();
	~ExefsCode();

	// internally generate code blob
	// code blobs are normally page aligned, except in builtin sysmodules
	int CreateCodeBlob(const u8* elf, bool is_page_aligned);

	// data relevant for CXI creation
	inline const u8* code_blob() const { return code_blob_.data_const(); }
	inline u32 code_size() const { return code_blob_.size(); }
	inline const u8* module_id_blob() const { return module_id_.data; }
	inline u32 module_id_size() const { return module_id_.file_size; }

	// data relevant for exheader
	inline u32 text_address() const { return text_.address; }
	inline u32 text_size() const { return text_.file_size; }
	inline u32 text_page_num() const { return text_.page_num; }

	inline u32 rodata_address() const { return rodata_.address; }
	inline u32 rodata_size() const { return rodata_.file_size; }
	inline u32 rodata_page_num() const { return rodata_.page_num; }

	inline u32 data_address() const { return data_.address; }
	inline u32 data_size() const { return data_.file_size; }
	inline u32 data_page_num() const { return data_.page_num; }

	inline u32 bss_size() const { return data_.memory_size - data_.file_size; }
private:
	static const int kCodePageSize = 0x1000;

	struct sCodeSegment
	{
		u32 address;
		u32 memory_size;
		u32 file_size;
		u32 page_num;
		u8 *data;
	};

	ByteBuffer code_blob_;

	struct sCodeSegment text_;
	struct sCodeSegment rodata_;
	struct sCodeSegment data_;
	struct sCodeSegment module_id_;
	
	int ParseElf(const u8* elf);

	void InitCodeSegment(struct sCodeSegment& segment);
	void FreeCodeSegment(struct sCodeSegment& segment);
	void CreateCodeSegment(struct sCodeSegment& segment, const Elf32_Phdr& phdr, const u8* elf);

	inline u32 SizeToPage(u32 size) const {	return align(size, kCodePageSize) / kCodePageSize; }
	inline u32 PageToSize(u32 page_num) const { return page_num * kCodePageSize; }
};