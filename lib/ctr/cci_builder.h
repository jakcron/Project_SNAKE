#pragma once

#include "types.h"
#include "crypto.h"

#include "ncch_header.h"
#include "ncsd_header.h"
#include "cci_cardinfo_header.h"

class CciBuilder
{
public:
	CciBuilder();
	~CciBuilder();

	int CreateCci();
	int WriteToFile();
	int WriteToBuffer();

	int SetCciRsaKey(const Crypto::sRsa2048Key& rsa_key);
	int AddContent(u16 index, const u8* data, u64 size);
private:
	static const int kIoBufferLen = 0x100000;

	struct ContentInfo {
		const u8* data;
		u16 index;
		u64 size;
	};

	int SetHeaderDataFromCxiHeader(const NcchHeader& ncch_header);
};

