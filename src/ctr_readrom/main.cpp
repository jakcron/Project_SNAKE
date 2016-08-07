#include "types.h"

#include "ByteBuffer.h"

#include "cia_header.h"
#include "ncch_header.h"
#include "ncsd_header.h"

int main(int argc, char** argv)
{
	CiaHeader cia_hdr;
	NcchHeader ncch_header;
	NcsdHeader cci_header;

	ByteBuffer file;

	if (argc != 2)
	{
		printf("usage: %s <rom image>\n", argv[0]);
		return 1;
	}

	printf("open file\n");
	if (file.OpenFile(argv[1]) != ByteBuffer::ERR_NONE) 
	{
		printf("Failed to open \"%s\"\n", argv[1]);
		return 1;
	}
	

	if (cci_header.SetHeader(file.data_const()) == 0)
	{
		printf("CCI File Found!\n");

		printf(" > Title ID %016lx\n", cci_header.title_id());
	}

	if (ncch_header.SetHeader(file.data_const()) == 0)
	{
		printf("NCCH File Found!\n");
	}

	return 0;
}