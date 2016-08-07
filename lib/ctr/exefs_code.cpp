#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "exefs_code.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)


ExefsCode::ExefsCode()
{
	InitCodeSegment(text_);
	InitCodeSegment(rodata_);
	InitCodeSegment(data_);
	InitCodeSegment(module_id_);
}

ExefsCode::~ExefsCode()
{
	FreeCodeSegment(text_);
	FreeCodeSegment(rodata_);
	FreeCodeSegment(data_);
	FreeCodeSegment(module_id_);
}

// internally generate code blob
// code blobs are normally page aligned, except in builtin sysmodules
int ExefsCode::CreateCodeBlob(const u8* elf, bool is_page_aligned)
{
	u8* text, *rodata, *data;

	safe_call(ParseElf(elf));

	if (is_page_aligned)
	{
		safe_call(code_blob_.alloc(PageToSize(text_.page_num + rodata_.page_num + data_.page_num)));

		text = (code_blob_.data() + 0);
		rodata = (code_blob_.data() + PageToSize(text_.page_num));
		data = (code_blob_.data() + PageToSize(text_.page_num + rodata_.page_num));
	}
	else
	{
		safe_call(code_blob_.alloc(text_.file_size + rodata_.file_size + data_.file_size));

		text = (code_blob_.data() + 0);
		rodata = (code_blob_.data() + text_.file_size);
		data = (code_blob_.data() + text_.file_size + rodata_.file_size);
	}
	
	memcpy(text, text_.data, text_.file_size);
	memcpy(rodata, rodata_.data, rodata_.file_size);
	memcpy(data, data_.data, data_.file_size);

	return 0;
}

int ExefsCode::ParseElf(const u8* elf)
{
	const Elf32_Ehdr* ehdr = (const Elf32_Ehdr*)elf;

	if (memcmp(ehdr->e_ident, ELF_MAGIC, 4) != 0) die("[ERROR] Not a valid ELF");

	if (ehdr->e_ident[EI_CLASS] != 1 || \
		ehdr->e_ident[EI_DATA] != ELFDATA2LSB || \
		le_hword(ehdr->e_type) != ET_EXEC || \
		le_hword(ehdr->e_machine) != ET_ARM)
	{
		die("[ERROR] Unsupported ELF");
	}

	const Elf32_Phdr* phdr = (const Elf32_Phdr*)(elf + le_word(ehdr->e_phoff));

	for (u16 i = 0; i < le_hword(ehdr->e_phnum); i++)
	{
		if (le_word(phdr[i].p_type) != PT_LOAD) continue;

		switch ((le_word(phdr[i].p_flags) & ~PF_CTRSDK))
		{
			// text
			case (PF_R | PF_X) :
			{
				CreateCodeSegment(text_, phdr[i], elf);
				break;
			}
			// rodata
			case (PF_R) :
			{
				// CTRSDK ELFs have ModuleId segments at the end
				if (i == le_hword(ehdr->e_phnum) - 1)
				{
					CreateCodeSegment(module_id_, phdr[i], elf);
				}
				else
				{
					CreateCodeSegment(rodata_, phdr[i], elf);
				}
				break;
			}
			// data
			case (PF_R | PF_W) :
			{
				CreateCodeSegment(data_, phdr[i], elf);
				break;
			}
		}
	}

	if (!text_.file_size) die("[ERROR] Failed to locate Text ELF Segment");
	if (!data_.file_size) die("[ERROR] Failed to locate Data ELF Segment");

	return 0;
}

void ExefsCode::InitCodeSegment(struct sCodeSegment& segment)
{
	segment.data = NULL;
	segment.address = 0;
	segment.memory_size = 0;
	segment.file_size = 0;
	segment.page_num = 0;
}


void ExefsCode::FreeCodeSegment(struct sCodeSegment& segment)
{
	if (segment.data != NULL) 
	{
		free(segment.data);
	}

	InitCodeSegment(segment);
}

void ExefsCode::CreateCodeSegment(struct sCodeSegment& segment, const Elf32_Phdr& phdr, const u8* elf)
{
	FreeCodeSegment(segment);

	segment.address = le_word(phdr.p_vaddr);
	segment.file_size = le_word(phdr.p_filesz);
	segment.memory_size = le_word(phdr.p_memsz);

	segment.page_num = SizeToPage(segment.file_size);
	segment.data = (u8*)malloc(segment.file_size);
	if (segment.data == NULL) 
	{
		InitCodeSegment(segment);
		return; // error maybe?
	}

	memcpy(segment.data, elf + le_word(phdr.p_offset), segment.file_size);
}