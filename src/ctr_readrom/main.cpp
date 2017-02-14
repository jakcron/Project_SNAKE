#include <cinttypes>

#include <fnd/types.h>
#include <fnd/memory_blob.h>

#include <ctr/ctr_program_id.h>

#include <ctr/cia_header.h>
#include <ctr/ncch_header.h>
#include <ctr/cci_header.h>
#include <ctr/extended_header.h>
#include <ctr/access_descriptor.h>

int main(int argc, char** argv)
{
	CiaHeader cia_hdr;
	NcchHeader ncch_header;
	CciHeader cci_header;

	MemoryBlob file;

	if (argc != 3)
	{
		printf("usage: %s <type, [exhdr]> <rom image>\n", argv[0]);
		return 1;
	}

	printf("open file\n");
	if (file.OpenFile(argv[2]) != MemoryBlob::ERR_NONE) 
	{
		printf("Failed to open \"%s\"\n", argv[1]);
		return 1;
	}
	
	CtrProgramId progid;
	try {
		cci_header.DeserialiseHeader(file.data_const());
		printf("CCI File Found!\n");
		progid = cci_header.GetTitleId();
		printf(" TitleID:     %04x:%04x:%06x:%02x\n", progid.device_type(), progid.category(), progid.unique_id(), progid.variation());
		printf(" CardDevice:  %d\n", cci_header.GetCardDevice());
		printf(" Platform:    %d\n", cci_header.GetPlatform());
		printf(" MediaType:   %d\n", cci_header.GetMediaType());
		printf(" Content:\n");
		for (int i = 0; i < CciHeader::kSectionNum; i++)
		{
			if (cci_header.GetPartition(i).size == 0) continue;

			progid = cci_header.GetPartition(i).title_id;
			printf("  %d:          [id=%04x:%04x:%06x:%02x]\n", i, progid.device_type(), progid.category(), progid.unique_id(), progid.variation());
		}
	}
	catch (const ProjectSnakeException& e) {
		printf("Not a valid cci file!\n");
	}

	try {
		ncch_header.DeserialiseHeader(file.data_const());
		printf("NCCH File Found!\n");
		progid = ncch_header.GetProgramId();
		printf(" ProgramID:   %04x:%04x:%06x:%02x\n", progid.device_type(), progid.category(), progid.unique_id(), progid.variation());
		progid = ncch_header.GetTitleId();
		printf(" TitleID:     %04x:%04x:%06x:%02x\n", progid.device_type(), progid.category(), progid.unique_id(), progid.variation());
		printf(" ProductCode: %s\n", ncch_header.GetProductCode().c_str());
		printf(" Platform:    %d\n", ncch_header.GetPlatform());
		printf(" FormType:    %d\n", ncch_header.GetFormType());
		printf(" ContentType: %d\n", ncch_header.GetContentType());
		printf(" IsEncrypted: %s\n", ncch_header.IsEncrypted() ? "true" : "false");
		printf(" KeyType:     %s\n", ncch_header.IsFixedAesKey() ? "Fixed" : "Unfixed");
	}
	catch (const ProjectSnakeException& e) {
		printf("Not a valid ncch file!\n");
	}

	if (strcmp(argv[1], "exhdr") == 0)
	{
		try {
			ExtendedHeader exhdr(file.data_const());
			AccessDescriptor desc(file.data_const() + 0x400);
			desc.ValidateExtendedHeader(exhdr);

			printf("EXHEADER File Found! (%s)\n", desc.IsExheaderValid()? "GOOD" : "FAIL");
			printf("Name:                   %s\n", exhdr.GetSystemControlInfo().GetProcessTitle().c_str());
			printf("Flag:                   ");
			if (exhdr.GetSystemControlInfo().IsCodeCompressed())
				printf("[compressed]");
			if (exhdr.GetSystemControlInfo().IsSdmcTitle())
				printf("[sd app]");
			printf("\n");
			printf("Remaster version:       %04X\n", exhdr.GetSystemControlInfo().GetRemasterVersion());

			printf("Code text address:      0x%08X\n", exhdr.GetSystemControlInfo().GetTextAddress());
			printf("Code text size:         0x%08X\n", exhdr.GetSystemControlInfo().GetTextSize());
			printf("Code text max pages:    0x%08X (0x%08X)\n", exhdr.GetSystemControlInfo().GetTextPageNum(), exhdr.GetSystemControlInfo().GetTextPageNum() << 12);
			printf("Code ro address:        0x%08X\n", exhdr.GetSystemControlInfo().GetRodataAddress());
			printf("Code ro size:           0x%08X\n", exhdr.GetSystemControlInfo().GetRodataSize());
			printf("Code ro max pages:      0x%08X (0x%08X)\n", exhdr.GetSystemControlInfo().GetRodataPageNum(), exhdr.GetSystemControlInfo().GetRodataPageNum() << 12);
			printf("Code data address:      0x%08X\n", exhdr.GetSystemControlInfo().GetDataAddress());
			printf("Code data size:         0x%08X\n", exhdr.GetSystemControlInfo().GetDataSize());
			printf("Code data max pages:    0x%08X (0x%08X)\n", exhdr.GetSystemControlInfo().GetDataPageNum(), exhdr.GetSystemControlInfo().GetDataPageNum() << 12);
			printf("Code bss size:          0x%08X\n", exhdr.GetSystemControlInfo().GetBssSize());
			printf("Code stack size:        0x%08X\n", exhdr.GetSystemControlInfo().GetStackSize());

			for (auto title_id : exhdr.GetSystemControlInfo().GetDependencyList())
			{
				fprintf(stdout, "Dependency:             %016" PRIx64 "\n", title_id);
			}

			u32 savedatasize = exhdr.GetSystemControlInfo().GetSaveDataSize();
			if (savedatasize < BIT(10))
				fprintf(stdout, "Savedata size:          0x%x\n", savedatasize);
			else if (savedatasize < BIT(20))
				fprintf(stdout, "Savedata size:          %dK\n", savedatasize / BIT(10));
			else
				fprintf(stdout, "Savedata size:          %dM\n", savedatasize / BIT(20));

			fprintf(stdout, "Jump id:                %016" PRIx64 "\n", exhdr.GetSystemControlInfo().GetJumpId());

			fprintf(stdout, "Program id:             %016" PRIx64 " %s\n", exhdr.GetArm11LocalCaps().GetProgramId(), desc.IsProgramIdValid()? "GOOD" : "FAIL");
			fprintf(stdout, "Firmware id:            %016" PRIx64 " %s\n", exhdr.GetArm11LocalCaps().GetFirmTitleId(), desc.IsFirmwareTitleIdValid() ? "GOOD" : "FAIL");
			fprintf(stdout, "System mode:            %d\n", exhdr.GetArm11LocalCaps().GetSystemMode());
			fprintf(stdout, "System mode (New3DS):   %d\n", exhdr.GetArm11LocalCaps().GetSystemModeExt());
			fprintf(stdout, "CPU Speed (New3DS):     %s\n", exhdr.GetArm11LocalCaps().GetCpuSpeed() == Arm11LocalCaps::CLOCK_804MHz ? "804MHz" : "268MHz");
			fprintf(stdout, "Enable L2 Cache:        %s\n", exhdr.GetArm11LocalCaps().IsL2CacheEnabled() ? "YES" : "NO");
			fprintf(stdout, "Ideal processor:        %d\n", exhdr.GetArm11LocalCaps().GetIdealProcessor());
			fprintf(stdout, "Affinity mask:          %d\n", exhdr.GetArm11LocalCaps().GetAffinityMask());
			fprintf(stdout, "Main thread priority:   %d\n", exhdr.GetArm11LocalCaps().GetThreadPriority());

			fprintf(stdout, "Ext savedata id:        0x%" PRIx64 "\n", exhdr.GetArm11LocalCaps().GetExtdataId());
			fprintf(stdout, "System savedata id 1:   0x%x\n", exhdr.GetArm11LocalCaps().GetSystemSaveId1());
			fprintf(stdout, "System savedata id 2:   0x%x\n", exhdr.GetArm11LocalCaps().GetSystemSaveId2());
			fprintf(stdout, "OtherUserSaveDataId1:   0x%x\n", exhdr.GetArm11LocalCaps().GetOtherUserSaveId1());
			fprintf(stdout, "OtherUserSaveDataId2:   0x%x\n", exhdr.GetArm11LocalCaps().GetOtherUserSaveId2());
			fprintf(stdout, "OtherUserSaveDataId3:   0x%x\n", exhdr.GetArm11LocalCaps().GetOtherUserSaveId3());
		
			fprintf(stdout, "Accessible Savedata Ids:\n");
			for (size_t i = 0; i < exhdr.GetArm11LocalCaps().GetAccessibleSaveIds().size(); i++)
			{
				fprintf(stdout, " > 0x%05x\n", exhdr.GetArm11LocalCaps().GetAccessibleSaveIds()[i]);
			}

			fprintf(stdout, "Other Variation Saves:  %s\n", exhdr.GetArm11LocalCaps().CanAccessOtherVariationSaveData() ? "Accessible" : "Inaccessible");
			fprintf(stdout, "Access info:            0x%" PRIx64"\n", exhdr.GetArm11LocalCaps().GetFsRights());

			printf("Service access:\n");
			for (auto service : exhdr.GetArm11LocalCaps().GetServiceACL())
			{
				fprintf(stdout, " > %s\n", service.c_str());
			}
			fprintf(stdout, "Reslimit category:      %02X\n", exhdr.GetArm11LocalCaps().GetResourceLimitCategory());
			/*
Flag:                   01 [compressed]
Remaster version:       0010
Code text address:      0x00100000
Code text size:         0x00207EFC
Code text max pages:    0x00000208 (0x00208000)
Code ro address:        0x00308000
Code ro size:           0x00023978
Code ro max pages:      0x00000024 (0x00024000)
Code data address:      0x0032C000
Code data size:         0x00017164
Code data max pages:    0x00000018 (0x00018000)
Code bss size:          0x0004268C
Code stack size:        0x00010000
Dependency:             0004013000001702
Dependency:             0004013000001b02
Dependency:             0004013000001e02
Dependency:             0004013000001f02
Dependency:             0004013000002102
Dependency:             0004013000002202
Dependency:             0004013000002302
Savedata size:          0x0
Jump id:                0004003000008f02
Program id:             0004003000008f02
Core version:           0x2
System mode:            64MB
System mode (New3DS):   64MB
CPU Speed (New3DS):     268MHz
Enable L2 Cache:        NO
Ideal processor:        0
Affinity mask:          1
Main thread priority:   28
Ext savedata id:        0x0
System savedata id 1:   0x2008f
System savedata id 2:   0x0
OtherUserSaveDataId1:   0x0
OtherUserSaveDataId2:   0x0
OtherUserSaveDataId3:   0x0*/
		
		}
		catch (const ProjectSnakeException& e) {
			printf("Not a valid exheader file! (%s, %s)\n", e.module(), e.what());
		}
	}
	

	return 0;
}