#pragma once
#include <vector>
#include <yaml/YamlFile.h>

#include <fnd/types.h>

#include <ctr/ctr_program_id.h>

#include <ctr/cia_header.h>

#include <ctr/ncch_header.h>
#include <ctr/extended_header.h>

#include <ctr/cci_header.h>
#include <ctr/card_info_header.h>

class RsfSettings
{
public:
	int ParseRsfFile(const char* path);


private:

	YamlFile yaml_;

	void SetUpYamlLayout(void);
};
