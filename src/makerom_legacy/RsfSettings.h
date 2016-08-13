#pragma once
#include <vector>

#include "types.h"

#include "program_id.h"

#include "cia_header.h"

#include "ncch_header.h"
#include "cxi_extended_header.h"

#include "ncsd_header.h"
#include "ncsd_cardinfo_header.h"

class RsfSettings
{
public:
	int ParseRsfFile(const char* path);


private:

	struct sRsfConfig
	{
		struct sRsfOption
		{
			bool media_foot_padding;
			bool allow_unaligned_section;
			bool enable_crypt;
			bool enable_compress;
			bool free_product_code;
			bool use_on_sd;
		} option;

		struct sRsfAccessControlInfo
		{
			bool disable_debug;
			bool force_debug;
			bool can_write_shared_page;
			bool can_use_privileged_priority;
			bool can_use_non_alphabet_and_number;
			bool permit_main_function_argument;
			bool can_share_device_memory;
			bool use_other_variation_save_data;
			bool runnable_on_sleep;
			bool can_access_core2;
			bool use_ext_save_Data;
			bool enable_l2_cache;

			std::string ideal_processor;
			std::string priority;
			std::string memory_type;
			std::string system_mode;
			std::string system_mode_ext;
			std::string cpu_speed;
			std::string core_version;
			std::string handle_table_size;
			std::string system_save_data_id1;
			std::string system_save_data_id2;
			std::string other_user_save_data1;
			std::string other_user_save_data2;
			std::string other_user_save_data3;
			std::string ext_save_data_id;
			std::string affinity_mask;
			std::string desc_version;
			std::string resource_limit_category;
			std::string release_kernel_major;
			std::string release_kernel_minor;
			std::string max_cpu;

			std::vector<std::string> memory_mapping;
			std::vector<std::string> io_register_mapping;
			std::vector<std::string> file_system_access;
			std::vector<std::string> io_access_control;
			std::vector<std::string> interrupt_numbers;
			std::vector<std::string> system_call_access;
			std::vector<std::string> service_access_control;
			std::vector<std::string> accessible_save_data_ids;
		} access_control_info;

		struct sRsfSystemControlInfo
		{
			std::string app_type;
			std::string stack_size;
			std::string remaster_version;
			std::string save_data_size;
			std::string jump_id;

			std::vector<std::string> dependency;
		} system_control_info;

		struct sRsfRomFs
		{
			std::string root_path;

			std::vector<std::string> default_reject;
			std::vector<std::string> reject;
			std::vector<std::string> include;
			std::vector<std::string> file;
		} romfs;

		struct sRsfTitleInfo
		{
			std::string platform;
			std::string category;
			std::string unique_id;
			std::string version;
			std::string contents_index;
			std::string variation;
			std::string child_index;
			std::string demo_index;
			std::string target_category;

			std::vector<std::string> category_flags;
		} title_info;

		struct sRsfCardInfo
		{
			std::string writable_address;
			std::string card_type;
			std::string crypto_type;
			std::string card_device;
			std::string media_type;
			std::string backup_write_wait_time;
			std::string save_crypto;
		} card_info;

		struct sRsfCommonHeaderKey
		{
			bool found;

			std::string d;
			std::string p;
			std::string q;
			std::string dp;
			std::string dq;
			std::string inverse_q;
			std::string modulus;
			std::string exponent;

			std::string acc_ctl_desc_sign;
			std::string acc_ctl_desc_bin;
		} common_header_key;
	};
};
