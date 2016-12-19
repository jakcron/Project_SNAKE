#pragma once
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <fnd/project_snake_exception.h>
#include "libyaml/yaml.h"

class YamlReader
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_FAILED_TO_OPEN_FILE,
		ERR_UNEXPECTED_LAYOUT
	};

	YamlReader() noexcept;
	~YamlReader() noexcept;

	int LoadFile(const char* path);

	// returns a reference to the current event string
	inline const std::string& event_string(void) const { return event_str_; }

	// copies the key's value (or sequence of values) to a referenced dst
	int SaveValue(std::string& dst);
	int SaveValueSequence(std::vector<std::string>& dst);

	// yaml event controls
	bool GetEvent();
	inline uint32_t level() const { return level_; }
	inline bool is_level_in_scope(uint32_t level) const { return level_ >= level; }
	inline bool is_level_same(uint32_t level) const { return level_ == level; }
	inline bool is_done() const { return is_done_; }
	inline bool is_error() const { return is_api_error_; }

	inline bool is_event_document_start() const { return event_.type == YAML_DOCUMENT_START_EVENT; }
	inline bool is_event_document_end() const { return event_.type == YAML_DOCUMENT_END_EVENT; }
	inline bool is_event_nothing() const { return event_.type == YAML_NO_EVENT; }
	inline bool is_event_scalar() const { return event_.type == YAML_SCALAR_EVENT; }
	inline bool is_event_mapping_start() const { return event_.type == YAML_MAPPING_START_EVENT; }
	inline bool is_event_mapping_end() const { return event_.type == YAML_MAPPING_END_EVENT; }
	inline bool is_event_sequence_start() const { return event_.type == YAML_SEQUENCE_START_EVENT; }
	inline bool is_event_sequence_end() const { return event_.type == YAML_SEQUENCE_END_EVENT; }

	inline bool is_sequence() const { return is_sequence_; }
	inline bool is_key() const { return is_key_; }

private:
	const std::string kModuleName = "YAML_READER";

	// for libyaml
	FILE *yaml_file_ptr_;
	yaml_parser_t parser_;
	yaml_event_t event_;
	bool is_done_;
	bool is_api_error_;

	// for event control
	bool is_sequence_;
	bool is_key_;
	uint32_t level_;

	std::string event_str_;

	void Cleanup() noexcept;
};