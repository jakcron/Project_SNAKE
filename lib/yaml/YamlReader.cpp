#include "YamlReader.h"

YamlReader::YamlReader() noexcept :
	yaml_file_ptr_(NULL),
	is_done_(false),
	is_api_error_(false),
	level_(0),
	event_str_("")
{
}

YamlReader::~YamlReader() noexcept
{
	Cleanup();
}

int YamlReader::LoadFile(const char * path)
{
	// do some cleanup before a file is loaded
	Cleanup();
	
	// Create Parser Object
	yaml_parser_initialize(&parser_);

	// Open the file
	yaml_file_ptr_ = fopen(path, "rb");
	if (yaml_file_ptr_ == NULL) 
	{
		throw ProjectSnakeException(kModuleName, "Failed to open " + std::string(path));
	}

	// Associate file with parser object
	yaml_parser_set_input_file(&parser_, yaml_file_ptr_);

	// Set initial conditions
	is_sequence_ = false;
	is_key_ = true;
	level_ = 0;

	// Read the event sequence until the first document starts the mapping appears after
	while (GetEvent() && !is_event_document_start()) continue;

	return ERR_NOERROR;
}

int YamlReader::SaveValue(std::string & dst)
{
	std::string key = event_string();

	if (!GetEvent() || !is_event_scalar()) 
	{
		throw ProjectSnakeException(kModuleName, "Unexpect YAML layout, expected SCALAR event");
	}

	dst = std::string(event_string());

	return ERR_NOERROR;
}

int YamlReader::SaveValueSequence(std::vector<std::string>& dst)
{
	if (!GetEvent() || !is_event_sequence_start())
	{
		throw ProjectSnakeException(kModuleName, "Unexpect YAML layout, expected SEQUENCE event");
	}

	dst.clear();

	uint32_t init_level = level();
	while (GetEvent() && is_level_same(init_level)) 
	{
		if (is_event_scalar() && !event_string().empty())
		{
			dst.push_back(event_string());
		}
	}
	
	return ERR_NOERROR;
}

bool YamlReader::GetEvent()
{
	/* Don't start if an API error was encountered */
	if (is_api_error_) return false;

	/* Finish Previous Event */
	if (!is_event_nothing())
	{
		if (is_event_scalar() && !is_sequence_)
		{
			is_key_ = !is_key_;
		}

		yaml_event_delete(&event_);
	}

	/* Get new event */
	if (yaml_parser_parse(&parser_, &event_) != 1)
	{
		yaml_event_delete(&event_);
		is_api_error_ = true;
		throw ProjectSnakeException(kModuleName, "(libyaml) " + std::string(parser_.context) + ", " + std::string(parser_.problem));
		//return false;
	}

	/* Clean string */
	event_str_.clear();

	/* Process Event */
	switch (event_.type) 
	{
		case YAML_NO_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS NO EVENT\n");
#endif
			break;
		case YAML_STREAM_START_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS STREAM_START EVENT\n");
#endif
			break;
		case YAML_DOCUMENT_START_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS DOCUMENT_START EVENT\n");
#endif
			break;
		case YAML_ALIAS_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS ALIAS EVENT\n");
#endif
			break;
		case YAML_SCALAR_EVENT:
			event_str_ = std::string(reinterpret_cast<char*>(event_.data.scalar.value));
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS SCALAR EVENT(%s)\n", event_str_.c_str());
#endif
			break;
		case YAML_SEQUENCE_START_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS SEQUENCE_START EVENT\n");
#endif
			is_sequence_ = true;
			is_key_ = false;
			level_++;
			break;
		case YAML_SEQUENCE_END_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS SEQUENCE EVENT\n");
#endif
			is_sequence_ = false;
			is_key_ = true;
			level_--;
			break;
		case YAML_MAPPING_START_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS MAPPING_START EVENT\n");
#endif
			is_key_ = true;
			level_++;
			break;
		case YAML_MAPPING_END_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS MAPPING_END EVENT\n");
#endif
			is_key_ = true;
			level_--;
			break;
		case YAML_DOCUMENT_END_EVENT:
		case YAML_STREAM_END_EVENT:
#ifdef YAML_DEBUG
			printf("[YAML DEBUG] API REPORTS DOCUMENT/STREAM_END EVENT\n");
#endif
			is_done_ = true;
			break;
		default: break;
	}

	return !is_done() && !is_error();
}

void YamlReader::Cleanup() noexcept
{
	if (yaml_file_ptr_ != NULL)
	{
		yaml_parser_delete(&parser_);
		fclose(yaml_file_ptr_);
		yaml_file_ptr_ = NULL;
	}
}
