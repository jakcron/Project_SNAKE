#include "project_snake_exception.h"

ProjectSnakeException::ProjectSnakeException() noexcept :
	what_(""),
	module_(""),
	level_(E_FATAL)
{

}

ProjectSnakeException::ProjectSnakeException(const std::string & what) noexcept :
	what_(what),
	module_(""),
	level_(E_FATAL)
{
}

ProjectSnakeException::ProjectSnakeException(const std::string & what, ExceptionLevel level) noexcept :
	what_(what),
	module_(""),
	level_(level)
{
}

ProjectSnakeException::ProjectSnakeException(const std::string & module, const std::string & what) noexcept :
	what_(what),
	module_(module),
	level_(E_FATAL)
{
}

ProjectSnakeException::ProjectSnakeException(const std::string & module, const std::string & what, ExceptionLevel level) noexcept :
what_(what),
	module_(module),
	level_(level)
{
}

ProjectSnakeException::~ProjectSnakeException()
{
}

const char* ProjectSnakeException::what() const noexcept 
{
	return what_.c_str();
}

const char* ProjectSnakeException::module() const noexcept
{
	return module_.c_str();
}

bool ProjectSnakeException::is_fatal() const noexcept
{
	return level_ == E_FATAL;
}
