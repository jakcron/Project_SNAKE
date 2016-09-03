#pragma once
#include <exception>
#include <string>

class ProjectSnakeException : public std::exception
{
public:
	enum ExceptionLevel
	{
		E_RECOVERABLE,
		E_FATAL,
	};

	ProjectSnakeException() noexcept;
	ProjectSnakeException(const std::string& what) noexcept;
	ProjectSnakeException(const std::string& what, ExceptionLevel level) noexcept;
	ProjectSnakeException(const std::string& module, const std::string& what) noexcept;
	ProjectSnakeException(const std::string& module, const std::string& what, ExceptionLevel level) noexcept;


	~ProjectSnakeException();

	const char* what() const noexcept;
	const char* module() const noexcept;
	bool is_fatal() const noexcept;
private:
	std::string what_;
	std::string module_;
	ExceptionLevel level_;
};

