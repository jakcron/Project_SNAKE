#include "user_settings.h"
#include <string>
#include <vector>
#include <iostream>


UserSettings::UserSettings()
{
}

UserSettings::UserSettings(int argc, char ** argv)
{
	ParseCliArgs(argc, argv);
}

UserSettings::~UserSettings()
{
}

void UserSettings::ParseCliArgs(int argc, char ** argv)
{
	// clear settings
	ClearSettings();

	// create vector of args
	std::vector<std::string> args;
	for (size_t i = 0; i < (size_t)argc; i++)
	{
		args.push_back(argv[i]);
	}

	// show help text
	if (args.size() < 3)
	{
		ShowCliHelp(args[0]);
		throw ProjectSnakeException(kModuleName, "Invalid user arguments.");
	}

	if (args.size() > 1)
	{
		for (size_t i = 1; i < args.size(); i++)
		{
			if (args[i] == "-i" || args[i] == "--in")
			{
				// check a parameter was specified
				if (i + 1 >= args.size() || args[i + 1][0] == '-')
				{
					throw ProjectSnakeException(kModuleName, "Argument \"" + args[i] + "\" requires a parameter.");
				}

				// save infile path
				general_.infile_path_ = args[i + 1];

				// increment args counter
				i++;
			}
			else if (args[i] == "-o" || args[i] == "--out")
			{
				// check a parameter was specified
				if (i + 1 >= args.size() || args[i + 1][0] == '-')
				{
					throw ProjectSnakeException(kModuleName, "Argument \"" + args[i] + "\" requires a parameter.");
				}

				// save outfile path
				general_.outfile_path_ = args[i + 1];

				// increment args counter
				i++;
			}
			else if (args[i] == "-t")
			{
				// check a parameter was specified
				if (i + 1 >= args.size() || args[i + 1][0] == '-')
				{
					throw ProjectSnakeException(kModuleName, "Argument \"" + args[i] + "\" requires a parameter.");
				}

				if (args[i + 1].compare("cert") == 0)
				{
					general_.file_type_ = FILE_CERTS;
				}
				else if (args[i + 1].compare("tik") == 0)
				{
					general_.file_type_ = FILE_TIK;
				}
				else if (args[i + 1].compare("tmd") == 0)
				{
					general_.file_type_ = FILE_TMD;
				}
				else
				{
					throw ProjectSnakeException(kModuleName, "File type \"" + args[1] + "\" is invalid.");
				}

				// increment args counter
				i++;
			}
			else if (args[i] == "-p" || args[i] == "--print")
			{
				cli_output_.print_fields_ = true;
			}
			else if (args[i] == "-v" || args[i] == "--verbose")
			{
				cli_output_.verbose_ = true;
			}
			else if (args[i] == "--showpubkey")
			{
				cli_output_.full_public_keys_ = true;
			}
			else if (args[i] == "--showsig")
			{
				cli_output_.show_signatures_ = true;
			}
			else if (args[i] == "--showcdncert")
			{
				cli_output_.show_cdn_certs_ = true;
			}
			else if (args[i] == "--usecdncert")
			{
				cli_output_.use_cdn_certs_ = true;
			}
			else if (args[i] == "--certs")
			{
				// check a parameter was specified
				if (i + 1 >= args.size() || args[i + 1][0] == '-')
				{
					throw ProjectSnakeException(kModuleName, "Argument \"" + args[i] + "\" requires a parameter.");
				}

				// save outfile path
				cli_output_.certs_path_ = args[i + 1];

				// increment args counter
				i++;
			}
			else
			{
				ShowCliHelp(args[0]);
				throw ProjectSnakeException(kModuleName, "Unknown argument \"" + args[i] + "\"");
			}
		}
	}
}

UserSettings::FileType UserSettings::GetFileType() const
{
	return general_.file_type_;
}

const std::string & UserSettings::GetInFilePath() const
{
	return general_.infile_path_;
}

const std::string & UserSettings::GetOutFilePath() const
{
	return general_.outfile_path_;
}

bool UserSettings::DoPrintData() const
{
	return cli_output_.print_fields_ || cli_output_.verbose_;
}

bool UserSettings::DoShowSignatures() const
{
	return cli_output_.show_signatures_ || cli_output_.verbose_;
}

bool UserSettings::DoShowFullPublicKeys() const
{
	return cli_output_.full_public_keys_ || cli_output_.verbose_;
}

bool UserSettings::DoShowCdnCerts() const
{
	return cli_output_.show_cdn_certs_ || cli_output_.verbose_;
}

bool UserSettings::DoUseCdnCertToVerify() const
{
	return cli_output_.use_cdn_certs_;
}

bool UserSettings::DoUseExternalCertToVerify() const
{
	return cli_output_.certs_path_.empty() == false && cli_output_.use_cdn_certs_ == false;
}

const std::string & UserSettings::GetExternalCertPath() const
{
	return cli_output_.certs_path_;
}

bool UserSettings::IsTitleIdSet() const
{
	return shared_.title_id_.is_set_;
}

u64 UserSettings::GetTitleId() const
{
	return shared_.title_id_.data_;
}

void UserSettings::ShowCliHelp(const std::string& name)
{
	std::cout << "eShop Tool - v" << kVersionMajor << "." << kVersionMinor << " - (c) 2017 jakcron" << std::endl;
	std::cout << std::endl << "Usage: " << name << " [options...]" << std::endl;
	std::cout << "Options: " << std::endl;
	std::cout << "  -i, --in <file>       - Input (template) file." << std::endl;
	std::cout << "  -o, --out <file>      - Output file." << std::endl;
	std::cout << "  -t <cert|tik|tmd>     - File type," << std::endl;
	std::cout << "                          'cert': Certificate (Chain)" << std::endl;
	std::cout << "                          'tik': eTicket" << std::endl;
	std::cout << "                          'tmd': Title Metadata" << std::endl;
	std::cout << "  -p, --print           - Output data fields." << std::endl;
	std::cout << "Print Options:" << std::endl;
	std::cout << "  -v, --verbose         - Verbose output." << std::endl;
	std::cout << "  --showpubkey          - Show full public key." << std::endl;
	std::cout << "  --showsig             - Show RSA/ECDSA signatures." << std::endl;
	std::cout << "  --showcdncert         - Show appended certificates." << std::endl;
	std::cout << "  --usecdncert          - Validate signatures using appended certificates." << std::endl;
	std::cout << "  --certs <file>        - Validate signatures using certificate chain." << std::endl;
	std::cout << "Ticket Options:" << std::endl;
	std::cout << "  -s, --signer <file>   - XS signer data." << std::endl;
	std::cout << "  -e, --keyid <id>      - Escrow key ID." << std::endl;
	std::cout << "  -E, --escrowkey <file> - Set AES128 escrow key from file (default 0)." << std::endl;
	std::cout << "  --formatver <ver>     - Format version (default 1)" << std::endl;
	std::cout << "                          '0': RVL/TWL compatible" << std::endl;
	std::cout << "                          '1': CTR/CAFE compatible" << std::endl;
	std::cout << "  --titleid <id>        - Title id." << std::endl;
	std::cout << "  --ticketid <id>       - Ticket id (default randomly generated)." << std::endl;
	std::cout << "  --version <version>   - 16 bit ticket version (default 0)." << std::endl;
	/*
	std::cout << "  --version <major.minor.build>" << std::endl;
	std::cout << "                      'major': Version major (0-63) (default 0)" << std::endl;
	std::cout << "                      'minor': Version minor (0-63) (default 0)" << std::endl;
	std::cout << "                      'build': Version minor (0-15) (default 0)" << std::endl;
	*/
	std::cout << "  --crlver <caCrlVersion,xsCrlVersion>" << std::endl;
	std::cout << "                         - Comma delimited CRL versions for CA and XS," << std::endl;
	std::cout << "                          defaults to 0 for both." << std::endl;
	std::cout << "  -c, --contentkey <file> - Set AES128 content key from file (default 0)." << std::endl;
	std::cout << "  --deviceid <id>        - Device id (default 0)." << std::endl;
	std::cout << "  --esactid <id>         - eShop account id (default 0)." << std::endl;
	std::cout << "  -l, --limit <id0:val0, id1:val1, ...>" << std::endl;
	std::cout << "                         - Comma delimited title limits, " << std::endl;
	std::cout << "                           '1': ES_LC_DURATION_TIME" << std::endl;
	std::cout << "                           '2': ES_LC_ABSOLUTE_TIME" << std::endl;
	std::cout << "                           '3': ES_LC_NUM_TITLES" << std::endl;
	std::cout << "                           '4': ES_LC_NUM_LAUNCH" << std::endl;
	std::cout << "                           '5': ES_LC_ELAPSED_TIME" << std::endl;
	std::cout << "  -C, --content-enabled <cidx0-num0, cidx1-num1, ...>" << std::endl;
	std::cout << "                         - List content covered by ticket," << std::endl;
	std::cout << "                           cidx: first content index" << std::endl;
	std::cout << "                           num: used with cidx to indicate" << std::endl;
	std::cout << "                                which are covered by ticket (when unspecified, default 1)" << std::endl;
	std::cout << "  -S, --sys-content <cidx0, cidx1, ...>" << std::endl;
	std::cout << "                         - List content accessible to system." << std::endl;
}

void UserSettings::ClearSettings()
{
	general_.file_type_ = FILE_INVALID;
	general_.infile_path_.clear();
	cli_output_.print_fields_ = false;
	cli_output_.verbose_ = false;
	cli_output_.show_signatures_ = false;
	cli_output_.full_public_keys_ = false;
	cli_output_.show_cdn_certs_ = false;
	cli_output_.use_cdn_certs_ = false;
	cli_output_.certs_path_.clear();
}
