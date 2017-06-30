#include "user_settings.h"
#include <string>
#include <vector>
#include <iostream>


UserSettings::UserSettings()
{
}

UserSettings::UserSettings(int argc, char ** argv)
{
	parseCliArgs(argc, argv);
}

UserSettings::~UserSettings()
{
}

void UserSettings::parseCliArgs(int argc, char ** argv)
{
	// clear settings
	clearSettings();

	// create vector of args
	std::vector<std::string> args;
	for (size_t i = 0; i < (size_t)argc; i++)
	{
		args.push_back(argv[i]);
	}

	// show help text
	if (args.size() < 3)
	{
		showCliHelp(args[0]);
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
				showCliHelp(args[0]);
				throw ProjectSnakeException(kModuleName, "Unknown argument \"" + args[i] + "\"");
			}
		}
	}
}

UserSettings::FileType UserSettings::getFileType() const
{
	return general_.file_type_;
}

const std::string & UserSettings::getInFilePath() const
{
	return general_.infile_path_;
}

const std::string & UserSettings::getOutFilePath() const
{
	return general_.outfile_path_;
}

bool UserSettings::doPrintData() const
{
	return cli_output_.print_fields_ || cli_output_.verbose_;
}

bool UserSettings::doShowSignatures() const
{
	return cli_output_.show_signatures_ || cli_output_.verbose_;
}

bool UserSettings::doShowFullPublicKeys() const
{
	return cli_output_.full_public_keys_ || cli_output_.verbose_;
}

bool UserSettings::doShowCdnCerts() const
{
	return cli_output_.show_cdn_certs_ || cli_output_.verbose_;
}

bool UserSettings::doUseCdnCertToVerify() const
{
	return cli_output_.use_cdn_certs_;
}

bool UserSettings::doUseExternalCertToVerify() const
{
	return cli_output_.certs_path_.empty() == false && cli_output_.use_cdn_certs_ == false;
}

const std::string & UserSettings::getExternalCertPath() const
{
	return cli_output_.certs_path_;
}

void UserSettings::setFormatVersion(u8 version)
{
	shared_.format_version_ = version;
}

u8 UserSettings::getFormatVersion() const
{
	return shared_.format_version_.get();
}

void UserSettings::setTitleId(u64 title_id)
{
	shared_.title_id_ = title_id;
}

u64 UserSettings::getTitleId() const
{
	return shared_.title_id_.get();
}

void UserSettings::setVersion(u16 version)
{
	shared_.version_ = version;
}

u16 UserSettings::getVersion() const
{
	return shared_.version_.get();
}

void UserSettings::setCaCrlVersion(u8 crl_version)
{
	shared_.ca_crl_version_ = crl_version;
}

u8 UserSettings::getCaCrlVersion() const
{
	return shared_.ca_crl_version_.get();
}

void UserSettings::setSignerCrlVersion(u8 crl_version)
{
	shared_.signer_crl_version_ = crl_version;
}

u8 UserSettings::getSignerCrlVersion() const
{
	return shared_.signer_crl_version_.get();
}

void UserSettings::setTicketId(u64 ticket_id)
{
	ticket_.ticket_id_ = ticket_id;
}

u64 UserSettings::getTicketId() const
{
	return ticket_.ticket_id_.get();
}

void UserSettings::setTitleKey(const u8 * title_key)
{
	if (ticket_.title_key_.get_unsafe().alloc(Crypto::kAes128KeySize) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for title key");
	}
	memcpy(ticket_.title_key_.get_unsafe().data(), title_key, Crypto::kAes128KeySize);
	
	ticket_.title_key_.set(ticket_.title_key_.get_unsafe());
}

const u8 * UserSettings::getTitleKey() const
{
	return ticket_.title_key_.get().data();
}

void UserSettings::setEscrowKey(const u8 * escrow_key)
{
	if (ticket_.escrow_key_.get_unsafe().alloc(Crypto::kAes128KeySize) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for title key");
	}
	memcpy(ticket_.escrow_key_.get_unsafe().data(), escrow_key, Crypto::kAes128KeySize);

	ticket_.escrow_key_.set(ticket_.escrow_key_.get_unsafe());
}

const u8 * UserSettings::getEscrowKey() const
{
	return ticket_.escrow_key_.get().data();
}

void UserSettings::setEscrowKeyId(u8 key_id)
{
	ticket_.escrow_key_id_ = key_id;
}

void UserSettings::setEscrowedTitleKey(const u8 * escrowed_key)
{
}

const u8 * UserSettings::getEscrowedTitleKey() const
{
	return nullptr;
}

u8 UserSettings::getEscrowKeyId() const
{
	return ticket_.escrow_key_id_.get();
}

void UserSettings::setDeviceId(u32 device_id)
{
	ticket_.device_id_ = device_id;
}

u32 UserSettings::getDeviceId() const
{
	return ticket_.device_id_.get();
}

void UserSettings::setSystemAccessibleContent(const std::vector<u16>& content_index)
{
	ticket_.system_accessible_content_ = content_index;
}

const std::vector<u16>& UserSettings::getSystemAccessibleContent() const
{
	return ticket_.system_accessible_content_.get();
}

void UserSettings::setAccessTitleId(u32 id)
{
	ticket_.access_title_id_ = id;
}

u32 UserSettings::getAccessTitleId() const
{
	return ticket_.access_title_id_.get();
}

void UserSettings::setAccessTitleIdMask(u32 id_mask)
{
	ticket_.access_title_id_mask_ = id_mask;
}

u32 UserSettings::getAccessTitleIdMask() const
{
	return ticket_.access_title_id_mask_.get();
}

void UserSettings::setLicenseType(ESTicket::ESLicenseType type)
{
	ticket_.license_type_ = type;
}

ESTicket::ESLicenseType UserSettings::getLicenseType() const
{
	return ticket_.license_type_.get();
}

void UserSettings::setEShopAccountId(u32 id)
{
	ticket_.eshop_act_id_ = id;
}

u32 UserSettings::getEShopAccountId() const
{
	return ticket_.eshop_act_id_.get();
}

void UserSettings::setAudit(u8 audit)
{
	ticket_.audit_ = audit;
}

u8 UserSettings::getAudit() const
{
	return ticket_.audit_.get();
}

void UserSettings::showCliHelp(const std::string& name)
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

void UserSettings::clearSettings()
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
