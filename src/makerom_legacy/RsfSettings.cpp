#include "RsfSettings.h"

void RsfSettings::SetUpYamlLayout(void)
{
	yaml_.AllowDuplicateDataChilds(false);

	// Option
	yaml_.AddChildToRoot("Option", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("Option", "EnableRomPadding", YamlElement::ELEMENT_SINGLE_KEY); // MediaFootPadding
	yaml_.AddChildToParent("Option", "EnableCodePadding", YamlElement::ELEMENT_SINGLE_KEY); // AllowUnalignedSection?
	yaml_.AddChildToParent("Option", "EnableCrypt", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("Option", "EnableCodeCompress", YamlElement::ELEMENT_SINGLE_KEY); // EnableCompress
	yaml_.AddChildToParent("Option", "UseRandomTitleKey", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("Option", "TitleKey", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("Option", "UseUnfixedKey", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("Option", "UnfixedKeyType", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("Option", "UseOnSD", YamlElement::ELEMENT_SINGLE_KEY);

	// AccessControlInfo
	yaml_.AddChildToRoot("AccessControlInfo", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("AccessControlInfo", "DisableDebug", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "ForceDebug", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "CanWriteSharedPage", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "CanUsePrivilegedPriority", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "CanUseNonAlphabetAndNumber", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "PermitMainFunctionArgument", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "CanShareDeviceMemory", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "RunnableOnSleep", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "CanAccessCore2", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "EnableL2Cache", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "EnableCpuSpeedUp", YamlElement::ELEMENT_SINGLE_KEY); // Replace CpuSpeed

	yaml_.AddChildToParent("AccessControlInfo", "UseExtSaveData", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "UseOtherVariationSaveData", YamlElement::ELEMENT_SINGLE_KEY);

	yaml_.AddChildToParent("AccessControlInfo", "IdealProcessor", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "Priority", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "MemoryType", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "SystemMode", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "SystemModeExt", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "CpuSpeed", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "CoreVersion", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "HandleTableSize", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "SystemSaveDataId1", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "SystemSaveDataId2", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "OtherUserSaveData1", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "OtherUserSaveData2", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "OtherUserSaveData3", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "ExtSaveDataId", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "AffinityMask", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "DescVersion", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "ResourceLimitCategory", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "ReleaseKernelMajor", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "ReleaseKernelMinor", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "MaxCpu", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "MemoryMapping", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "IoRegisterMapping", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "FileSystemAccess", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "IoAccessControl", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "InterruptNumbers", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "SystemCallAccess", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "ServiceAccessControl", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("AccessControlInfo", "AccessibleSaveDataIds", YamlElement::ELEMENT_LIST_KEY);

	// SystemControlInfo
	yaml_.AddChildToRoot("SystemControlInfo", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("SystemControlInfo", "AppType", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("SystemControlInfo", "StackSize", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("SystemControlInfo", "RemasterVersion", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("SystemControlInfo", "SaveDataSize", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("SystemControlInfo", "JumpId", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("SystemControlInfo", "Dependency", YamlElement::ELEMENT_LIST_KEY);

	// BasicInfo
	yaml_.AddChildToRoot("BasicInfo", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("BasicInfo", "Title", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("BasicInfo", "CompanyCode", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("BasicInfo", "ProductCode", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("BasicInfo", "ContentType", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("BasicInfo", "Logo", YamlElement::ELEMENT_SINGLE_KEY);

	// RomFs
	yaml_.AddChildToRoot("RomFs", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("RomFs", "RootPath", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("RomFs", "DefaultReject", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("RomFs", "Reject", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("RomFs", "Include", YamlElement::ELEMENT_LIST_KEY);
	yaml_.AddChildToParent("RomFs", "File", YamlElement::ELEMENT_LIST_KEY);

	// TitleInfo
	yaml_.AddChildToRoot("TitleInfo", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("TitleInfo", "Platform", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "Category", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "UniqueId", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "Version", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "ContentsIndex", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "Variation", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "ChildIndex", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "DemoIndex", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "TargetCategory", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("TitleInfo", "CategoryFlags", YamlElement::ELEMENT_LIST_KEY);

	// CardInfo
	yaml_.AddChildToRoot("CardInfo", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CardInfo", "WritableAddress", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CardInfo", "CardType", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CardInfo", "CryptoType", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CardInfo", "CardDevice", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CardInfo", "MediaType", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CardInfo", "BackupWriteWaitTime", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CardInfo", "SaveCrypto", YamlElement::ELEMENT_SINGLE_KEY);

	// CommonHeaderKey
	yaml_.AddChildToRoot("CommonHeaderKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CommonHeaderKey", "D", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "P", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "Q", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "DP", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "DQ", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "InverseQ", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "Modulus", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "Exponent", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "AccCtlDescSign", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CommonHeaderKey", "AccCtlDescBin", YamlElement::ELEMENT_SINGLE_KEY);
}
