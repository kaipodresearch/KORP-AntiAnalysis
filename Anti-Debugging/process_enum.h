#pragma once

#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)

namespace enumeration
{
	namespace debuger_present
	{
		bool check()
		{
			return IsDebuggerPresent();
		}
	}

	namespace remote_debuger
	{
		bool check()
		{
			BOOL result = false;
			CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
			if (result == true)
				return true;
			else
				return false;
		}
	}

	bool check(std::wstring arg_process_name)
	{
		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(PROCESSENTRY32);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		std::wstring process_name;
		
		if (Process32First(snapshot, &process_entry) == true)
		{
			while (Process32Next(snapshot, &process_entry) == true)
			{
				process_name = process_entry.szExeFile;
				if (process_name == arg_process_name)
					return true;
			}
			return false;
		}
		CloseHandle(snapshot);
	}
}